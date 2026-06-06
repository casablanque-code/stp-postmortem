// analyzer.rs — RSTP FSM + детекция аномалий
// Структура аналогична dhcp-postmortem/analyzer.rs

use std::collections::HashMap;
use crate::stp::{Bpdu, BpduType, PortRole};
use serde::{Serialize, Deserialize};

// ── Timestamp — 1:1 с предыдущими проектами ──────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Timestamp {
    pub sec:  u32,
    pub usec: u32,
}

impl Timestamp {
    pub fn to_f64(&self) -> f64 {
        self.sec as f64 + self.usec as f64 / 1_000_000.0
    }
    pub fn diff_ms(&self, other: &Timestamp) -> f64 {
        (self.to_f64() - other.to_f64()) * 1000.0
    }
}

// ── RSTP Port FSM states (802.1w) ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PortState {
    Discarding,
    Learning,
    Forwarding,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Discarding  => "Discarding",
            PortState::Learning    => "Learning",
            PortState::Forwarding  => "Forwarding",
        }
    }
}

// ── События ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum StpEvent {
    /// Первый BPDU от нового bridge
    BridgeDiscovered {
        ts:           f64,
        bridge_id:    String,
        bridge_mac:   String,
        is_root:      bool,
        vlan_id:      Option<u16>,
    },
    /// Текущий Root Bridge
    RootElected {
        ts:           f64,
        root_id:      String,
        root_mac:     String,
        root_priority: u16,
        vlan_id:      Option<u16>,
    },
    /// Смена Root Bridge
    RootChanged {
        ts:           f64,
        old_root:     String,
        new_root:     String,
        new_root_mac: String,
        vlan_id:      Option<u16>,
    },
    /// Topology Change флаг замечен
    TopologyChange {
        ts:           f64,
        sender_mac:   String,
        bridge_id:    String,
        vlan_id:      Option<u16>,
        tc_count:     usize,
    },
    /// TCN BPDU (запрос смены топологии от non-root)
    TcnReceived {
        ts:           f64,
        sender_mac:   String,
        vlan_id:      Option<u16>,
    },
    /// TC шторм — слишком много TC за короткое время
    TcStorm {
        ts:           f64,
        tc_count:     usize,
        window_ms:    f64,
        vlan_id:      Option<u16>,
    },
    /// Порт сменил роль
    PortRoleChange {
        ts:           f64,
        sender_mac:   String,
        port_id:      u16,
        old_role:     String,
        new_role:     String,
        vlan_id:      Option<u16>,
    },
    /// Порт сменил состояние FSM
    PortStateChange {
        ts:           f64,
        sender_mac:   String,
        port_id:      u16,
        old_state:    String,
        new_state:    String,
        vlan_id:      Option<u16>,
    },
    /// Inferior BPDU — bridge получает BPDU хуже своего (признак петли или неправильной конфигурации)
    InferiorBpdu {
        ts:           f64,
        sender_mac:   String,
        claimed_root: String,
        actual_root:  String,
        vlan_id:      Option<u16>,
    },
    /// Bridge flapping — root меняется несколько раз
    RootFlapping {
        ts:           f64,
        change_count: usize,
        window_ms:    f64,
        vlan_id:      Option<u16>,
    },
    /// BPDU получен (info, для timeline)
    BpduReceived {
        ts:           f64,
        sender_mac:   String,
        root_id:      String,
        root_cost:    u32,
        bridge_id:    String,
        port_id:      u16,
        flags_tc:     bool,
        is_rstp:      bool,
        vlan_id:      Option<u16>,
    },
}

// ── Состояние одного порта ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct PortState_ {
    port_id:    u16,
    role:       PortRole,
    fsm_state:  PortState,
    last_ts:    Timestamp,
}

// ── Состояние одного bridge (per VLAN) ───────────────────────────────────────

#[derive(Debug, Clone)]
struct BridgeState {
    bridge_id:   String,
    bridge_mac:  String,
    ports:       HashMap<u16, PortState_>,
    last_bpdu_ts: Timestamp,
}

// ── TC шторм трекер ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct TcTracker {
    window_start: Timestamp,
    count:        usize,
}

// ── Root change трекер ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RootChangeTracker {
    window_start:  Timestamp,
    change_count:  usize,
}

// ── Основной анализатор ───────────────────────────────────────────────────────

pub struct Analyzer {
    /// (vlan_id_or_0) → current root bridge_id string
    current_root:      HashMap<u16, String>,
    /// bridge_mac → BridgeState (per VLAN ключ = mac + vlan)
    bridges:           HashMap<String, BridgeState>,
    /// TC трекер per VLAN
    tc_tracker:        HashMap<u16, TcTracker>,
    /// Root change трекер per VLAN
    root_tracker:      HashMap<u16, RootChangeTracker>,
    /// Порог TC шторма (TC за 10 сек)
    tc_storm_threshold: usize,
    /// Порог root flapping (смен за 30 сек)
    root_flap_threshold: usize,
    /// Уже сгенерированные storm события per VLAN
    storm_reported:    std::collections::HashSet<String>,
    /// Уже сгенерированные flap события per VLAN
    flap_reported:     std::collections::HashSet<String>,
}

impl Analyzer {
    pub fn new() -> Self {
        Analyzer {
            current_root:        HashMap::new(),
            bridges:             HashMap::new(),
            tc_tracker:          HashMap::new(),
            root_tracker:        HashMap::new(),
            tc_storm_threshold:  10,
            root_flap_threshold: 3,
            storm_reported:      std::collections::HashSet::new(),
            flap_reported:       std::collections::HashSet::new(),
        }
    }

    pub fn process(&mut self, bpdu: &Bpdu, ts: Timestamp) -> Vec<StpEvent> {
        let mut events = Vec::new();
        let vlan = bpdu.vlan_id;
        let vlan_key = vlan.unwrap_or(0);
        let sender_mac = bpdu.sender_mac_str();
        let bridge_key = format!("{}:{}", sender_mac, vlan_key);

        // ── TCN BPDU ─────────────────────────────────────────────────────────
        if bpdu.bpdu_type == BpduType::TcnBpdu {
            events.push(StpEvent::TcnReceived {
                ts:         ts.to_f64(),
                sender_mac: sender_mac.clone(),
                vlan_id:    vlan,
            });
            return events;
        }

        let root_id_str   = bpdu.root_id.to_string();
        let bridge_id_str = bpdu.bridge_id.to_string();

        // ── BpduReceived (info) ───────────────────────────────────────────────
        events.push(StpEvent::BpduReceived {
            ts:         ts.to_f64(),
            sender_mac: sender_mac.clone(),
            root_id:    root_id_str.clone(),
            root_cost:  bpdu.root_path_cost,
            bridge_id:  bridge_id_str.clone(),
            port_id:    bpdu.port_id,
            flags_tc:   bpdu.flags.tc,
            is_rstp:    bpdu.is_rstp,
            vlan_id:    vlan,
        });

        // ── Новый bridge ──────────────────────────────────────────────────────
        if !self.bridges.contains_key(&bridge_key) {
            self.bridges.insert(bridge_key.clone(), BridgeState {
                bridge_id:    bridge_id_str.clone(),
                bridge_mac:   sender_mac.clone(),
                ports:        HashMap::new(),
                last_bpdu_ts: ts,
            });
            events.push(StpEvent::BridgeDiscovered {
                ts:            ts.to_f64(),
                bridge_id:     bridge_id_str.clone(),
                bridge_mac:    sender_mac.clone(),
                is_root:       bpdu.is_root_bridge(),
                vlan_id:       vlan,
            });
        } else if let Some(b) = self.bridges.get_mut(&bridge_key) {
            b.last_bpdu_ts = ts;
        }

        // ── Root election / change ────────────────────────────────────────────
        match self.current_root.get(&vlan_key).cloned() {
            None => {
                // Первый BPDU — устанавливаем root
                self.current_root.insert(vlan_key, root_id_str.clone());
                events.push(StpEvent::RootElected {
                    ts:            ts.to_f64(),
                    root_id:       root_id_str.clone(),
                    root_mac:      bpdu.root_id.mac_str(),
                    root_priority: bpdu.root_id.bridge_priority(),
                    vlan_id:       vlan,
                });
            }
            Some(ref cur) if *cur != root_id_str => {
                // Root сменился
                let old_root = cur.clone();
                self.current_root.insert(vlan_key, root_id_str.clone());

                events.push(StpEvent::RootChanged {
                    ts:           ts.to_f64(),
                    old_root:     old_root,
                    new_root:     root_id_str.clone(),
                    new_root_mac: bpdu.root_id.mac_str(),
                    vlan_id:      vlan,
                });

                // Трекаем flapping
                let tracker = self.root_tracker.entry(vlan_key).or_insert(RootChangeTracker {
                    window_start: ts,
                    change_count: 0,
                });
                let elapsed = ts.diff_ms(&tracker.window_start);
                if elapsed > 30_000.0 {
                    tracker.window_start = ts;
                    tracker.change_count = 0;
                }
                tracker.change_count += 1;

                let flap_key = format!("{}:{}", vlan_key, tracker.window_start.sec);
                if tracker.change_count >= self.root_flap_threshold
                    && !self.flap_reported.contains(&flap_key)
                {
                    self.flap_reported.insert(flap_key);
                    events.push(StpEvent::RootFlapping {
                        ts:           ts.to_f64(),
                        change_count: tracker.change_count,
                        window_ms:    elapsed,
                        vlan_id:      vlan,
                    });
                }
            }
            _ => {}
        }

        // ── Topology Change флаг ──────────────────────────────────────────────
        if bpdu.flags.tc {
            let tracker = self.tc_tracker.entry(vlan_key).or_insert(TcTracker {
                window_start: ts,
                count: 0,
            });
            let elapsed = ts.diff_ms(&tracker.window_start);
            if elapsed > 10_000.0 {
                tracker.window_start = ts;
                tracker.count = 0;
            }
            tracker.count += 1;
            let tc_count = tracker.count;

            events.push(StpEvent::TopologyChange {
                ts:         ts.to_f64(),
                sender_mac: sender_mac.clone(),
                bridge_id:  bridge_id_str.clone(),
                vlan_id:    vlan,
                tc_count,
            });

            // TC storm?
            let storm_key = format!("{}:{}", vlan_key, tracker.window_start.sec);
            if tc_count >= self.tc_storm_threshold
                && !self.storm_reported.contains(&storm_key)
            {
                self.storm_reported.insert(storm_key);
                events.push(StpEvent::TcStorm {
                    ts:        ts.to_f64(),
                    tc_count,
                    window_ms: elapsed,
                    vlan_id:   vlan,
                });
            }
        }

        // ── Port role / state changes ─────────────────────────────────────────
        let bridge = self.bridges.get_mut(&bridge_key).unwrap();
        let port_id = bpdu.port_id;

        let new_role = bpdu.flags.port_role.clone();
        let new_fsm  = if bpdu.flags.forwarding {
            PortState::Forwarding
        } else if bpdu.flags.learning {
            PortState::Learning
        } else {
            PortState::Discarding
        };

        if let Some(port) = bridge.ports.get(&port_id) {
            if port.role != new_role {
                events.push(StpEvent::PortRoleChange {
                    ts:         ts.to_f64(),
                    sender_mac: sender_mac.clone(),
                    port_id,
                    old_role:   port.role.as_str().to_string(),
                    new_role:   new_role.as_str().to_string(),
                    vlan_id:    vlan,
                });
            }
            if port.fsm_state != new_fsm {
                events.push(StpEvent::PortStateChange {
                    ts:         ts.to_f64(),
                    sender_mac: sender_mac.clone(),
                    port_id,
                    old_state:  port.fsm_state.as_str().to_string(),
                    new_state:  new_fsm.as_str().to_string(),
                    vlan_id:    vlan,
                });
            }
        } else {
            // Первый BPDU от этого порта
            events.push(StpEvent::PortStateChange {
                ts:        ts.to_f64(),
                sender_mac: sender_mac.clone(),
                port_id,
                old_state: "Unknown".to_string(),
                new_state: new_fsm.as_str().to_string(),
                vlan_id:   vlan,
            });
        }

        bridge.ports.insert(port_id, PortState_ {
            port_id,
            role:      new_role,
            fsm_state: new_fsm,
            last_ts:   ts,
        });

        // ── Inferior BPDU ─────────────────────────────────────────────────────
        // Если отправитель заявляет root хуже чем мы уже знаем
        if let Some(known_root) = self.current_root.get(&vlan_key) {
            // Парсим числовые приоритеты для сравнения
            if *known_root != root_id_str {
                // Сравниваем Bridge ID числово (priority + MAC)
                if bpdu.root_id.to_u64() > bpdu.bridge_id.to_u64() {
                    // root_id хуже чем bridge_id отправителя — нестандартно,
                    // но inferior BPDU определяется по сравнению с known root
                    events.push(StpEvent::InferiorBpdu {
                        ts:           ts.to_f64(),
                        sender_mac:   sender_mac.clone(),
                        claimed_root: root_id_str.clone(),
                        actual_root:  known_root.clone(),
                        vlan_id:      vlan,
                    });
                }
            }
        }

        events
    }

    pub fn finalize(&self, _last_ts: Timestamp) -> Vec<StpEvent> {
        // STP не имеет "незавершённых транзакций" как DHCP
        Vec::new()
    }

    /// Для summary — возвращаем список bridge'ей и текущих root'ов
    pub fn get_topology(&self) -> TopologySnapshot {
        let bridges: Vec<BridgeSummary> = self.bridges.values().map(|b| BridgeSummary {
            bridge_id:  b.bridge_id.clone(),
            bridge_mac: b.bridge_mac.clone(),
            port_count: b.ports.len(),
        }).collect();

        let roots: Vec<RootSummary> = self.current_root.iter().map(|(vlan, root)| RootSummary {
            vlan_id: if *vlan == 0 { None } else { Some(*vlan) },
            root_id: root.clone(),
        }).collect();

        TopologySnapshot { bridges, roots }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BridgeSummary {
    pub bridge_id:  String,
    pub bridge_mac: String,
    pub port_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootSummary {
    pub vlan_id: Option<u16>,
    pub root_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TopologySnapshot {
    pub bridges: Vec<BridgeSummary>,
    pub roots:   Vec<RootSummary>,
}

// ── Report types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct TimedEvent {
    pub ts:       f64,
    pub event:    StpEvent,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReportSummary {
    pub bridges_seen:    usize,
    pub vlans_seen:      usize,
    pub root_changes:    usize,
    pub tc_events:       usize,
    pub anomalies:       usize,
    pub tc_storms:       usize,
    pub root_flaps:      usize,
    pub inferior_bpdus:  usize,
}

pub fn classify_event(event: &StpEvent) -> Severity {
    match event {
        StpEvent::RootFlapping  { .. }  => Severity::Critical,
        StpEvent::TcStorm       { .. }  => Severity::Critical,
        StpEvent::InferiorBpdu  { .. }  => Severity::Warning,
        StpEvent::RootChanged   { .. }  => Severity::Warning,
        StpEvent::TcnReceived   { .. }  => Severity::Warning,
        StpEvent::TopologyChange { .. } => Severity::Warning,
        StpEvent::PortRoleChange { .. } => Severity::Info,
        _                               => Severity::Info,
    }
}
