// root_cause.rs — корреляция STP событий в причинно-следственные цепочки
// Структура 1:1 с dhcp-postmortem

#![allow(unused_imports, unused_variables, dead_code)]

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::analyzer::{TimedEvent, StpEvent, Severity};

// ── Типы — идентичны предыдущим проектам ─────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RootCauseKind {
    RootFlapping,
    TcStorm,
    RogueBridge,     // bridge с низким priority захватывает root
    LoopDetected,    // inferior BPDU + TC storm вместе
    ConfigMismatch,  // неожиданная смена root без шторма
    Clean,
}

impl RootCauseKind {
    pub fn title(&self) -> &'static str {
        match self {
            RootCauseKind::RootFlapping   => "Root Bridge Flapping",
            RootCauseKind::TcStorm        => "Topology Change Storm",
            RootCauseKind::RogueBridge    => "Rogue Root Bridge",
            RootCauseKind::LoopDetected   => "Loop Suspected",
            RootCauseKind::ConfigMismatch => "Root Bridge Change",
            RootCauseKind::Clean          => "No Issues Detected",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub ts:          f64,
    pub event_type:  String,
    pub description: String,
    pub role:        ChainRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainRole {
    Cause,
    Effect,
    Context,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, PartialOrd)]
pub enum RootCauseSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub ts:          f64,
    pub event_type:  String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCause {
    pub kind:               RootCauseKind,
    pub severity:           RootCauseSeverity,
    pub headline:           String,
    pub impact:             String,
    pub remediation:        String,
    pub evidence:           Vec<EvidenceRef>,
    pub secondary_effects:  Vec<String>,
    pub affected_vlans:     Vec<String>,
    pub first_seen:         f64,
    pub last_seen:          f64,
    pub confidence:         u8,
    pub confidence_reason:  String,
    pub causal_chain:       Vec<ChainStep>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootCauseReport {
    pub causes:      Vec<RootCause>,
    pub verdict:     String,
    pub stable:      bool,
    pub action_plan: Vec<String>,
}

// ── Correlator ────────────────────────────────────────────────────────────────

pub fn correlate(events: &[TimedEvent]) -> RootCauseReport {
    let mut causes: Vec<RootCause> = Vec::new();

    if let Some(c) = detect_root_flapping(events)   { causes.push(c); }
    if let Some(c) = detect_tc_storm(events)         { causes.push(c); }
    if let Some(c) = detect_rogue_bridge(events)     { causes.push(c); }
    if let Some(c) = detect_loop(events)             { causes.push(c); }
    if let Some(c) = detect_config_mismatch(events)  { causes.push(c); }

    causes.sort_by(|a, b| b.severity.partial_cmp(&a.severity).unwrap());

    let stable      = assess_stability(events);
    let verdict     = build_verdict(&causes, stable);
    let action_plan = build_action_plan(&causes);

    if causes.is_empty() {
        causes.push(RootCause {
            kind:              RootCauseKind::Clean,
            severity:          RootCauseSeverity::Info,
            headline:          "STP topology stable".into(),
            impact:            "No anomalies detected. Root bridge consistent throughout capture.".into(),
            remediation:       "No action required.".into(),
            evidence:          Vec::new(),
            secondary_effects: Vec::new(),
            affected_vlans:    Vec::new(),
            first_seen:        0.0,
            last_seen:         0.0,
            confidence:        90,
            confidence_reason: "Root bridge stable, no TC storms or flapping detected.".into(),
            causal_chain:      Vec::new(),
        });
    }

    RootCauseReport { causes, verdict, stable, action_plan }
}

// ── Детекторы ─────────────────────────────────────────────────────────────────

fn detect_root_flapping(events: &[TimedEvent]) -> Option<RootCause> {
    let flap_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, StpEvent::RootFlapping { .. }))
        .collect();
    if flap_events.is_empty() { return None; }

    let first_seen = flap_events.first().unwrap().ts;
    let last_seen  = flap_events.last().unwrap().ts;

    let mut max_changes = 0usize;
    let mut affected_vlans = Vec::new();
    let mut evidence = Vec::new();

    for te in &flap_events {
        if let StpEvent::RootFlapping { change_count, window_ms, vlan_id, .. } = &te.event {
            if *change_count > max_changes { max_changes = *change_count; }
            let v = vlan_label(*vlan_id);
            if !affected_vlans.contains(&v) { affected_vlans.push(v.clone()); }
            evidence.push(EvidenceRef {
                ts:          te.ts,
                event_type:  "RootFlapping".into(),
                description: format!(
                    "{}: {} root changes in {:.0}ms",
                    v, change_count, window_ms
                ),
            });
        }
    }

    // Добавляем RootChanged события как контекст
    for te in events.iter().filter(|e| matches!(e.event, StpEvent::RootChanged { .. })) {
        if let StpEvent::RootChanged { old_root, new_root, vlan_id, .. } = &te.event {
            evidence.push(EvidenceRef {
                ts:          te.ts,
                event_type:  "RootChanged".into(),
                description: format!("{}: {} → {}", vlan_label(*vlan_id), old_root, new_root),
            });
        }
    }

    let chain = vec![
        ChainStep {
            ts:          first_seen,
            event_type:  "RootChanged".into(),
            description: "Root bridge changes rapidly — new bridge announces lower Bridge ID".into(),
            role:        ChainRole::Cause,
        },
        ChainStep {
            ts:          first_seen + 0.5,
            event_type:  "TopologyChange".into(),
            description: "Each root change triggers TC flood — all bridges flush MAC tables".into(),
            role:        ChainRole::Effect,
        },
        ChainStep {
            ts:          last_seen,
            event_type:  "RootFlapping".into(),
            description: "Instability continues — network convergence never completes".into(),
            role:        ChainRole::Effect,
        },
    ];

    Some(RootCause {
        kind:     RootCauseKind::RootFlapping,
        severity: RootCauseSeverity::Critical,
        headline: format!("Root bridge flapping — {} changes detected", max_changes),
        impact:   "MAC tables flushed repeatedly. Broadcast storms possible. Network convergence delayed. All traffic on affected VLANs disrupted.".into(),
        remediation: "Set explicit root bridge: `spanning-tree vlan <id> root primary` on intended root. Enable Root Guard on access ports: `spanning-tree guard root`. Check for rogue switches.".into(),
        evidence,
        secondary_effects: vec![
            "Repeated MAC table flushes → temporary flooding".into(),
            "STP re-convergence on every change (30s classic STP, 1-2s RSTP)".into(),
            "Possible broadcast storm during convergence".into(),
        ],
        affected_vlans,
        first_seen,
        last_seen,
        confidence: 95,
        confidence_reason: format!("{} root changes observed directly in capture window.", max_changes),
        causal_chain: chain,
    })
}

fn detect_tc_storm(events: &[TimedEvent]) -> Option<RootCause> {
    let storm_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, StpEvent::TcStorm { .. }))
        .collect();
    if storm_events.is_empty() { return None; }

    let first_seen = storm_events.first().unwrap().ts;
    let last_seen  = storm_events.last().unwrap().ts;

    let mut max_tc = 0usize;
    let mut affected_vlans = Vec::new();
    let mut evidence = Vec::new();

    for te in &storm_events {
        if let StpEvent::TcStorm { tc_count, window_ms, vlan_id, .. } = &te.event {
            if *tc_count > max_tc { max_tc = *tc_count; }
            let v = vlan_label(*vlan_id);
            if !affected_vlans.contains(&v) { affected_vlans.push(v.clone()); }
            evidence.push(EvidenceRef {
                ts:          te.ts,
                event_type:  "TcStorm".into(),
                description: format!("{}: {} TC flags in {:.0}ms", v, tc_count, window_ms),
            });
        }
    }

    // TC events как контекст
    for te in events.iter().filter(|e| matches!(e.event, StpEvent::TopologyChange { .. })).take(5) {
        if let StpEvent::TopologyChange { sender_mac, vlan_id, tc_count, .. } = &te.event {
            evidence.push(EvidenceRef {
                ts:          te.ts,
                event_type:  "TopologyChange".into(),
                description: format!("{}: TC #{} from {}", vlan_label(*vlan_id), tc_count, sender_mac),
            });
        }
    }

    Some(RootCause {
        kind:     RootCauseKind::TcStorm,
        severity: RootCauseSeverity::Critical,
        headline: format!("TC storm — {} topology changes detected", max_tc),
        impact:   "Excessive TC flags cause all bridges to flush MAC tables on every TC. Results in temporary unicast flooding across entire VLAN, bandwidth saturation, CPU spikes on switches.".into(),
        remediation: "Enable BPDU Guard on access ports: `spanning-tree bpduguard enable`. Enable PortFast on end-device ports: `spanning-tree portfast`. Check for flapping ports or loops.".into(),
        evidence,
        secondary_effects: vec![
            "MAC table flush on every TC → unicast flooding".into(),
            "CPU load spike on all bridges".into(),
            "Bandwidth saturation from flooding".into(),
        ],
        affected_vlans,
        first_seen,
        last_seen,
        confidence: 90,
        confidence_reason: format!("{} TC events observed in capture window.", max_tc),
        causal_chain: Vec::new(),
    })
}

fn detect_rogue_bridge(events: &[TimedEvent]) -> Option<RootCause> {
    // Rogue bridge: неожиданная смена root без предшествующего flapping
    // (одиночная смена root на новый bridge с очень низким priority)
    let root_changed: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, StpEvent::RootChanged { .. }))
        .collect();
    let has_flapping = events.iter().any(|e| matches!(e.event, StpEvent::RootFlapping { .. }));

    // Rogue = смена root есть, но flapping нет (один новый захватчик)
    if root_changed.is_empty() || has_flapping { return None; }

    let first_seen = root_changed.first().unwrap().ts;
    let last_seen  = root_changed.last().unwrap().ts;

    let mut affected_vlans = Vec::new();
    let mut evidence = Vec::new();
    let mut new_root = String::new();

    for te in &root_changed {
        if let StpEvent::RootChanged { old_root, new_root: nr, new_root_mac, vlan_id, .. } = &te.event {
            let v = vlan_label(*vlan_id);
            if !affected_vlans.contains(&v) { affected_vlans.push(v.clone()); }
            new_root = nr.clone();
            evidence.push(EvidenceRef {
                ts:          te.ts,
                event_type:  "RootChanged".into(),
                description: format!("{}: new root {} (mac {})", v, nr, new_root_mac),
            });
        }
    }

    let chain = vec![
        ChainStep {
            ts:          first_seen,
            event_type:  "BridgeDiscovered".into(),
            description: "New bridge connected to network with low Bridge ID".into(),
            role:        ChainRole::Cause,
        },
        ChainStep {
            ts:          first_seen + 0.1,
            event_type:  "RootChanged".into(),
            description: format!("New bridge {} elected as Root — all traffic path changes", new_root),
            role:        ChainRole::Effect,
        },
        ChainStep {
            ts:          first_seen + 1.0,
            event_type:  "TopologyChange".into(),
            description: "TC flood triggered — MAC tables flushed across all bridges".into(),
            role:        ChainRole::Effect,
        },
    ];

    Some(RootCause {
        kind:     RootCauseKind::RogueBridge,
        severity: RootCauseSeverity::Critical,
        headline: format!("Rogue root bridge — unexpected root takeover on {} VLAN(s)", affected_vlans.len()),
        impact:   "Traffic paths changed unexpectedly. New root may be a misconfigured access switch or unauthorized device, causing suboptimal or broken routing.".into(),
        remediation: "Enable Root Guard on uplink ports: `spanning-tree guard root`. Verify intended root has lowest Bridge ID. Check for unauthorized switches. Set `spanning-tree vlan <id> priority 4096` on intended root.".into(),
        evidence,
        secondary_effects: vec![
            "Traffic paths changed to suboptimal routes".into(),
            "Potential traffic blackhole during convergence".into(),
        ],
        affected_vlans,
        first_seen,
        last_seen,
        confidence: 80,
        confidence_reason: "Root changed to previously unknown bridge without prior instability.".into(),
        causal_chain: chain,
    })
}

fn detect_loop(events: &[TimedEvent]) -> Option<RootCause> {
    // Loop heuristic: inferior BPDU + TC storm вместе
    let has_inferior = events.iter().any(|e| matches!(e.event, StpEvent::InferiorBpdu { .. }));
    let has_tc_storm = events.iter().any(|e| matches!(e.event, StpEvent::TcStorm { .. }));

    if !has_inferior || !has_tc_storm { return None; }

    let inferior_events: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, StpEvent::InferiorBpdu { .. }))
        .collect();

    let first_seen = inferior_events.first().unwrap().ts;
    let last_seen  = inferior_events.last().unwrap().ts;

    let mut evidence = Vec::new();
    for te in &inferior_events {
        if let StpEvent::InferiorBpdu { sender_mac, claimed_root, actual_root, vlan_id, .. } = &te.event {
            evidence.push(EvidenceRef {
                ts:          te.ts,
                event_type:  "InferiorBpdu".into(),
                description: format!(
                    "{}: {} claims root {} (actual: {})",
                    vlan_label(*vlan_id), sender_mac, claimed_root, actual_root
                ),
            });
        }
    }

    Some(RootCause {
        kind:     RootCauseKind::LoopDetected,
        severity: RootCauseSeverity::Critical,
        headline: "Possible loop — inferior BPDUs with TC storm".into(),
        impact:   "Inferior BPDUs combined with TC storm indicate a possible loop condition. Bridges receiving BPDUs with stale root information may indicate a segment is not receiving BPDUs properly.".into(),
        remediation: "Check for unidirectional links (SFP issues). Enable UDLD: `udld enable`. Check BPDU filtering is not blocking legitimate BPDUs. Verify physical topology matches logical.".into(),
        evidence,
        secondary_effects: vec![
            "Broadcast storm if loop not blocked by STP".into(),
            "MAC table instability".into(),
        ],
        affected_vlans: Vec::new(),
        first_seen,
        last_seen,
        confidence: 70,
        confidence_reason: "Inferior BPDUs co-occurring with TC storm — correlation suggests loop, but physical verification needed.".into(),
        causal_chain: Vec::new(),
    })
}

fn detect_config_mismatch(events: &[TimedEvent]) -> Option<RootCause> {
    // Одиночная смена root без шторма, flapping и rogue (уже покрыт выше)
    // Здесь детектируем только если нет других причин
    let root_changed: Vec<&TimedEvent> = events.iter()
        .filter(|e| matches!(e.event, StpEvent::RootChanged { .. }))
        .collect();

    let has_flapping = events.iter().any(|e| matches!(e.event, StpEvent::RootFlapping { .. }));
    let has_storm    = events.iter().any(|e| matches!(e.event, StpEvent::TcStorm { .. }));

    // Если уже есть более серьёзные причины — не дублируем
    if root_changed.is_empty() || has_flapping || has_storm { return None; }

    let first_seen = root_changed.first().unwrap().ts;
    let last_seen  = root_changed.last().unwrap().ts;

    let mut evidence = Vec::new();
    let mut affected_vlans = Vec::new();

    for te in &root_changed {
        if let StpEvent::RootChanged { old_root, new_root, vlan_id, .. } = &te.event {
            let v = vlan_label(*vlan_id);
            if !affected_vlans.contains(&v) { affected_vlans.push(v.clone()); }
            evidence.push(EvidenceRef {
                ts:          te.ts,
                event_type:  "RootChanged".into(),
                description: format!("{}: {} → {}", v, old_root, new_root),
            });
        }
    }

    Some(RootCause {
        kind:     RootCauseKind::ConfigMismatch,
        severity: RootCauseSeverity::Warning,
        headline: format!("Root bridge changed — {} VLAN(s) affected", affected_vlans.len()),
        impact:   "Traffic paths changed. May indicate planned maintenance, or misconfigured bridge priority.".into(),
        remediation: "Verify intended root bridge has correct priority. Check for recent topology changes. If unplanned, investigate which bridge became root and why.".into(),
        evidence,
        secondary_effects: vec![
            "Traffic path changes during convergence".into(),
        ],
        affected_vlans,
        first_seen,
        last_seen,
        confidence: 75,
        confidence_reason: "Single root change detected without associated instability patterns.".into(),
        causal_chain: Vec::new(),
    })
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn vlan_label(vlan_id: Option<u16>) -> String {
    match vlan_id {
        Some(v) => format!("VLAN {}", v),
        None    => "native".to_string(),
    }
}

fn assess_stability(events: &[TimedEvent]) -> bool {
    if events.is_empty() { return true; }
    let first = events.first().unwrap().ts;
    let last  = events.last().unwrap().ts;
    let window_start = first + (last - first) * 0.8;
    let late_anomalies = events.iter().filter(|e|
        e.ts >= window_start &&
        matches!(e.severity, Severity::Warning | Severity::Critical)
    ).count();
    late_anomalies == 0
}

fn build_verdict(causes: &[RootCause], stable: bool) -> String {
    if causes.is_empty() {
        return "STP topology stable. No anomalies detected.".into();
    }
    let critical: Vec<_> = causes.iter().filter(|c| c.severity == RootCauseSeverity::Critical).collect();
    let warnings: Vec<_> = causes.iter().filter(|c| c.severity == RootCauseSeverity::Warning).collect();

    if !critical.is_empty() {
        let titles: Vec<_> = critical.iter().map(|c| c.kind.title()).collect();
        format!(
            "{} critical issue(s): {}. {}",
            critical.len(),
            titles.join(", "),
            if stable { "Topology may have stabilized by end of capture." }
            else      { "Topology had NOT stabilized by end of capture." }
        )
    } else {
        let titles: Vec<_> = warnings.iter().map(|c| c.kind.title()).collect();
        format!(
            "{} warning(s): {}. {}",
            warnings.len(),
            titles.join(", "),
            if stable { "Topology stable." } else { "Instability persisted." }
        )
    }
}

fn build_action_plan(causes: &[RootCause]) -> Vec<String> {
    let mut plan = Vec::new();
    for cause in causes {
        match cause.kind {
            RootCauseKind::RootFlapping => {
                plan.push("1. URGENT: Stabilize root bridge — `spanning-tree vlan <id> root primary` on intended root. Enable Root Guard on all edge ports.".into());
            }
            RootCauseKind::TcStorm => {
                plan.push("2. URGENT: Enable PortFast + BPDU Guard on all access ports. Check for flapping links. Investigate TC source bridge.".into());
            }
            RootCauseKind::RogueBridge => {
                plan.push("3. URGENT: Enable Root Guard on uplink ports. Identify and isolate unauthorized bridge. Set correct STP priority on intended root.".into());
            }
            RootCauseKind::LoopDetected => {
                plan.push("4. Check for unidirectional links. Enable UDLD. Verify BPDU propagation on all segments.".into());
            }
            RootCauseKind::ConfigMismatch => {
                plan.push("5. Review root bridge priority configuration. Verify intended root has lowest Bridge ID for all VLANs.".into());
            }
            RootCauseKind::Clean => {}
        }
    }
    if plan.is_empty() { plan.push("No action required.".into()); }
    plan
}
