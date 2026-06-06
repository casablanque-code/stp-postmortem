#![allow(dead_code, unused_imports, unused_variables)]

mod pcap;
mod pcapng;
mod net;
mod stp;
mod analyzer;
mod root_cause;

use wasm_bindgen::prelude::*;
use analyzer::{Analyzer, TimedEvent, ReportSummary, classify_event, Severity};

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

#[wasm_bindgen]
pub fn analyze_pcap(data: &[u8]) -> Result<JsValue, JsValue> {
    let is_pcapng = data.len() >= 4 &&
        u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == 0x0A0D0D0Au32;

    let unified: Vec<(u32, u32, Vec<u8>)> = if is_pcapng {
        console_log!("Detected PCAPng format");
        pcapng::parse_pcapng(data)
            .map_err(|e| JsValue::from_str(e.as_str()))?
    } else {
        console_log!("Detected legacy PCAP format");
        let (_, pkts) = pcap::iter_packets(data)
            .map_err(|e| JsValue::from_str(e.as_str()))?;
        pkts.iter().map(|p| (p.ts_sec, p.ts_usec, p.data.to_vec())).collect()
    };

    console_log!("Parsed: {} packets", unified.len());

    let mut analyzer  = Analyzer::new();
    let mut events:   Vec<TimedEvent> = Vec::new();
    let mut stp_count = 0usize;
    let mut last_ts   = analyzer::Timestamp { sec: 0, usec: 0 };

    let first_ts = unified.first()
        .map(|(s, u, _)| *s as f64 + *u as f64 / 1e6)
        .unwrap_or(0.0);

    for (ts_sec, ts_usec, pkt_data) in &unified {
        let ts = analyzer::Timestamp { sec: *ts_sec, usec: *ts_usec };
        last_ts = ts;

        // STP/RSTP/PVST+ живёт прямо поверх Ethernet — extract_bpdu фильтрует по dst MAC
        let Some((frame, bpdu_data)) = net::extract_bpdu(pkt_data) else { continue };

        let Some(bpdu) = stp::parse_bpdu(
            bpdu_data,
            frame.src_mac,
            frame.vlan_id,
        ) else { continue };

        stp_count += 1;

        let new_events = analyzer.process(&bpdu, ts);
        for ev in new_events {
            let severity = classify_event(&ev);
            events.push(TimedEvent { ts: ts.to_f64(), event: ev, severity });
        }
    }

    let final_events = analyzer.finalize(last_ts);
    for ev in final_events {
        let severity = classify_event(&ev);
        events.push(TimedEvent { ts: last_ts.to_f64(), event: ev, severity });
    }

    let topology   = analyzer.get_topology();
    let root_cause = root_cause::correlate(&events);

    let anomalies = events.iter().filter(|e|
        matches!(e.severity, Severity::Warning | Severity::Critical)
    ).count();

    let root_changes = events.iter().filter(|e|
        matches!(e.event, analyzer::StpEvent::RootChanged { .. })
    ).count();

    let tc_events = events.iter().filter(|e|
        matches!(e.event, analyzer::StpEvent::TopologyChange { .. } | analyzer::StpEvent::TcnReceived { .. })
    ).count();

    let tc_storms = events.iter().filter(|e|
        matches!(e.event, analyzer::StpEvent::TcStorm { .. })
    ).count();

    let root_flaps = events.iter().filter(|e|
        matches!(e.event, analyzer::StpEvent::RootFlapping { .. })
    ).count();

    let inferior_bpdus = events.iter().filter(|e|
        matches!(e.event, analyzer::StpEvent::InferiorBpdu { .. })
    ).count();

    let bridges_seen = {
        let mut macs = std::collections::HashSet::new();
        for te in &events {
            if let analyzer::StpEvent::BridgeDiscovered { bridge_mac, .. } = &te.event {
                macs.insert(bridge_mac.clone());
            }
        }
        macs.len()
    };

    let vlans_seen = {
        let mut vlans = std::collections::HashSet::new();
        for te in &events {
            match &te.event {
                analyzer::StpEvent::BpduReceived { vlan_id, .. } => { vlans.insert(vlan_id.unwrap_or(0)); }
                _ => {}
            }
        }
        vlans.len()
    };

    let report = FullReport {
        total_packets: unified.len(),
        stp_packets:   stp_count,
        duration_sec:  last_ts.to_f64() - first_ts,
        events,
        summary: ReportSummary {
            bridges_seen,
            vlans_seen,
            root_changes,
            tc_events,
            anomalies,
            tc_storms,
            root_flaps,
            inferior_bpdus,
        },
        root_cause,
        topology,
    };

    serde_wasm_bindgen::to_value(&report).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[derive(serde::Serialize)]
struct FullReport {
    total_packets: usize,
    stp_packets:   usize,
    duration_sec:  f64,
    events:        Vec<TimedEvent>,
    summary:       ReportSummary,
    root_cause:    root_cause::RootCauseReport,
    topology:      analyzer::TopologySnapshot,
}

pub use analyzer::Timestamp;
