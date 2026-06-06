// net.rs — Ethernet frame dispatch для STP/RSTP/PVST+
// STP не использует IP — BPDU идут прямо поверх 802.3 + LLC
// или поверх 802.1Q для PVST+

/// STP/RSTP multicast dst MAC (IEEE 802.1D)
pub const STP_MCAST: [u8; 6]      = [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00];
/// Cisco PVST+ multicast dst MAC
pub const PVST_MCAST: [u8; 6]     = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd];

pub const ETHERTYPE_8021Q:  u16 = 0x8100;
pub const ETHERTYPE_8021AD: u16 = 0x88a8;

/// LLC SAP для STP (0x42 / 0x42)
pub const LLC_STP_DSAP: u8 = 0x42;
pub const LLC_STP_SSAP: u8 = 0x42;

/// Тип фрейма после разбора
#[derive(Debug, Clone, PartialEq)]
pub enum FrameKind {
    Stp,   // IEEE 802.1D/RSTP BPDU
    Pvst,  // Cisco PVST+/Rapid-PVST+ BPDU
}

/// Мета-данные Ethernet фрейма нужные анализатору
#[derive(Debug, Clone)]
pub struct EtherFrame {
    pub src_mac:   [u8; 6],
    pub dst_mac:   [u8; 6],
    pub vlan_id:   Option<u16>, // None если нет 802.1Q тега
    pub kind:      FrameKind,
}

impl EtherFrame {
    pub fn src_mac_str(&self) -> String { mac_str(&self.src_mac) }
    pub fn dst_mac_str(&self) -> String { mac_str(&self.dst_mac) }
}

pub fn mac_str(m: &[u8; 6]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5])
}

/// Извлекаем из raw Ethernet фрейма:
/// - мета-данные фрейма (src/dst MAC, VLAN)
/// - payload после LLC заголовка (сам BPDU)
///
/// Возвращает None если это не STP/PVST фрейм
pub fn extract_bpdu(frame: &[u8]) -> Option<(EtherFrame, &[u8])> {
    if frame.len() < 14 { return None; }

    let dst_mac: [u8; 6] = frame[0..6].try_into().ok()?;
    let src_mac: [u8; 6] = frame[6..12].try_into().ok()?;

    // Определяем тип фрейма по dst MAC
    let is_stp  = dst_mac == STP_MCAST;
    let is_pvst = dst_mac == PVST_MCAST;
    if !is_stp && !is_pvst { return None; }

    let kind = if is_pvst { FrameKind::Pvst } else { FrameKind::Stp };

    // offset 12: либо length (802.3) либо ethertype (Ethernet II)
    let field = u16::from_be_bytes([frame[12], frame[13]]);

    let (vlan_id, llc_start) = if field == ETHERTYPE_8021Q {
        // 802.1Q тег: 4 байта, потом снова length/ethertype
        if frame.len() < 18 { return None; }
        let tci      = u16::from_be_bytes([frame[14], frame[15]]);
        let vid      = tci & 0x0FFF;
        // frame[16..18] = inner length/ethertype, пропускаем
        (Some(vid), 18usize)
    } else if field < 0x0600 {
        // 802.3 length — сразу LLC
        (None, 14usize)
    } else {
        // Ethernet II без тега — у STP такого быть не должно, но на всякий случай
        return None;
    };

    // LLC header: DSAP(1) + SSAP(1) + Control(1)
    if frame.len() < llc_start + 3 { return None; }
    let dsap    = frame[llc_start];
    let ssap    = frame[llc_start + 1];
    // control = frame[llc_start + 2], для STP всегда 0x03 (UI frame)

    // PVST+ использует SNAP вместо LLC SAP 0x42 у некоторых реализаций,
    // но большинство Cisco всё равно шлёт 0x42/0x42 — принимаем оба варианта
    if dsap != LLC_STP_DSAP && dsap != 0xAA { return None; }
    if ssap != LLC_STP_SSAP && ssap != 0xAA { return None; }

    let bpdu_start = if dsap == 0xAA {
        // SNAP: LLC(3) + OUI(3) + type(2) = 8 байт
        llc_start + 8
    } else {
        llc_start + 3
    };

    if frame.len() <= bpdu_start { return None; }

    Some((EtherFrame { src_mac, dst_mac, vlan_id, kind }, &frame[bpdu_start..]))
}
