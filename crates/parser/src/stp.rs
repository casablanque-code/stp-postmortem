// stp.rs — парсер BPDU для STP (802.1D), RSTP (802.1w), PVST+/Rapid-PVST+
// Spec: IEEE 802.1D-2004, 802.1w, Cisco PVST+ extensions

/// Тип BPDU
#[derive(Debug, Clone, PartialEq)]
pub enum BpduType {
    ConfigBpdu,   // 0x00 — STP Configuration BPDU
    TcnBpdu,      // 0x80 — Topology Change Notification
    RstBpdu,      // 0x02 — RSTP / Rapid-PVST+ BPDU
}

/// Роль порта (RSTP, биты 2-3 флагов)
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PortRole {
    Unknown,
    AlternateBackup,
    Root,
    Designated,
}

impl PortRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortRole::Unknown         => "Unknown",
            PortRole::AlternateBackup => "Alternate/Backup",
            PortRole::Root            => "Root",
            PortRole::Designated      => "Designated",
        }
    }

    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => PortRole::Unknown,
            0b01 => PortRole::AlternateBackup,
            0b10 => PortRole::Root,
            0b11 => PortRole::Designated,
            _    => PortRole::Unknown,
        }
    }
}

/// Bridge ID: priority (2 байта, включает system-id-extension) + MAC (6 байт)
#[derive(Debug, Clone, PartialEq)]
pub struct BridgeId {
    pub priority:  u16,   // старшие 4 бита — priority (шаг 4096), младшие 12 — sys-id-ext (VLAN)
    pub mac:       [u8; 6],
}

impl BridgeId {
    pub fn bridge_priority(&self) -> u16 { self.priority & 0xF000 }
    pub fn sys_id_ext(&self) -> u16      { self.priority & 0x0FFF }
    pub fn mac_str(&self) -> String {
        format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.mac[0], self.mac[1], self.mac[2],
            self.mac[3], self.mac[4], self.mac[5])
    }
    pub fn to_string(&self) -> String {
        format!("{}/{}", self.bridge_priority(), self.mac_str())
    }
    pub fn to_u64(&self) -> u64 {
        let mut v = (self.priority as u64) << 48;
        for (i, &b) in self.mac.iter().enumerate() {
            v |= (b as u64) << ((5 - i) * 8);
        }
        v
    }
}

/// Флаги BPDU (1 байт)
#[derive(Debug, Clone)]
pub struct BpduFlags {
    pub tc:               bool,  // bit 0 — Topology Change
    pub proposal:         bool,  // bit 1 — Proposal (RSTP)
    pub port_role:        PortRole, // bits 2-3 (RSTP)
    pub learning:         bool,  // bit 4 (RSTP)
    pub forwarding:       bool,  // bit 5 (RSTP)
    pub agreement:        bool,  // bit 6 (RSTP)
    pub tc_ack:           bool,  // bit 7 — TC Acknowledgement
}

impl BpduFlags {
    pub fn from_byte(b: u8) -> Self {
        BpduFlags {
            tc:          b & 0x01 != 0,
            proposal:    b & 0x02 != 0,
            port_role:   PortRole::from_bits((b >> 2) & 0b11),
            learning:    b & 0x10 != 0,
            forwarding:  b & 0x20 != 0,
            agreement:   b & 0x40 != 0,
            tc_ack:      b & 0x80 != 0,
        }
    }
}

/// Распарсенный BPDU
#[derive(Debug, Clone)]
pub struct Bpdu {
    pub bpdu_type:       BpduType,
    /// VLAN ID из 802.1Q тега (для PVST+)
    pub vlan_id:         Option<u16>,
    /// Порт-отправитель (src MAC фрейма)
    pub sender_mac:      [u8; 6],
    /// Флаги
    pub flags:           BpduFlags,
    /// Root Bridge ID
    pub root_id:         BridgeId,
    /// Root Path Cost
    pub root_path_cost:  u32,
    /// Bridge ID отправителя
    pub bridge_id:       BridgeId,
    /// Port ID (priority + port number)
    pub port_id:         u16,
    /// Message Age (в 1/256 секунды)
    pub message_age:     u16,
    /// Max Age
    pub max_age:         u16,
    /// Hello Time
    pub hello_time:      u16,
    /// Forward Delay
    pub forward_delay:   u16,
    /// RSTP: Version 1 Length (только для RST BPDU)
    pub is_rstp:         bool,
}

impl Bpdu {
    pub fn sender_mac_str(&self) -> String {
        crate::net::mac_str(&self.sender_mac)
    }

    /// True если отправитель сам считает себя Root
    pub fn is_root_bridge(&self) -> bool {
        self.root_id == self.bridge_id
    }

    pub fn hello_time_sec(&self) -> f32 { self.hello_time as f32 / 256.0 }
    pub fn max_age_sec(&self)    -> f32 { self.max_age as f32 / 256.0 }
    pub fn forward_delay_sec(&self) -> f32 { self.forward_delay as f32 / 256.0 }
    pub fn message_age_sec(&self)   -> f32 { self.message_age as f32 / 256.0 }
}

fn parse_bridge_id(data: &[u8], offset: usize) -> Option<BridgeId> {
    if offset + 8 > data.len() { return None; }
    let priority = u16::from_be_bytes([data[offset], data[offset + 1]]);
    let mac: [u8; 6] = data[offset + 2..offset + 8].try_into().ok()?;
    Some(BridgeId { priority, mac })
}

/// Парсим BPDU из payload после LLC заголовка
pub fn parse_bpdu(data: &[u8], sender_mac: [u8; 6], vlan_id: Option<u16>) -> Option<Bpdu> {
    if data.len() < 4 { return None; }

    // Protocol ID (2) = 0x0000, Version (1), BPDU Type (1)
    let proto = u16::from_be_bytes([data[0], data[1]]);
    if proto != 0x0000 { return None; }

    let _version  = data[2];
    let bpdu_type_byte = data[3];

    let bpdu_type = match bpdu_type_byte {
        0x00 => BpduType::ConfigBpdu,
        0x80 => BpduType::TcnBpdu,
        0x02 => BpduType::RstBpdu,
        _    => return None,
    };

    // TCN BPDU — минимальный, только 4 байта
    if bpdu_type == BpduType::TcnBpdu {
        return Some(Bpdu {
            bpdu_type,
            vlan_id,
            sender_mac,
            flags:           BpduFlags::from_byte(0),
            root_id:         BridgeId { priority: 0, mac: [0u8; 6] },
            root_path_cost:  0,
            bridge_id:       BridgeId { priority: 0, mac: sender_mac },
            port_id:         0,
            message_age:     0,
            max_age:         0,
            hello_time:      0,
            forward_delay:   0,
            is_rstp:         false,
        });
    }

    // Config BPDU и RST BPDU — минимум 35 байт
    if data.len() < 35 { return None; }

    let flags          = BpduFlags::from_byte(data[4]);
    let root_id        = parse_bridge_id(data, 5)?;
    let root_path_cost = u32::from_be_bytes([data[13], data[14], data[15], data[16]]);
    let bridge_id      = parse_bridge_id(data, 17)?;
    let port_id        = u16::from_be_bytes([data[25], data[26]]);
    let message_age    = u16::from_be_bytes([data[27], data[28]]);
    let max_age        = u16::from_be_bytes([data[29], data[30]]);
    let hello_time     = u16::from_be_bytes([data[31], data[32]]);
    let forward_delay  = u16::from_be_bytes([data[33], data[34]]);

    let is_rstp = bpdu_type == BpduType::RstBpdu;

    Some(Bpdu {
        bpdu_type,
        vlan_id,
        sender_mac,
        flags,
        root_id,
        root_path_cost,
        bridge_id,
        port_id,
        message_age,
        max_age,
        hello_time,
        forward_delay,
        is_rstp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_bridge_id_bytes(priority: u16, mac: [u8; 6]) -> Vec<u8> {
        let mut v = vec![0u8; 8];
        v[0] = (priority >> 8) as u8;
        v[1] = (priority & 0xff) as u8;
        v[2..8].copy_from_slice(&mac);
        v
    }

    fn make_rst_bpdu(
        root_priority: u16, root_mac: [u8; 6],
        root_cost: u32,
        bridge_priority: u16, bridge_mac: [u8; 6],
        port_id: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x00, 0x00]); // Protocol ID
        b.push(0x02);                        // Version: RSTP
        b.push(0x02);                        // Type: RST BPDU
        b.push(flags);
        b.extend_from_slice(&make_bridge_id_bytes(root_priority, root_mac));
        b.extend_from_slice(&root_cost.to_be_bytes());
        b.extend_from_slice(&make_bridge_id_bytes(bridge_priority, bridge_mac));
        b.extend_from_slice(&port_id.to_be_bytes());
        b.extend_from_slice(&512u16.to_be_bytes());  // message_age
        b.extend_from_slice(&5120u16.to_be_bytes()); // max_age
        b.extend_from_slice(&512u16.to_be_bytes());  // hello_time
        b.extend_from_slice(&3840u16.to_be_bytes()); // fwd_delay
        b.push(0x00);                                // version1_length
        b
    }

    fn make_tcn_bpdu() -> Vec<u8> {
        vec![0x00, 0x00, 0x00, 0x80]
    }

    fn make_config_bpdu(
        root_priority: u16, root_mac: [u8; 6],
        root_cost: u32,
        bridge_priority: u16, bridge_mac: [u8; 6],
        port_id: u16,
        flags: u8,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x00, 0x00]); // Protocol ID
        b.push(0x00);                        // Version: STP
        b.push(0x00);                        // Type: Config
        b.push(flags);
        b.extend_from_slice(&make_bridge_id_bytes(root_priority, root_mac));
        b.extend_from_slice(&root_cost.to_be_bytes());
        b.extend_from_slice(&make_bridge_id_bytes(bridge_priority, bridge_mac));
        b.extend_from_slice(&port_id.to_be_bytes());
        b.extend_from_slice(&512u16.to_be_bytes());
        b.extend_from_slice(&5120u16.to_be_bytes());
        b.extend_from_slice(&512u16.to_be_bytes());
        b.extend_from_slice(&3840u16.to_be_bytes());
        b
    }

    const MAC_A: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x01];
    const MAC_B: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x02];

    // ── parse_bpdu ────────────────────────────────────────────────────────────

    #[test]
    fn test_parse_rst_bpdu_basic() {
        let data = make_rst_bpdu(4096, MAC_A, 0, 4096, MAC_A, 0x8001, 0x3c);
        let bpdu = parse_bpdu(&data, MAC_A, None).expect("should parse");
        assert_eq!(bpdu.bpdu_type, BpduType::RstBpdu);
        assert!(bpdu.is_rstp);
        assert_eq!(bpdu.root_id.bridge_priority(), 4096);
        assert_eq!(bpdu.root_id.mac, MAC_A);
        assert_eq!(bpdu.root_path_cost, 0);
        assert_eq!(bpdu.port_id, 0x8001);
    }

    #[test]
    fn test_parse_config_bpdu() {
        let data = make_config_bpdu(4096, MAC_A, 0, 8192, MAC_B, 0x8002, 0x00);
        let bpdu = parse_bpdu(&data, MAC_B, None).expect("should parse");
        assert_eq!(bpdu.bpdu_type, BpduType::ConfigBpdu);
        assert!(!bpdu.is_rstp);
        assert_eq!(bpdu.bridge_id.bridge_priority(), 8192);
        assert_eq!(bpdu.bridge_id.mac, MAC_B);
    }

    #[test]
    fn test_parse_tcn_bpdu() {
        let data = make_tcn_bpdu();
        let bpdu = parse_bpdu(&data, MAC_A, None).expect("should parse TCN");
        assert_eq!(bpdu.bpdu_type, BpduType::TcnBpdu);
    }

    #[test]
    fn test_parse_bpdu_too_short_returns_none() {
        let data = vec![0x00, 0x00, 0x02]; // 3 bytes, too short
        assert!(parse_bpdu(&data, MAC_A, None).is_none());
    }

    #[test]
    fn test_parse_bpdu_wrong_protocol_id() {
        let mut data = make_rst_bpdu(4096, MAC_A, 0, 4096, MAC_A, 0x8001, 0x3c);
        data[0] = 0x01; // Protocol ID != 0x0000
        assert!(parse_bpdu(&data, MAC_A, None).is_none());
    }

    #[test]
    fn test_parse_bpdu_unknown_type() {
        let data = vec![0x00, 0x00, 0x00, 0x42]; // unknown type 0x42
        assert!(parse_bpdu(&data, MAC_A, None).is_none());
    }

    #[test]
    fn test_vlan_id_preserved() {
        let data = make_rst_bpdu(4096, MAC_A, 0, 4096, MAC_A, 0x8001, 0x3c);
        let bpdu = parse_bpdu(&data, MAC_A, Some(10)).expect("should parse");
        assert_eq!(bpdu.vlan_id, Some(10));
    }

    // ── BridgeId ─────────────────────────────────────────────────────────────

    #[test]
    fn test_bridge_id_priority_extraction() {
        let bid = BridgeId { priority: 0x1000, mac: MAC_A }; // 4096
        assert_eq!(bid.bridge_priority(), 4096);
        assert_eq!(bid.sys_id_ext(), 0);
    }

    #[test]
    fn test_bridge_id_sys_id_ext_pvst() {
        // PVST+: priority field encodes VLAN in lower 12 bits
        // priority=0x100A → priority=4096, sys_id_ext=10 (VLAN 10)
        let bid = BridgeId { priority: 0x100A, mac: MAC_A };
        assert_eq!(bid.bridge_priority(), 4096);
        assert_eq!(bid.sys_id_ext(), 10);
    }

    #[test]
    fn test_bridge_id_to_u64_ordering() {
        // Lower u64 = better (wins election)
        let better = BridgeId { priority: 4096, mac: MAC_A };
        let worse  = BridgeId { priority: 8192, mac: MAC_A };
        assert!(better.to_u64() < worse.to_u64());
    }

    #[test]
    fn test_bridge_id_mac_tiebreak() {
        let lower_mac = BridgeId { priority: 4096, mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x01] };
        let higher_mac= BridgeId { priority: 4096, mac: [0x00, 0x11, 0x22, 0x33, 0x44, 0x02] };
        assert!(lower_mac.to_u64() < higher_mac.to_u64());
    }

    #[test]
    fn test_bridge_id_mac_str() {
        let bid = BridgeId { priority: 4096, mac: MAC_A };
        assert_eq!(bid.mac_str(), "00:11:22:33:44:01");
    }

    #[test]
    fn test_bridge_id_to_string() {
        let bid = BridgeId { priority: 4096, mac: MAC_A };
        assert_eq!(bid.to_string(), "4096/00:11:22:33:44:01");
    }

    // ── BpduFlags ────────────────────────────────────────────────────────────

    #[test]
    fn test_flags_tc_bit() {
        let f = BpduFlags::from_byte(0x01);
        assert!(f.tc);
        assert!(!f.proposal);
        assert!(!f.tc_ack);
    }

    #[test]
    fn test_flags_forwarding_learning() {
        // 0x3c = 0b00111100 = forwarding(5) | learning(4) | designated_role(3:2)
        let f = BpduFlags::from_byte(0x3c);
        assert!(f.forwarding);
        assert!(f.learning);
        assert!(!f.tc);
        assert_eq!(f.port_role, PortRole::Designated);
    }

    #[test]
    fn test_flags_root_port_role() {
        // bits 2-3 = 0b10 → Root
        let f = BpduFlags::from_byte(0x08); // 0b00001000
        assert_eq!(f.port_role, PortRole::Root);
    }

    #[test]
    fn test_flags_alternate_backup_role() {
        let f = BpduFlags::from_byte(0x04); // bits 2-3 = 0b01
        assert_eq!(f.port_role, PortRole::AlternateBackup);
    }

    #[test]
    fn test_flags_tc_ack() {
        let f = BpduFlags::from_byte(0x80);
        assert!(f.tc_ack);
        assert!(!f.tc);
    }

    // ── is_root_bridge ───────────────────────────────────────────────────────

    #[test]
    fn test_is_root_bridge_true() {
        let data = make_rst_bpdu(4096, MAC_A, 0, 4096, MAC_A, 0x8001, 0x3c);
        let bpdu = parse_bpdu(&data, MAC_A, None).unwrap();
        assert!(bpdu.is_root_bridge());
    }

    #[test]
    fn test_is_root_bridge_false() {
        // root=MAC_A, bridge=MAC_B → not root
        let data = make_rst_bpdu(4096, MAC_A, 4, 8192, MAC_B, 0x8001, 0x3c);
        let bpdu = parse_bpdu(&data, MAC_B, None).unwrap();
        assert!(!bpdu.is_root_bridge());
    }

    // ── timing helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_hello_time_sec() {
        let data = make_rst_bpdu(4096, MAC_A, 0, 4096, MAC_A, 0x8001, 0x3c);
        let bpdu = parse_bpdu(&data, MAC_A, None).unwrap();
        // hello_time=512 → 512/256 = 2.0s
        assert!((bpdu.hello_time_sec() - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_max_age_sec() {
        let data = make_rst_bpdu(4096, MAC_A, 0, 4096, MAC_A, 0x8001, 0x3c);
        let bpdu = parse_bpdu(&data, MAC_A, None).unwrap();
        // max_age=5120 → 5120/256 = 20.0s
        assert!((bpdu.max_age_sec() - 20.0).abs() < 0.01);
    }
}
