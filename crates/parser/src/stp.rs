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
