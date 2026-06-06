// pcapng.rs — парсит PCAPng формат (RFC) 
// Spec: https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.txt

use crate::pcap::RawPacket;

const SHB_MAGIC: u32 = 0x0A0D0D0A;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B3C4D;
const BYTE_ORDER_MAGIC_SWAPPED: u32 = 0x4D3C2B1A;

const BLOCK_SHB: u32 = 0x0A0D0D0A;
const BLOCK_IDB: u32 = 0x00000001;
const BLOCK_EPB: u32 = 0x00000006;
const BLOCK_SPB: u32 = 0x00000003;
const BLOCK_OPB: u32 = 0x00000002; // Obsolete Packet Block

/// Метаданные интерфейса из IDB
#[derive(Debug, Clone)]
struct Interface {
    link_type: u16,
    ts_resol: u8, // временное разрешение — 10^-resol или 2^-resol
    ts_offset: u64,
}

impl Interface {
    fn ts_to_secs_usecs(&self, ts: u64) -> (u32, u32) {
        // По умолчанию ts_resol=6 → микросекунды
        let resol = self.ts_resol;
        let (sec, frac) = if resol == 6 {
            // microseconds
            (ts / 1_000_000, ts % 1_000_000)
        } else if resol == 9 {
            // nanoseconds → конвертируем в микросекунды
            (ts / 1_000_000_000, (ts % 1_000_000_000) / 1_000)
        } else {
            // generic: 10^-resol
            let factor = 10u64.pow(resol as u32);
            (ts / factor, (ts % factor) * 1_000_000 / factor)
        };
        ((sec + self.ts_offset) as u32, frac as u32)
    }
}

fn read_u16(data: &[u8], offset: usize, big_endian: bool) -> Option<u16> {
    if offset + 2 > data.len() { return None; }
    let b = &data[offset..offset+2];
    Some(if big_endian {
        u16::from_be_bytes([b[0], b[1]])
    } else {
        u16::from_le_bytes([b[0], b[1]])
    })
}

fn read_u32(data: &[u8], offset: usize, big_endian: bool) -> Option<u32> {
    if offset + 4 > data.len() { return None; }
    let b = &data[offset..offset+4];
    Some(if big_endian {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    })
}

fn read_u64(data: &[u8], offset: usize, big_endian: bool) -> Option<u64> {
    if offset + 8 > data.len() { return None; }
    let b = &data[offset..offset+8];
    Some(if big_endian {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// Парсим PCAPng файл, возвращаем Vec<RawPacket>
/// Аллоцируем данные пакетов в переданный буфер
pub fn parse_pcapng(data: &[u8]) -> Result<Vec<(u32, u32, Vec<u8>)>, String> {
    if data.len() < 12 {
        return Err("File too short for PCAPng".into());
    }

    // Проверяем SHB magic
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != SHB_MAGIC {
        return Err(format!("Not a PCAPng file (magic: 0x{:08x})", magic));
    }

    let mut pos = 0usize;
    let mut big_endian = false;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut packets: Vec<(u32, u32, Vec<u8>)> = Vec::new();

    while pos + 8 <= data.len() {
        // block_type читаем с текущим endianness
        // SHB (0x0A0D0D0A) одинаков в обоих порядках — безопасно
        let block_type = read_u32(data, pos, big_endian)
            .ok_or("Failed to read block type")?;
        // block_len читаем с текущим endianness
        // Для SHB endianness ещё не определён — читаем LE, потом корректируем
        let block_len_raw = read_u32(data, pos + 4, false)
            .ok_or("Failed to read block length")?;
        let block_len = if block_type == BLOCK_SHB {
            block_len_raw // SHB всегда читаем LE до определения BOM
        } else {
            read_u32(data, pos + 4, big_endian)
                .ok_or("Failed to read block length")?
        };

        if block_len < 12 || pos + block_len as usize > data.len() {
            break;
        }

        let block_data = &data[pos..pos + block_len as usize];

        match block_type {
            BLOCK_SHB => {
                // Section Header Block
                // offset 8: Byte-Order Magic
                if block_len < 16 { 
                    pos += block_len as usize;
                    continue;
                }
                let bom = u32::from_le_bytes([
                    block_data[8], block_data[9], 
                    block_data[10], block_data[11]
                ]);
                big_endian = match bom {
                    BYTE_ORDER_MAGIC         => false,
                    BYTE_ORDER_MAGIC_SWAPPED => true,
                    _ => return Err(format!("Invalid BOM: 0x{:08x}", bom)),
                };
                // Новая секция — сбрасываем интерфейсы
                interfaces.clear();
            }

            BLOCK_IDB => {
                // Interface Description Block
                // offset 8: LinkType (2), Reserved (2), SnapLen (4)
                if block_len < 20 {
                    pos += block_len as usize;
                    continue;
                }
                let link_type = read_u16(block_data, 8, big_endian).unwrap_or(1);
                // Парсим опции для ts_resol и ts_offset
                let mut ts_resol = 6u8; // default: microseconds
                let mut ts_offset = 0u64;

                let opts_start = 16usize;
                let opts_end = block_len as usize - 4;
                let mut opos = opts_start;
                while opos + 4 <= opts_end {
                    let opt_code = read_u16(block_data, opos, big_endian).unwrap_or(0);
                    let opt_len  = read_u16(block_data, opos + 2, big_endian).unwrap_or(0) as usize;
                    opos += 4;
                    if opt_code == 0 { break; } // endofopt
                    if opos + opt_len <= opts_end {
                        match opt_code {
                            9 => { // if_tsresol
                                if opt_len >= 1 {
                                    ts_resol = block_data[opos];
                                }
                            }
                            14 => { // if_tsoffset
                                if opt_len >= 8 {
                                    ts_offset = read_u64(block_data, opos, big_endian).unwrap_or(0);
                                }
                            }
                            _ => {}
                        }
                    }
                    // Опции выровнены по 4 байта
                    opos += (opt_len + 3) & !3;
                }

                interfaces.push(Interface { link_type, ts_resol, ts_offset });
            }

            BLOCK_EPB => {
                // Enhanced Packet Block
                // offset 8:  Interface ID (4)
                // offset 12: Timestamp High (4)
                // offset 16: Timestamp Low (4)
                // offset 20: Captured Packet Length (4)
                // offset 24: Original Packet Length (4)
                // offset 28: Packet Data
                if block_len < 32 {
                    pos += block_len as usize;
                    continue;
                }
                let iface_id   = read_u32(block_data, 8,  big_endian).unwrap_or(0) as usize;
                let ts_high    = read_u32(block_data, 12, big_endian).unwrap_or(0) as u64;
                let ts_low     = read_u32(block_data, 16, big_endian).unwrap_or(0) as u64;
                let cap_len    = read_u32(block_data, 20, big_endian).unwrap_or(0) as usize;

                let ts = (ts_high << 32) | ts_low;

                let iface = interfaces.get(iface_id).cloned()
                    .unwrap_or(Interface { link_type: 1, ts_resol: 6, ts_offset: 0 });

                // Только Ethernet (link_type == 1)
                if iface.link_type != 1 {
                    pos += block_len as usize;
                    continue;
                }

                let data_start = 28usize;
                if data_start + cap_len <= block_len as usize - 4 {
                    let pkt_data = block_data[data_start..data_start + cap_len].to_vec();
                    let (ts_sec, ts_usec) = iface.ts_to_secs_usecs(ts);
                    packets.push((ts_sec, ts_usec, pkt_data));
                }
            }

            BLOCK_OPB => {
                // Obsolete Packet Block (старый формат)
                // offset 8:  Interface ID (2), Drops Count (2)
                // offset 12: Timestamp High (4)
                // offset 16: Timestamp Low (4)
                // offset 20: Captured Length (4)
                // offset 24: Original Length (4)
                // offset 28: Packet Data
                if block_len < 32 {
                    pos += block_len as usize;
                    continue;
                }
                let iface_id = read_u16(block_data, 8, big_endian).unwrap_or(0) as usize;
                let ts_high  = read_u32(block_data, 12, big_endian).unwrap_or(0) as u64;
                let ts_low   = read_u32(block_data, 16, big_endian).unwrap_or(0) as u64;
                let cap_len  = read_u32(block_data, 20, big_endian).unwrap_or(0) as usize;
                let ts       = (ts_high << 32) | ts_low;

                let iface = interfaces.get(iface_id).cloned()
                    .unwrap_or(Interface { link_type: 1, ts_resol: 6, ts_offset: 0 });

                if iface.link_type != 1 {
                    pos += block_len as usize;
                    continue;
                }

                let data_start = 28usize;
                if data_start + cap_len <= block_len as usize - 4 {
                    let pkt_data = block_data[data_start..data_start + cap_len].to_vec();
                    let (ts_sec, ts_usec) = iface.ts_to_secs_usecs(ts);
                    packets.push((ts_sec, ts_usec, pkt_data));
                }
            }

            BLOCK_SPB => {
                // Simple Packet Block — нет timestamp, используем 0
                if block_len < 16 {
                    pos += block_len as usize;
                    continue;
                }
                let orig_len = read_u32(block_data, 8, big_endian).unwrap_or(0) as usize;
                let cap_len  = orig_len.min(block_len as usize - 16);
                let iface    = interfaces.first().cloned()
                    .unwrap_or(Interface { link_type: 1, ts_resol: 6, ts_offset: 0 });

                if iface.link_type == 1 && cap_len > 0 {
                    let pkt_data = block_data[12..12 + cap_len].to_vec();
                    packets.push((0, 0, pkt_data));
                }
            }

            _ => {
                // Неизвестный блок — пропускаем
            }
        }

        pos += block_len as usize;
    }

    Ok(packets)
}
