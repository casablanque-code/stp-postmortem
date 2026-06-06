// pcap.rs — парсит legacy PCAP формат (не PCAPng)
// Spec: https://wiki.wireshark.org/Development/LibpcapFileFormat

use nom::{
    bytes::complete::take,
    number::complete::{le_u16, le_u32, be_u32},
    IResult,
};

/// Magic numbers
const MAGIC_LE: u32 = 0xa1b2c3d4; // little-endian, microseconds
const MAGIC_BE: u32 = 0xd4c3b2a1; // big-endian, microseconds

#[derive(Debug, Clone)]
pub struct PcapHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub network: u32, // link-layer type
    pub big_endian: bool,
}

#[derive(Debug, Clone)]
pub struct RawPacket<'a> {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub data: &'a [u8],
}

/// Парсим глобальный хедер
pub fn parse_pcap_header(input: &[u8]) -> IResult<&[u8], PcapHeader> {
    let (input, magic) = le_u32(input)?;

    let big_endian = match magic {
        MAGIC_LE => false,
        MAGIC_BE => true,
        _ => {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Tag,
            )))
        }
    };

    // Дальше парсим с учётом endianness файла
    if big_endian {
        let (input, version_major) = nom::number::complete::be_u16(input)?;
        let (input, version_minor) = nom::number::complete::be_u16(input)?;
        let (input, _thiszone) = be_u32(input)?;
        let (input, _sigfigs) = be_u32(input)?;
        let (input, snaplen) = be_u32(input)?;
        let (input, network) = be_u32(input)?;
        Ok((input, PcapHeader { magic, version_major, version_minor, snaplen, network, big_endian }))
    } else {
        let (input, version_major) = le_u16(input)?;
        let (input, version_minor) = le_u16(input)?;
        let (input, _thiszone) = le_u32(input)?;
        let (input, _sigfigs) = le_u32(input)?;
        let (input, snaplen) = le_u32(input)?;
        let (input, network) = le_u32(input)?;
        Ok((input, PcapHeader { magic, version_major, version_minor, snaplen, network, big_endian }))
    }
}

/// Парсим один packet record
pub fn parse_packet<'a>(input: &'a [u8], big_endian: bool) -> IResult<&'a [u8], RawPacket<'a>> {
    let (input, ts_sec) = if big_endian { be_u32(input)? } else { le_u32(input)? };
    let (input, ts_usec) = if big_endian { be_u32(input)? } else { le_u32(input)? };
    let (input, incl_len) = if big_endian { be_u32(input)? } else { le_u32(input)? };
    let (input, _orig_len) = if big_endian { be_u32(input)? } else { le_u32(input)? };
    let (input, data) = take(incl_len)(input)?;

    Ok((input, RawPacket { ts_sec, ts_usec, data }))
}

/// Итерируем все пакеты из файла
pub fn iter_packets(mut input: &[u8]) -> Result<(PcapHeader, Vec<RawPacket<'_>>), String> {
    let (rest, header) = parse_pcap_header(input)
        .map_err(|e| format!("Failed to parse PCAP header: {:?}", e))?;

    // network == 1 — Ethernet, что нам и нужно
    if header.network != 1 {
        return Err(format!(
            "Unsupported link type: {} (only Ethernet/1 supported)",
            header.network
        ));
    }

    input = rest;
    let mut packets = Vec::new();

    while !input.is_empty() {
        match parse_packet(input, header.big_endian) {
            Ok((rest, pkt)) => {
                packets.push(pkt);
                input = rest;
            }
            Err(_) => break,
        }
    }

    Ok((header, packets))
}
