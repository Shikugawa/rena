use crate::addresses::mac::MacAddr;
use crate::buffer::Buffer;
use crate::frames::arp::ArpFrame;
use crate::frames::codec::Codec;
use crate::frames::frame::Frame;
use crate::frames::ipv4::Ipv4Frame;
use crate::utils::bit_calculation::{extract_2u8_from_u16, extract_u16_from_2u8, push_bytes};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use std::fmt;

// https://en.wikipedia.org/wiki/EtherType
#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Arp = 0x0806,
    Ipv4 = 0x0800,
    Ipv6 = 0x86DD,
    Unknown = 0xFFFF,
}

impl Default for EtherType {
    fn default() -> Self {
        EtherType::Unknown
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &EtherType::Arp => write!(f, "ARP"),
            &EtherType::Ipv4 => write!(f, "IPv4"),
            &EtherType::Ipv6 => write!(f, "IPv6"),
            &EtherType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Codec<EtherType, [u8; 2]> for EtherType {
    fn encode(from: EtherType) -> [u8; 2] {
        extract_2u8_from_u16(from as u16)
    }

    fn decode(from: [u8; 2]) -> EtherType {
        let ether_type = extract_u16_from_2u8(from);
        if ether_type == EtherType::Arp as u16 {
            EtherType::Arp
        } else if ether_type == EtherType::Ipv4 as u16 {
            EtherType::Ipv4
        } else if ether_type == EtherType::Ipv6 as u16 {
            EtherType::Ipv6
        } else {
            EtherType::Unknown
        }
    }
}

static ETHER_HDR_LEN: usize = 14;

pub enum EthernetPayload {
    ArpPayload(ArpFrame),
    Ipv4Payload(Ipv4Frame),
    Unknown,
}

impl Default for EthernetPayload {
    fn default() -> Self {
        EthernetPayload::Unknown
    }
}

#[derive(Default)]
pub struct EthernetFrame {
    saddr: MacAddr,        // 6Bytes
    daddr: MacAddr,        // 6Bytes
    frame_type: EtherType, // 2Bytes
    payload: EthernetPayload,
}

impl fmt::Display for EthernetFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ether Type: {}
Mac Address (src): {}
Mac Address (dst): {}
    ",
            self.frame_type, self.saddr, self.daddr
        )
    }
}

impl Frame for EthernetFrame {
    fn to_bytes(&self) -> BytesMut {
        let mut packet = BytesMut::with_capacity(ETHER_HDR_LEN);
        push_bytes(&mut packet, self.daddr.to_bytes().iter());
        push_bytes(&mut packet, self.saddr.to_bytes().iter());
        push_bytes(&mut packet, EtherType::encode(self.frame_type).iter());

        match &self.payload {
            EthernetPayload::Unknown => packet,
            EthernetPayload::ArpPayload(p) => BytesMut::from_iter([packet, p.to_bytes()].concat()),
            EthernetPayload::Ipv4Payload(p) => BytesMut::from_iter([packet, p.to_bytes()].concat()),
        }
    }

    fn frame_length(&self) -> usize {
        self.header_length() + self.payload_length()
    }

    fn header_length(&self) -> usize {
        ETHER_HDR_LEN
    }

    fn payload_length(&self) -> usize {
        match &self.payload {
            EthernetPayload::Unknown => 0,
            EthernetPayload::ArpPayload(p) => p.frame_length(),
            EthernetPayload::Ipv4Payload(p) => p.frame_length(),
        }
    }
}

impl EthernetFrame {
    pub fn from_raw(raw_buf: &mut Buffer) -> Self {
        let daddr = MacAddr::new(raw_buf.get_slice_6());
        let saddr = MacAddr::new(raw_buf.get_slice_6());
        let frame_type = EtherType::decode(raw_buf.get_slice_2());
        let payload = match frame_type {
            EtherType::Arp => EthernetPayload::ArpPayload(ArpFrame::from_raw(raw_buf)),
            EtherType::Ipv4 => EthernetPayload::Ipv4Payload(Ipv4Frame::from_raw(raw_buf)),
            EtherType::Ipv6 | EtherType::Unknown => EthernetPayload::Unknown,
        };
        EthernetFrame::new(saddr, daddr, frame_type, payload)
    }

    pub fn new(saddr: MacAddr, daddr: MacAddr, etype: EtherType, payload: EthernetPayload) -> Self {
        let ethernet_frame = EthernetFrame {
            saddr,
            daddr,
            frame_type: etype,
            payload: payload,
        };
        ethernet_frame
    }

    pub fn frame_type(&self) -> EtherType {
        self.frame_type
    }

    pub fn arp_payload(&self) -> Result<&ArpFrame> {
        match &self.payload {
            EthernetPayload::ArpPayload(p) => Ok(p),
            _ => Err(anyhow!("failed to get arp payload")),
        }
    }

    pub fn ipv4_payload(&self) -> Result<&Ipv4Frame> {
        match &self.payload {
            EthernetPayload::Ipv4Payload(p) => Ok(p),
            _ => Err(anyhow!("failed to get ipv4 payload")),
        }
    }
}
