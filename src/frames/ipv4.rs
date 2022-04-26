use crate::addresses::ipv4::Ipv4Addr;
use crate::buffer::Buffer;
use crate::frames::codec::Codec;
use crate::frames::frame::Frame;
use crate::frames::icmp::IcmpFrame;
use crate::frames::tcp::TcpFrame;
use crate::utils::bit_calculation::{
    extract_nbit_be_left_from_u16, extract_nbit_be_left_from_u8, extract_nbit_be_right_from_u16,
    extract_nbit_be_right_from_u8, extract_u16_from_2u8, merge_2u8_to_u8, push_bytes,
};
use crate::utils::checksum::{calculate_checksum, verify_checksum};
use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};
use log::warn;
use rand::{thread_rng, Rng};
use std::fmt;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    Ipv4 = 0x0004,
    Ipv6 = 0x0006,
    Unknown = 0x00FF,
}

impl Default for IpVersion {
    fn default() -> Self {
        IpVersion::Unknown
    }
}

impl fmt::Display for IpVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &IpVersion::Ipv4 => write!(f, "IPv4"),
            &IpVersion::Ipv6 => write!(f, "IPv6"),
            &IpVersion::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Codec<IpVersion, u8> for IpVersion {
    fn encode(from: IpVersion) -> u8 {
        from as u8
    }

    fn decode(from: u8) -> IpVersion {
        if from == IpVersion::Ipv4 as u8 {
            IpVersion::Ipv4
        } else if from == IpVersion::Ipv6 as u8 {
            IpVersion::Ipv6
        } else {
            IpVersion::Unknown
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IpFlags {
    None = 0x0000,
    DontFragment = 0x2,
    MoreFragments = 0x4,
    Unknown = 0xF,
}

impl Default for IpFlags {
    fn default() -> Self {
        IpFlags::None
    }
}

impl fmt::Display for IpFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &IpFlags::None => write!(f, "None"),
            &IpFlags::DontFragment => write!(f, "DF"),
            &IpFlags::MoreFragments => write!(f, "MF"),
            &IpFlags::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Codec<IpFlags, u8> for IpFlags {
    fn encode(from: IpFlags) -> u8 {
        from as u8
    }

    fn decode(from: u8) -> IpFlags {
        if from == IpFlags::None as u8 {
            IpFlags::None
        } else if from == IpFlags::DontFragment as u8 {
            IpFlags::DontFragment
        } else if from == IpFlags::MoreFragments as u8 {
            IpFlags::MoreFragments
        } else {
            IpFlags::Unknown
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    Icmp = 0x01,
    Tcp = 0x06,
    Unknown = 0x00FF,
}

impl Default for IpProtocol {
    fn default() -> Self {
        IpProtocol::Unknown
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &IpProtocol::Icmp => write!(f, "ICMP"),
            &IpProtocol::Tcp => write!(f, "TCP"),
            &IpProtocol::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Codec<IpProtocol, u8> for IpProtocol {
    fn encode(from: IpProtocol) -> u8 {
        from as u8
    }

    fn decode(from: u8) -> IpProtocol {
        if from == IpProtocol::Icmp as u8 {
            IpProtocol::Icmp
        } else if from == IpProtocol::Tcp as u8 {
            IpProtocol::Tcp
        } else {
            IpProtocol::Unknown
        }
    }
}

#[derive(Clone)]
pub enum Ipv4Payload {
    IcmpPayload(IcmpFrame),
    TcpPayload(TcpFrame),
    Unknown,
}

impl Default for Ipv4Payload {
    fn default() -> Self {
        Ipv4Payload::Unknown
    }
}

const IPV4_DEFAULT_HDR_SIZE: usize = 20;

// https://en.wikipedia.org/wiki/IPv4
#[derive(Default, Clone)]
pub struct Ipv4Frame {
    version: IpVersion, // 4 bits (<= 0x00FF)
    ihl: u8,            // 4 bits (<= 0x00FF)
    // 1 Byte
    dscp: u8, // 6 bits
    ecn: u8,  // 2 bits
    // 1 Byte
    length: u16,         // 2 bytes
    identification: u16, // 2 bytes
    // 2 Bytes
    flags: IpFlags,   // 3 bits,
    flag_offset: u16, // 13 bits,
    // 2 Bytes
    ttl: u8,
    protocol: IpProtocol,
    // 2 Bytes
    cksum: u16,
    // 2 Bytes
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    options: Option<BytesMut>, // if ihl > 5
    payload: Ipv4Payload,
}

impl fmt::Display for Ipv4Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "        Version: {}
        Internet Header Length (IHL): {}
        Differentiated Services Code Point (DSCP): {}
        Explicit Congestion Notification (ECN): {}
        Total Length: {}
        Identification: {}
        Flags: {}
        Fragment Offset: {}
        TTL: {}
        Protocol: {}
        CheckSum: {}
        Source IP: {}
        Dst IP: {}
",
            self.version,
            self.ihl,
            self.dscp,
            self.ecn,
            self.length,
            self.identification,
            self.flags,
            self.flag_offset,
            self.ttl,
            self.protocol,
            self.cksum,
            self.src_ip,
            self.dst_ip
        )
    }
}

impl Frame for Ipv4Frame {
    fn to_bytes(&self) -> BytesMut {
        let mut packet = BytesMut::with_capacity(self.header_length() as usize);
        packet.put_u8(merge_2u8_to_u8(
            IpVersion::encode(self.version),
            self.ihl,
            4,
        ));
        packet.put_u8(merge_2u8_to_u8(self.dscp, self.ecn, 2));
        packet.put_u16(self.length);
        packet.put_u16(self.identification);
        packet.put_u16((IpFlags::encode(self.flags) as u16) << 13 | self.flag_offset);
        packet.put_u8(self.ttl);
        packet.put_u8(IpProtocol::encode(self.protocol));
        packet.put_u16(self.cksum);
        push_bytes(&mut packet, self.src_ip.to_bytes().iter());
        push_bytes(&mut packet, self.dst_ip.to_bytes().iter());

        match &self.payload {
            Ipv4Payload::Unknown => packet,
            Ipv4Payload::IcmpPayload(p) => BytesMut::from_iter([packet, p.to_bytes()].concat()),
            Ipv4Payload::TcpPayload(p) => BytesMut::from_iter([packet, p.to_bytes()].concat()),
        }
    }

    fn frame_length(&self) -> usize {
        self.header_length() + self.payload_length()
    }

    fn header_length(&self) -> usize {
        4 * self.ihl as usize
    }

    fn payload_length(&self) -> usize {
        match &self.payload {
            Ipv4Payload::Unknown => 0,
            Ipv4Payload::IcmpPayload(p) => p.frame_length(),
            Ipv4Payload::TcpPayload(p) => p.frame_length(),
        }
    }
}

impl Ipv4Frame {
    pub fn from_raw(raw_buf: &mut Buffer) -> Self {
        let (version, ihl) = {
            let val = raw_buf.get_slice_1();
            let raw_version = extract_nbit_be_left_from_u8(val[0], 4);
            let ihl = extract_nbit_be_right_from_u8(val[0], 4);
            (IpVersion::decode(raw_version), ihl)
        };
        let (dscp, ecn) = {
            let val = raw_buf.get_slice_1();
            let dscp = extract_nbit_be_left_from_u8(val[0], 6);
            let ecn = extract_nbit_be_right_from_u8(val[0], 2);
            (dscp, ecn)
        };
        let length = extract_u16_from_2u8(raw_buf.get_slice_2());
        let identification = extract_u16_from_2u8(raw_buf.get_slice_2());
        let (flags, flag_offset) = {
            let val = raw_buf.get_slice_2();
            let raw_value = extract_u16_from_2u8([val[0], val[1]]);
            let flags = extract_nbit_be_left_from_u16(raw_value, 3) as u8;
            let offset = extract_nbit_be_right_from_u16(raw_value, 13);
            (IpFlags::decode(flags), offset)
        };
        let ttl = raw_buf.get_slice_1()[0];
        let protocol = IpProtocol::decode(raw_buf.get_slice_1()[0]);
        let cksum = extract_u16_from_2u8(raw_buf.get_slice_2());
        let src_ip = Ipv4Addr::new_without_subnet(raw_buf.get_slice_4());
        let dst_ip = Ipv4Addr::new_without_subnet(raw_buf.get_slice_4());

        let header_size = ihl as usize * 4;

        if let Some(val) = verify_checksum(&raw_buf, header_size) {
            warn!("invalid checksum: {:02x}", val);
        }

        let options = if header_size > IPV4_DEFAULT_HDR_SIZE {
            if let Ok(buf) = raw_buf.get_fixed_sized_bytes(header_size - IPV4_DEFAULT_HDR_SIZE) {
                Some(buf)
            } else {
                None
            }
        } else {
            None
        };

        let payload = match protocol {
            IpProtocol::Icmp => Ipv4Payload::IcmpPayload(IcmpFrame::from_raw(raw_buf)),
            IpProtocol::Tcp => Ipv4Payload::TcpPayload(TcpFrame::from_raw(raw_buf, src_ip, dst_ip)),
            IpProtocol::Unknown => Ipv4Payload::Unknown,
        };
        Ipv4Frame {
            version,
            ihl,
            dscp,
            ecn,
            length,
            identification,
            flags,
            flag_offset,
            ttl,
            protocol,
            cksum,
            src_ip,
            dst_ip,
            options,
            payload,
        }
    }

    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: IpProtocol,
        payload: Ipv4Payload,
    ) -> Self {
        // TODO: Should we call this every time?
        let mut rng = thread_rng();
        let payload_length = match &payload {
            Ipv4Payload::IcmpPayload(p) => p.to_bytes().len(),
            Ipv4Payload::TcpPayload(p) => p.to_bytes().len(),
            Ipv4Payload::Unknown => 0,
        };
        // IHL is fixed value (5), but when it supports option field, then we should be it variable
        let ihl: u8 = 5;
        let ip_hdr_len = ihl * 4;
        let length: u16 = ip_hdr_len as u16 + payload_length as u16;

        let mut frame = Ipv4Frame {
            version: IpVersion::Ipv4,
            // TODO: Ipv4 frame includes 4*5 Bytes. If options are not none, it will be higher than 6.
            ihl,
            dscp: 0,
            ecn: 0,
            length,
            // TODO: This field will be used if IP Fragmentation is allowed.
            // But it is not supported right now. Thus we use random value as it.
            identification: rng.gen(),
            flags: IpFlags::None, // Disallow IP Fragmentation
            flag_offset: 0,       // TODO: IP Fragmentation not supported.
            ttl: 64,              // 64 is default in linux.
            protocol,
            cksum: 0,
            src_ip: src_ip,
            dst_ip: dst_ip,
            options: None, // TODO: Option fields are not supported
            payload,
        };

        frame.cksum = calculate_checksum(frame.to_bytes(), frame.header_length()) as u16;
        frame
    }

    pub fn dest_ip_addr(&self) -> Ipv4Addr {
        self.dst_ip
    }

    pub fn protocol(&self) -> IpProtocol {
        self.protocol
    }

    pub fn icmp_payload(&self) -> Result<&IcmpFrame> {
        match &self.payload {
            Ipv4Payload::IcmpPayload(p) => Ok(p),
            _ => Err(anyhow!("failed to get icmp payload")),
        }
    }

    pub fn tcp_payload(&self) -> Result<&TcpFrame> {
        match &self.payload {
            Ipv4Payload::TcpPayload(p) => Ok(p),
            _ => Err(anyhow!("failed to get tcp payload")),
        }
    }
}
