use crate::addresses::ipv4::{Ipv4Addr, IPV4_ADDR_LEN};
use crate::addresses::mac::{MacAddr, MACADDR_BYTES};
use crate::buffer::Buffer;
use crate::frames::codec::Codec;
use crate::frames::ethernet::EtherType;
use crate::frames::frame::Frame;
use crate::utils::bit_calculation::{extract_2u8_from_u16, extract_u16_from_2u8, push_bytes};
use bytes::{BufMut, BytesMut};
use std::fmt;

#[repr(u16)]
#[derive(Clone, Copy)]
pub enum HardwareType {
    Ethernet = 0x0001,
    Unknown = 0xFFFF,
}

impl Default for HardwareType {
    fn default() -> Self {
        HardwareType::Unknown
    }
}

impl fmt::Display for HardwareType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &HardwareType::Ethernet => write!(f, "Ethernet"),
            &HardwareType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Codec<HardwareType, [u8; 2]> for HardwareType {
    fn encode(from: HardwareType) -> [u8; 2] {
        extract_2u8_from_u16(from as u16)
    }

    fn decode(from: [u8; 2]) -> HardwareType {
        let hwtype = extract_u16_from_2u8(from);
        if hwtype == HardwareType::Ethernet as u16 {
            HardwareType::Ethernet
        } else {
            HardwareType::Unknown
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ArpOperation {
    Request = 0x0001,
    Response = 0x0002,
    Unknown = 0xFFFF,
}

impl Default for ArpOperation {
    fn default() -> Self {
        ArpOperation::Unknown
    }
}

impl fmt::Display for ArpOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &ArpOperation::Request => write!(f, "ARP Request"),
            &ArpOperation::Response => write!(f, "ARP Response"),
            &ArpOperation::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Codec<ArpOperation, [u8; 2]> for ArpOperation {
    fn encode(from: ArpOperation) -> [u8; 2] {
        extract_2u8_from_u16(from as u16)
    }

    fn decode(from: [u8; 2]) -> ArpOperation {
        let opcode = extract_u16_from_2u8(from);
        if opcode == ArpOperation::Request as u16 {
            ArpOperation::Request
        } else if opcode == ArpOperation::Response as u16 {
            ArpOperation::Response
        } else {
            ArpOperation::Unknown
        }
    }
}

static ARP_HDR_LEN: usize = 28;

#[derive(Default, Clone)]
pub struct ArpFrame {
    hardware_type: HardwareType, // 2 Byte
    proto_type: EtherType,       // 2 Byte
    hwaddr_len: u8,              // 1 Byte
    protoaddr_len: u8,           // 1 Byte
    opcode: ArpOperation,        // 2 Byte
    smac: MacAddr,               // 6 Byte
    sproto_addr: Ipv4Addr,       // 4 Byte
    dmac: MacAddr,               // 6 Byte
    dproto_addr: Ipv4Addr,       // 4 Byte
}

impl fmt::Display for ArpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "        Hardware Type: {}
        Protocol Type: {}
        Hardware Address Length: {}
        Protocol Address Length: {}
        ARP Operaton Code: {}
        Mac Address (src): {}
        IPv4 Address (src): {}
        Mac Address (dst): {}
        IPv4 Address (dst): {}
    ",
            self.hardware_type,
            self.proto_type,
            self.hwaddr_len,
            self.protoaddr_len,
            self.opcode,
            self.smac,
            self.sproto_addr,
            self.dmac,
            self.dproto_addr
        )
    }
}

impl Frame for ArpFrame {
    fn to_bytes(&self) -> BytesMut {
        let mut stream = BytesMut::with_capacity(ARP_HDR_LEN);
        push_bytes(&mut stream, HardwareType::encode(self.hardware_type).iter());
        push_bytes(&mut stream, EtherType::encode(self.proto_type).iter());
        stream.put_u8(self.hwaddr_len);
        stream.put_u8(self.protoaddr_len);
        push_bytes(&mut stream, ArpOperation::encode(self.opcode).iter());
        push_bytes(&mut stream, self.smac.to_bytes().iter());
        push_bytes(&mut stream, self.sproto_addr.to_bytes().iter());
        push_bytes(&mut stream, self.dmac.to_bytes().iter());
        push_bytes(&mut stream, self.dproto_addr.to_bytes().iter());
        stream
    }

    fn frame_length(&self) -> usize {
        self.header_length()
    }

    fn header_length(&self) -> usize {
        ARP_HDR_LEN
    }

    fn payload_length(&self) -> usize {
        0
    }
}

impl ArpFrame {
    pub fn from_raw(raw_buf: &mut Buffer) -> Self {
        let hardware_type = HardwareType::decode(raw_buf.get_slice_2());
        let proto_type = EtherType::decode(raw_buf.get_slice_2());
        let hwaddr_len = raw_buf.get_slice_1()[0];
        let protoaddr_len = raw_buf.get_slice_1()[0];
        let opcode = ArpOperation::decode(raw_buf.get_slice_2());
        let smac = MacAddr::new(raw_buf.get_slice_6());
        let sproto_addr = Ipv4Addr::new_without_subnet(raw_buf.get_slice_4());
        let dmac = MacAddr::new(raw_buf.get_slice_6());
        let dproto_addr = Ipv4Addr::new_without_subnet(raw_buf.get_slice_4());
        ArpFrame {
            hardware_type,
            proto_type,
            hwaddr_len,
            protoaddr_len,
            opcode,
            smac,
            sproto_addr,
            dmac,
            dproto_addr,
        }
    }

    pub fn new_request(smac_addr: MacAddr, sproto_addr: Ipv4Addr, dproto_addr: Ipv4Addr) -> Self {
        ArpFrame {
            hardware_type: HardwareType::Ethernet,
            proto_type: EtherType::Ipv4,
            hwaddr_len: MACADDR_BYTES as u8,
            protoaddr_len: IPV4_ADDR_LEN as u8,
            opcode: ArpOperation::Request,
            smac: smac_addr,
            sproto_addr,
            dmac: MacAddr::from_str("00:00:00:00:00:00").unwrap(),
            dproto_addr,
        }
    }

    pub fn new_reply(
        sproto_addr: Ipv4Addr,
        dproto_addr: Ipv4Addr,
        smac_addr: MacAddr,
        dmac_addr: MacAddr,
    ) -> Self {
        ArpFrame {
            hardware_type: HardwareType::Ethernet,
            proto_type: EtherType::Ipv4,
            hwaddr_len: MACADDR_BYTES as u8,
            protoaddr_len: IPV4_ADDR_LEN as u8,
            opcode: ArpOperation::Response,
            smac: smac_addr,
            sproto_addr,
            dmac: dmac_addr,
            dproto_addr,
        }
    }

    pub fn opcode(&self) -> ArpOperation {
        self.opcode
    }

    pub fn source_ipaddr(&self) -> Ipv4Addr {
        self.sproto_addr
    }

    pub fn source_macaddr(&self) -> MacAddr {
        self.smac
    }
}
