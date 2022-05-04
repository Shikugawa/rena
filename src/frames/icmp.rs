use crate::buffer::Buffer;
use crate::frames::codec::Codec;
use crate::frames::frame::Frame;
use crate::utils::bit_calculation::extract_u16_from_2u8;
use crate::utils::checksum::{calculate_checksum, verify_checksum};
use bytes::{BufMut, BytesMut};
use log::warn;
use rand::{thread_rng, Rng};
use std::fmt;

static ICMP_DEFAULT_BYTES: usize = 8;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply = 0,
    EchoRequest = 8,
    Unknown = 0xFF,
}

impl Default for IcmpType {
    fn default() -> Self {
        IcmpType::Unknown
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            &IcmpType::EchoReply => write!(f, "Echo Reply"),
            &IcmpType::EchoRequest => write!(f, "Echo Request"),
            &IcmpType::Unknown => write!(f, "Unknown"),
        }
    }
}

impl Codec<IcmpType, u8> for IcmpType {
    fn encode(from: IcmpType) -> u8 {
        from as u8
    }

    fn decode(from: u8) -> IcmpType {
        if from == IcmpType::EchoReply as u8 {
            IcmpType::EchoReply
        } else if from == IcmpType::EchoRequest as u8 {
            IcmpType::EchoRequest
        } else {
            IcmpType::Unknown
        }
    }
}

#[derive(Default, Clone)]
pub struct IcmpFrame {
    icmp_type: IcmpType,
    code: u8,
    cksum: u16,
    identifier: u16,
    seq_num: u16, // rest: u32,
}

impl fmt::Display for IcmpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "            Type: {}
            Code: {}
            Checksum: {}
",
            self.icmp_type, self.code, self.cksum
        )
    }
}

impl Frame for IcmpFrame {
    fn to_bytes(&self) -> BytesMut {
        let mut packet = BytesMut::with_capacity(ICMP_DEFAULT_BYTES);
        packet.put_u8(IcmpType::encode(self.icmp_type));
        packet.put_u8(self.code);
        packet.put_u16(self.cksum);
        packet.put_u16(self.identifier);
        packet.put_u16(self.seq_num);
        packet
    }

    fn frame_length(&self) -> usize {
        self.header_length()
    }

    fn header_length(&self) -> usize {
        ICMP_DEFAULT_BYTES
    }

    fn payload_length(&self) -> usize {
        0
    }
}

impl IcmpFrame {
    pub fn from_raw(raw_buf: &mut Buffer) -> Self {
        let icmp_type = IcmpType::decode(raw_buf.get_slice_1()[0]);
        let code = raw_buf.get_slice_1()[0];
        let cksum = extract_u16_from_2u8(raw_buf.get_slice_2());
        let identifier = extract_u16_from_2u8(raw_buf.get_slice_2());
        let seq_num = extract_u16_from_2u8(raw_buf.get_slice_2());

        if let Some(val) = verify_checksum(raw_buf, ICMP_DEFAULT_BYTES) {
            warn!("invalid checksum: {:02x}", val);
        }

        IcmpFrame {
            icmp_type,
            code,
            cksum,
            identifier,
            seq_num,
        }
    }

    pub fn new(icmp_type: IcmpType, seq_num: u16) -> Self {
        // TODO: Should we call this every time?
        let mut rng = thread_rng();
        let mut frame = IcmpFrame {
            icmp_type,
            // TODO: Since it only supports icmp echo req/res that doesn't have any code, we don't have to impl code.
            code: 0,
            cksum: 0,
            identifier: rng.gen(),
            seq_num,
        };
        frame.cksum = calculate_checksum(frame.to_bytes(), frame.header_length()) as u16;
        frame
    }

    pub fn seq_num(&self) -> u16 {
        self.seq_num()
    }
}
