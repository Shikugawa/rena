use crate::addresses::ipv4::Ipv4Addr;
use crate::buffer::Buffer;
use crate::frames::codec::Codec;
use crate::frames::frame::Frame;
use crate::frames::ipv4::IpProtocol;
use crate::utils::bit_calculation::{extract_u16_from_2u8, extract_u32_from_4u8, push_bytes};
use crate::utils::checksum::{calculate_checksum, verify_checksum};
use bytes::{BufMut, BytesMut};
use log::warn;
use std::fmt;

const FLAG_NS: u16 = 0x100;
const FLAG_CWR: u16 = 0x80;
const FLAG_ECE: u16 = 0x40;
const FLAG_URG: u16 = 0x20;
const FLAG_ACK: u16 = 0x10;
const FLAG_PSH: u16 = 0x8;
const FLAG_RST: u16 = 0x4;
const FLAG_SYN: u16 = 0x2;
const FLAG_FIN: u16 = 0x1;

const TCP_DEFAULT_HDR_LEN: usize = 20;
const PSEUDO_IP_HDR_LEN: usize = 12;

#[derive(Default, Clone)]
pub struct TcpFrame {
    sport: u16,
    dport: u16,
    seq_num: u32,
    ack_num: u32,
    offset: u8, // 4 bits
    flags: u16, // (lower) 9 bits
    window_size: u16,
    cksum: u16,
    urg_ptr: u16,
    options: Option<BytesMut>, // if offset > 5
    payload: BytesMut,
    // For building pseudo IP header
    sipaddr: Ipv4Addr,
    dipaddr: Ipv4Addr,
}

impl fmt::Display for TcpFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flags = String::default();
        if self.is_ack() {
            flags += "ACK,";
        }
        if self.is_cwr() {
            flags += "CWR,";
        }
        if self.is_ece() {
            flags += "ECE,";
        }
        if self.is_fin() {
            flags += "FIN,";
        }
        if self.is_ns() {
            flags += "NS,";
        }
        if self.is_psh() {
            flags += "PSH,";
        }
        if self.is_rst() {
            flags += "RST,";
        }
        if self.is_syn() {
            flags += "SYN,";
        }
        if self.is_urg() {
            flags += "URG,";
        }
        if flags.len() != 0 {
            flags = flags.strip_suffix(",").unwrap().to_string();
        } else {
            flags = "N/A".to_string();
        }
        write!(
            f,
            "            source port: {}
            dst port: {}
            seq number: {}
            ack number: {}
            offset: {}
            flags: {}
            window_size: {}
            checksum: {}
            urg_ptr: {}
",
            self.sport,
            self.dport,
            self.seq_num,
            self.ack_num,
            self.offset,
            flags,
            self.window_size,
            self.cksum,
            self.urg_ptr
        )
    }
}

impl Frame for TcpFrame {
    fn to_bytes(&self) -> BytesMut {
        let mut packet = BytesMut::with_capacity((self.offset * 4) as usize);
        packet.put_u16(self.sport);
        packet.put_u16(self.dport);
        packet.put_u32(self.seq_num);
        packet.put_u32(self.ack_num);
        let mut offset_and_flags: u16 = 0x0000;
        offset_and_flags = offset_and_flags | ((self.offset as u16) << 12);
        offset_and_flags = offset_and_flags | self.flags;
        packet.put_u16(offset_and_flags);
        packet.put_u16(self.window_size);
        packet.put_u16(self.cksum);
        packet.put_u16(self.urg_ptr);
        BytesMut::from_iter([packet, self.payload.clone()].concat())
    }

    fn frame_length(&self) -> usize {
        self.header_length() + self.payload_length()
    }

    fn header_length(&self) -> usize {
        (self.offset * 4) as usize
    }

    fn payload_length(&self) -> usize {
        self.payload.len()
    }
}

impl TcpFrame {
    pub fn from_raw(raw_buf: &mut Buffer, sipaddr: Ipv4Addr, dipaddr: Ipv4Addr) -> Self {
        let sport = extract_u16_from_2u8(raw_buf.get_slice_2());
        let dport = extract_u16_from_2u8(raw_buf.get_slice_2());
        let seq_num = extract_u32_from_4u8(raw_buf.get_slice_4());
        let ack_num = extract_u32_from_4u8(raw_buf.get_slice_4());
        let (offset, flags) = {
            let tmp = extract_u16_from_2u8(raw_buf.get_slice_2());
            (((tmp & 0xF000) >> 12) as u8, tmp & 0xF1FF)
        };
        let window_size = extract_u16_from_2u8(raw_buf.get_slice_2());
        let cksum = extract_u16_from_2u8(raw_buf.get_slice_2());
        let urg_ptr = extract_u16_from_2u8(raw_buf.get_slice_2());

        let header_length = offset * 4;

        let options = if header_length > TCP_DEFAULT_HDR_LEN as u8 {
            if let Ok(buf) =
                raw_buf.get_fixed_sized_bytes(header_length as usize - TCP_DEFAULT_HDR_LEN)
            {
                Some(buf)
            } else {
                None
            }
        } else {
            None
        };

        if let Some(val) = verify_checksum(&raw_buf, header_length as usize) {
            warn!("invalid checksum: {:02x}", val);
        }

        let payload = raw_buf.get_remain_bytes();

        TcpFrame {
            sport,
            dport,
            seq_num,
            ack_num,
            offset,
            flags,
            window_size,
            cksum,
            urg_ptr,
            options,
            payload,
            sipaddr,
            dipaddr,
        }
    }

    pub fn new(
        sipaddr: Ipv4Addr,
        dipaddr: Ipv4Addr,
        sport: u16,
        dport: u16,
        seq_num: u32,
        ack_num: u32,
        window_size: u16,
        payload: BytesMut,
    ) -> Self {
        let mut frame = TcpFrame {
            sport,
            dport,
            seq_num,
            ack_num,
            // We should fix this after we supported TCP options header.
            offset: 5,
            flags: 0x0000,
            window_size,
            cksum: 0,
            urg_ptr: 0,
            options: None,
            payload,
            sipaddr: sipaddr,
            dipaddr: dipaddr,
        };

        frame.cksum = frame.calc_checksum();
        frame
    }

    pub fn dport(&self) -> u16 {
        self.dport
    }

    pub fn window_size(&self) -> u16 {
        self.window_size
    }

    pub fn seq_num(&self) -> u32 {
        self.seq_num
    }

    pub fn ack_num(&self) -> u32 {
        self.ack_num
    }

    pub fn is_ns(&self) -> bool {
        (self.flags & FLAG_NS) == FLAG_NS
    }

    pub fn is_cwr(&self) -> bool {
        (self.flags & FLAG_CWR) == FLAG_CWR
    }

    pub fn is_ece(&self) -> bool {
        (self.flags & FLAG_ECE) == FLAG_ECE
    }

    pub fn is_fin(&self) -> bool {
        (self.flags & FLAG_FIN) == FLAG_FIN
    }

    pub fn is_ack(&self) -> bool {
        (self.flags & FLAG_ACK) == FLAG_ACK
    }

    pub fn is_psh(&self) -> bool {
        (self.flags & FLAG_PSH) == FLAG_PSH
    }

    pub fn is_rst(&self) -> bool {
        (self.flags & FLAG_RST) == FLAG_RST
    }

    pub fn is_syn(&self) -> bool {
        (self.flags & FLAG_SYN) == FLAG_SYN
    }

    pub fn is_urg(&self) -> bool {
        (self.flags & FLAG_URG) == FLAG_URG
    }

    pub fn set_ns(&mut self) {
        self.flags = self.flags | FLAG_NS;
        self.cksum = self.calc_checksum();
    }

    pub fn set_cwr(&mut self) {
        self.flags = self.flags | FLAG_CWR;
        self.cksum = self.calc_checksum();
    }

    pub fn set_ece(&mut self) {
        self.flags = self.flags | FLAG_ECE;
        self.cksum = self.calc_checksum();
    }

    pub fn set_fin(&mut self) {
        self.flags = self.flags | FLAG_FIN;
        self.cksum = self.calc_checksum();
    }

    pub fn set_ack(&mut self) {
        self.flags = self.flags | FLAG_ACK;
        self.cksum = self.calc_checksum();
    }

    pub fn set_psh(&mut self) {
        self.flags = self.flags | FLAG_PSH;
        self.cksum = self.calc_checksum();
    }

    pub fn set_rst(&mut self) {
        self.flags = self.flags | FLAG_RST;
        self.cksum = self.calc_checksum();
    }

    pub fn set_syn(&mut self) {
        self.flags = self.flags | FLAG_SYN;
        self.cksum = self.calc_checksum();
    }

    pub fn set_urg(&mut self) {
        self.flags = self.flags | FLAG_URG;
        self.cksum = self.calc_checksum();
    }

    fn calc_checksum(&mut self) -> u16 {
        self.cksum = 0;
        let mut ip = self.pseudo_ip_header(self.sipaddr, self.dipaddr);
        let tcp = self.to_bytes();
        ip.extend(tcp.iter());
        calculate_checksum(ip, PSEUDO_IP_HDR_LEN + self.frame_length()) as u16
    }

    fn pseudo_ip_header(&self, sipaddr: Ipv4Addr, dipaddr: Ipv4Addr) -> BytesMut {
        let mut pseudo_ip_frame = BytesMut::with_capacity(PSEUDO_IP_HDR_LEN);
        push_bytes(&mut pseudo_ip_frame, sipaddr.to_bytes().iter());
        push_bytes(&mut pseudo_ip_frame, dipaddr.to_bytes().iter());
        pseudo_ip_frame.put_u8(0);
        pseudo_ip_frame.put_u8(IpProtocol::encode(IpProtocol::Tcp));
        pseudo_ip_frame.put_u16(self.frame_length() as u16);
        pseudo_ip_frame
    }
}
