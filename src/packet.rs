use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::frames::arp::ArpFrame;
use crate::frames::ethernet::{EtherType, EthernetFrame, EthernetPayload};
use crate::frames::frame::Frame;
use crate::frames::icmp::{IcmpFrame, IcmpType};
use crate::frames::ipv4::{IpProtocol, Ipv4Frame, Ipv4Payload};
use crate::frames::tcp::TcpFrame;
use bytes::BytesMut;
use std::mem::swap;

enum ArpPacketType {
    ArpRequest(ArpFrame),
    ArpResponse(ArpFrame),
    None,
}

impl Default for ArpPacketType {
    fn default() -> Self {
        ArpPacketType::None
    }
}

#[derive(Default)]
pub struct ArpPacket {
    ether: Option<EthernetFrame>,
    packet: ArpPacketType,
}

impl ArpPacket {
    pub fn set_ether(mut self, saddr: MacAddr, daddr: MacAddr) -> Self {
        let mut payload = ArpFrame::default();
        swap(
            match self.packet {
                ArpPacketType::ArpRequest(ref mut payload2)
                | ArpPacketType::ArpResponse(ref mut payload2) => payload2,
                ArpPacketType::None => panic!("arp payload must be set"),
            },
            &mut payload,
        );
        self.ether = Some(EthernetFrame::new(
            saddr,
            daddr,
            EtherType::Arp,
            EthernetPayload::ArpPayload(payload),
        ));
        self
    }

    pub fn set_arp_request(
        mut self,
        smac_addr: MacAddr,
        sipaddr: Ipv4Addr,
        dipaddr: Ipv4Addr,
    ) -> Self {
        self.packet = ArpPacketType::ArpRequest(ArpFrame::new_request(smac_addr, sipaddr, dipaddr));
        self
    }

    pub fn set_arp_reply(
        mut self,
        smac_addr: MacAddr,
        dmac_addr: MacAddr,
        sipaddr: Ipv4Addr,
        dipaddr: Ipv4Addr,
    ) -> Self {
        self.packet =
            ArpPacketType::ArpResponse(ArpFrame::new_reply(sipaddr, dipaddr, smac_addr, dmac_addr));
        self
    }

    pub fn build(self) -> BytesMut {
        self.ether.unwrap().to_bytes()
    }
}

enum IcmpPacketType {
    IcmpEchoRequest(IcmpFrame),
    IcmpEchoReply(IcmpFrame),
    None,
}

impl Default for IcmpPacketType {
    fn default() -> Self {
        IcmpPacketType::None
    }
}

#[derive(Default)]
pub struct IcmpPacket {
    ether: Option<EthernetFrame>,
    ipv4_packet: Option<Ipv4Frame>,
    icmp_packet: IcmpPacketType,
}

impl IcmpPacket {
    pub fn set_ether(mut self, saddr: MacAddr, daddr: MacAddr) -> Self {
        let mut payload = Ipv4Frame::default();
        swap(self.ipv4_packet.as_mut().unwrap(), &mut payload);
        self.ether = Some(EthernetFrame::new(
            saddr,
            daddr,
            EtherType::Ipv4,
            EthernetPayload::Ipv4Payload(payload),
        ));
        self
    }

    pub fn set_ipv4(mut self, sipaddr: Ipv4Addr, dipaddr: Ipv4Addr) -> Self {
        let mut payload = IcmpFrame::default();
        swap(
            match self.icmp_packet {
                IcmpPacketType::IcmpEchoRequest(ref mut payload2)
                | IcmpPacketType::IcmpEchoReply(ref mut payload2) => payload2,
                IcmpPacketType::None => panic!("arp payload must be set"),
            },
            &mut payload,
        );
        self.ipv4_packet = Some(Ipv4Frame::new(
            sipaddr,
            dipaddr,
            IpProtocol::Icmp,
            Ipv4Payload::IcmpPayload(payload),
        ));
        self
    }

    pub fn set_icmp_echo_request(mut self, seq_num: u16) -> Self {
        let icmp = IcmpFrame::new(IcmpType::EchoRequest, seq_num);
        self.icmp_packet = IcmpPacketType::IcmpEchoRequest(icmp);
        self
    }

    pub fn set_icmp_echo_reply(mut self, seq_num: u16) -> Self {
        let icmp = IcmpFrame::new(IcmpType::EchoReply, seq_num);
        self.icmp_packet = IcmpPacketType::IcmpEchoReply(icmp);
        self
    }

    pub fn build(self) -> BytesMut {
        self.ether.unwrap().to_bytes()
    }
}

#[derive(Default)]
pub struct TcpPacket {
    ether: Option<EthernetFrame>,
    ipv4_packet: Option<Ipv4Frame>,
    tcp_packet: Option<TcpFrame>,
}

impl TcpPacket {
    pub fn set_ether(mut self, saddr: MacAddr, daddr: MacAddr) -> Self {
        let mut payload = Ipv4Frame::default();
        swap(self.ipv4_packet.as_mut().unwrap(), &mut payload);
        self.ether = Some(EthernetFrame::new(
            saddr,
            daddr,
            EtherType::Ipv4,
            EthernetPayload::Ipv4Payload(payload),
        ));
        self
    }

    pub fn set_ipv4(mut self, sipaddr: Ipv4Addr, dipaddr: Ipv4Addr) -> Self {
        let mut payload = TcpFrame::default();
        swap(self.tcp_packet.as_mut().unwrap(), &mut payload);
        self.ipv4_packet = Some(Ipv4Frame::new(
            sipaddr,
            dipaddr,
            IpProtocol::Tcp,
            Ipv4Payload::TcpPayload(payload),
        ));
        self
    }

    pub fn set_tcp(mut self, frame: TcpFrame) -> Self {
        self.tcp_packet = Some(frame);
        self
    }

    pub fn build(self) -> BytesMut {
        self.ether.unwrap().to_bytes()
    }
}
