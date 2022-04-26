use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::arp_table::ArpTable;
use crate::datalink::traits::DatalinkReaderWriter;
use crate::frames::arp::ArpFrame;
use crate::frames::ethernet::{EtherType, EthernetFrame, EthernetPayload};
use crate::frames::frame::Frame;
use crate::frames::icmp::{IcmpFrame, IcmpType};
use crate::frames::ipv4::{IpProtocol, Ipv4Frame, Ipv4Payload};
use crate::frames::tcp::TcpFrame;
use crate::io_handler::IoHandler;
use crate::tcp::active_session::ActiveSession;
use anyhow::Result;
use bytes::BytesMut;
use log::info;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::mem::swap;
use std::time::Duration;

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

pub struct EthernetLayer {
    smacaddr: MacAddr,
    arp_table: ArpTable,
}

impl EthernetLayer {
    pub fn new(smacaddr: MacAddr) -> Self {
        Self {
            smacaddr,
            arp_table: ArpTable::new(),
        }
    }

    pub fn send(&mut self, frame: Ipv4Frame) -> EthernetFrame {
        let dmacaddr = self.arp_table.lookup(frame.dest_ip_addr()).unwrap();
        EthernetFrame::new(
            self.smacaddr,
            dmacaddr,
            EtherType::Ipv4,
            EthernetPayload::Ipv4Payload(frame),
        )
    }
}

pub struct Ipv4Layer {
    sipaddr: Ipv4Addr,
}

impl Ipv4Layer {
    pub fn new(sipaddr: Ipv4Addr) -> Self {
        Ipv4Layer { sipaddr }
    }

    pub fn send(&mut self, dipaddr: Ipv4Addr, frame: TcpFrame) -> Ipv4Frame {
        Ipv4Frame::new(
            self.sipaddr,
            dipaddr,
            IpProtocol::Tcp,
            Ipv4Payload::TcpPayload(frame),
        )
    }
}

pub struct TcpLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    sipaddr: Ipv4Addr,
    sessions: HashMap<u32, ActiveSession>,
    io_handler: IoHandler<T>,
}

impl<T: DatalinkReaderWriter> TcpLayer<T> {
    pub fn new(sock: T, smacaddr: MacAddr, sipaddr: Ipv4Addr) -> Self {
        // TODO: graceful close of iohandler
        let io_handler = IoHandler::new(sock, smacaddr, sipaddr);
        Self {
            sessions: HashMap::new(),
            io_handler,
            sipaddr,
        }
    }

    async fn handshake(&mut self, dipaddr: Ipv4Addr, dport: u16) {
        let mut rand_gen = thread_rng();

        // Same as linux's default range
        // https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables
        let sport: u16 = rand_gen.gen_range(32768..60999);

        let mut new_session = ActiveSession::new(self.sipaddr, dipaddr, sport, dport);
        let stream_id = new_session.stream_id();
        info!("session {} start handshake", stream_id);

        // send SYN
        let syn_frame = new_session.create_next_frame(true, true).unwrap();
        self.send(dipaddr, syn_frame).await;

        // wait ACK
        let frame = self.wait_valid_frame(&mut new_session, None).await;
        if frame.is_err() {
            return;
        }
        new_session.on_recv(&frame.unwrap());

        // send SYN
        let syn_frame = new_session.create_next_frame(true, false).unwrap();
        self.send(dipaddr, syn_frame).await;
    }

    pub async fn read(&mut self) -> Option<TcpFrame> {
        if let Some(tcp_frame) = self.io_handler.recv().await {
            Some(tcp_frame)
        } else {
            None
        }
    }

    pub async fn send(&mut self, dipaddr: Ipv4Addr, frame: TcpFrame) {
        self.io_handler.send(frame, dipaddr).await;
    }

    // TODO: timeout
    async fn wait_valid_frame(
        &mut self,
        sess: &mut ActiveSession,
        timeout: Option<Duration>,
    ) -> Result<TcpFrame> {
        loop {
            if let Some(tcp_frame) = self.read().await {
                if sess.is_valid_frame(&tcp_frame) {
                    return Ok(tcp_frame);
                }
            } else {
                continue;
            }
        }
    }
}
