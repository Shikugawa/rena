use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::arp_table::ArpTable;
use crate::datalink::rawsock::RawSock;
use crate::datalink::tap::TapDevice;
use crate::datalink::traits::DatalinkReaderWriter;
use crate::datalink::writer::write;
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
use once_cell::sync::Lazy;
use rand::{thread_rng, Rng};
use std::cmp::min;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::mem::swap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::{interval, Duration, Instant};

// TODO: thread local
static mut ARP_TABLE: Lazy<ArpTable> = Lazy::new(|| ArpTable::new());

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

pub struct ArpLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    smacaddr: MacAddr,
    sipaddr: Ipv4Addr,
    layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
}

impl<T> ArpLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    pub fn new(
        smacaddr: MacAddr,
        sipaddr: Ipv4Addr,
        layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
    ) -> Self {
        Self {
            smacaddr,
            sipaddr,
            layers_storage,
        }
    }

    pub async fn send(&self, dipaddr: Ipv4Addr) {
        let arp_frame = ArpFrame::new_request(self.smacaddr, self.sipaddr, dipaddr);
    }
}

pub struct EthernetLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    smacaddr: MacAddr,
    layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
    sock: Arc<T>,
}

impl<T> EthernetLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    pub fn new(
        sock: Arc<T>,
        smacaddr: MacAddr,
        layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
    ) -> EthernetLayer<T> {
        EthernetLayer {
            smacaddr,
            layers_storage,
            sock,
        }
    }

    pub async fn send_ip_frame(&self, frame: Ipv4Frame) {
        let dmacaddr = unsafe { ARP_TABLE.lookup(frame.dest_ip_addr()).unwrap() };

        let ether = EthernetFrame::new(
            self.smacaddr,
            dmacaddr,
            EtherType::Ipv4,
            EthernetPayload::Ipv4Payload(frame),
        );
        write(self.sock.clone(), ether.to_bytes(), None).await;
    }

    pub async fn send_arp_frame(&self, frame: ArpFrame) {
        let ether = EthernetFrame::new(
            self.smacaddr,
            MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
            EtherType::Arp,
            EthernetPayload::ArpPayload(frame),
        );
        write(self.sock.clone(), ether.to_bytes(), None).await;
    }
}

pub struct Ipv4Layer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    sipaddr: Ipv4Addr,
    layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
}

impl<T> Ipv4Layer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    pub fn new(
        sipaddr: Ipv4Addr,
        layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
    ) -> Self {
        Ipv4Layer {
            sipaddr,
            layers_storage,
        }
    }

    pub async fn send_tcp_frame(&self, dipaddr: Ipv4Addr, frame: TcpFrame) {
        let ipv4_frame = Ipv4Frame::new(
            self.sipaddr,
            dipaddr,
            IpProtocol::Tcp,
            Ipv4Payload::TcpPayload(frame),
        );
        self.layers_storage
            .ethernet_layer()
            .send_ip_frame(ipv4_frame)
            .await;
    }
}

pub struct TcpLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    sipaddr: Ipv4Addr,
    sessions: HashMap<u16, ActiveSession>,
    io_handler: IoHandler<T>,
    write_tx: mpsc::Sender<(TcpFrame, Ipv4Addr)>,
    read_rx: mpsc::Receiver<TcpFrame>,

    // pending_message_queue is used to hold inflight segments.
    // If retransmission which is triggered by 1) duplicated ack_num, 2) ack timeout
    // is occurred, the number of packet will be enqueued repeatedly here.
    pending_message_queue: VecDeque<(usize, Instant)>,
}

impl<T: DatalinkReaderWriter> TcpLayer<T> {
    pub fn new(sock: T, smacaddr: MacAddr, sipaddr: Ipv4Addr) -> Self {
        // TODO: graceful close of iohandler
        let (io_handler, write_tx, read_rx) = IoHandler::new(sock, smacaddr, sipaddr);
        Self {
            sessions: HashMap::new(),
            io_handler,
            write_tx,
            read_rx,
            sipaddr,
            pending_message_queue: VecDeque::new(),
        }
    }

    pub async fn handshake(&mut self, dipaddr: Ipv4Addr, dport: u16) {
        let mut rand_gen = thread_rng();

        // Same as linux's default range
        // https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables
        let sport: u16 = rand_gen.gen_range(32768..60999);

        let mut new_session = ActiveSession::new(self.sipaddr, dipaddr, sport, dport);
        let stream_id = new_session.stream_id();
        info!("session {} start handshake", stream_id);

        // send SYN
        let syn_frame = new_session.create_next_frame(false, true).unwrap();
        self.send_internal(dipaddr, syn_frame).await;

        // wait ACK
        let frame = self.wait_valid_frame(&mut new_session, None).await;
        if frame.is_err() {
            return;
        }
        new_session.on_recv(&frame.unwrap());

        // send SYN
        let syn_frame = new_session.create_next_frame(false, false).unwrap();
        self.send_internal(dipaddr, syn_frame).await;
    }

    pub async fn close(&mut self, sess: &mut ActiveSession, dipaddr: Ipv4Addr, dport: u16) {
        let stream_id = sess.stream_id();
        info!("session {} start handshake", stream_id);

        // send SYN
        let syn_frame = sess.create_next_frame(true, true).unwrap();
        self.send_internal(dipaddr, syn_frame).await;

        // wait ACK
        let frame = self.wait_valid_frame(sess, None).await;
        if frame.is_err() {
            return;
        }
        sess.on_recv(&frame.unwrap());

        // send SYN
        let syn_frame = sess.create_next_frame(false, false).unwrap();
        self.send_internal(dipaddr, syn_frame).await;
    }

    pub async fn get_session(
        &mut self,
        dipaddr: Ipv4Addr,
        dport: u16,
        payload: BytesMut,
    ) -> Option<&mut ActiveSession> {
        if !self.sessions.contains_key(&dport) {
            return None;
        }
        Some(self.sessions.get_mut(&dport).unwrap())
    }

    pub async fn send2(
        &mut self,
        sess: &mut ActiveSession,
        dipaddr: Ipv4Addr,
        dport: u16,
        payload: BytesMut,
    ) {
        let tcp_frames = self.create_tcp_data_packet(sess, payload);

        let mut next_idx = 0;
        let pending_buf_size = min(sess.can_send_packet_num(), tcp_frames.len());

        // Init data send state
        self.pending_message_queue = VecDeque::with_capacity(pending_buf_size);

        // Initial flight
        while next_idx < pending_buf_size {
            let frame = tcp_frames[next_idx].1.clone();
            self.send_data_internal(next_idx, dipaddr, frame).await;
            next_idx += 1;
        }

        let mut interval = interval(Duration::from_secs(1));

        // Wait ACKs for pending messages. If it succeeded, it executes
        // 1) If it has remaining segment, handler sends it.
        // 2) If ACKs can't be received via timeout, handler execute transmission
        //    for failed SYN message immediately.
        while !self.pending_message_queue.is_empty() {
            tokio::select! {
                instant = interval.tick() => {
                    loop {
                        let (_, deadline) = self.pending_message_queue.front().unwrap();
                        if instant < *deadline {
                            break;
                        }

                        let (idx, _) = self.pending_message_queue.pop_front().unwrap();
                        let frame = tcp_frames[idx].1.clone();

                        self.send_data_internal(idx, dipaddr, frame).await;
                    }
                },
                res = self.read() => {
                    match res {
                        Some(tcp_frame) => {
                            self.pending_message_queue.pop_front().unwrap();
                            if !sess.on_recv(&tcp_frame) {
                                continue;
                            }

                            if next_idx >= tcp_frames.len() {
                                continue;
                            }

                            next_idx += 1;

                            let frame = tcp_frames[next_idx].1.clone();
                            self.send_data_internal(next_idx, dipaddr, frame).await;
                        }
                        None => {}
                    }
                }
            }
        }

        info!("segment write succeded");
        self.pending_message_queue.clear();
    }

    async fn read(&mut self) -> Option<TcpFrame> {
        if let Some(tcp_frame) = self.read_rx.recv().await {
            Some(tcp_frame)
        } else {
            None
        }
    }

    async fn send_internal(&mut self, dipaddr: Ipv4Addr, frame: TcpFrame) {
        self.write_tx.send((frame, dipaddr)).await;
    }

    // TODO: handle timeout if local transmission failed
    async fn send_data_internal(&mut self, idx: usize, dipaddr: Ipv4Addr, frame: TcpFrame) {
        self.write_tx.send((frame, dipaddr)).await;

        // TODO: fix backoff timeout
        let deadline = Instant::now() + Duration::from_secs(3);
        self.pending_message_queue.push_back((idx, deadline));
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

    fn create_tcp_data_packet(
        &self,
        sess: &mut ActiveSession,
        payload: BytesMut,
    ) -> Vec<(u32 /* exepcted ack num */, TcpFrame)> {
        let tcp_frames = sess.create_next_data_frame(payload).unwrap();
        let mut chunked_raw_frames = Vec::new();

        for frame in tcp_frames {
            let tcp_seq_num = frame.seq_num();
            let tcp_payload_len = frame.payload_length();
            chunked_raw_frames.push((tcp_seq_num + tcp_payload_len as u32, frame));
        }

        chunked_raw_frames
    }
}

// TODO: thread local
static mut ETHERNET_LAYER_RAW_SOCK: Lazy<Option<EthernetLayer<RawSock>>> = Lazy::new(|| None);
static mut ARP_LAYER_RAW_SOCK: Lazy<Option<ArpLayer<RawSock>>> = Lazy::new(|| None);
static mut IPV4_LAYER_RAW_SOCK: Lazy<Option<Ipv4Layer<RawSock>>> = Lazy::new(|| None);

static mut ETHERNET_LAYER_TAP: Lazy<Option<EthernetLayer<TapDevice>>> = Lazy::new(|| None);
static mut ARP_LAYER_TAP: Lazy<Option<ArpLayer<TapDevice>>> = Lazy::new(|| None);
static mut IPV4_LAYER_TAP: Lazy<Option<Ipv4Layer<TapDevice>>> = Lazy::new(|| None);

trait IoThreadLayersStorageWrapper<T>
where
    T: DatalinkReaderWriter,
{
    fn ethernet_layer(&self) -> &EthernetLayer<T>;

    fn arp_layer(&self) -> &ArpLayer<T>;

    fn ipv4_layer(&self) -> &Ipv4Layer<T>;
}

pub struct IoThreadLayersStorageWrapperRawSock;

impl IoThreadLayersStorageWrapperRawSock {
    pub fn init(sock: Arc<RawSock>, sipaddr: Ipv4Addr, smacaddr: MacAddr) -> Arc<Self> {
        let storage = Arc::new(Self {});

        unsafe {
            ETHERNET_LAYER_RAW_SOCK.insert(EthernetLayer::new(sock, smacaddr, storage));
            ARP_LAYER_RAW_SOCK.insert(ArpLayer::new(smacaddr, sipaddr, storage));
            IPV4_LAYER_RAW_SOCK.insert(Ipv4Layer::new(sipaddr, storage));
        }

        storage
    }
}

impl IoThreadLayersStorageWrapper<RawSock> for IoThreadLayersStorageWrapperRawSock {
    fn ethernet_layer(&self) -> &EthernetLayer<RawSock> {
        unsafe { &ETHERNET_LAYER_RAW_SOCK.unwrap() }
    }

    fn arp_layer(&self) -> &ArpLayer<RawSock> {
        unsafe { &ARP_LAYER_RAW_SOCK.unwrap() }
    }

    fn ipv4_layer(&self) -> &Ipv4Layer<RawSock> {
        unsafe { &IPV4_LAYER_RAW_SOCK.unwrap() }
    }
}
