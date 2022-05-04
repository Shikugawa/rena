// use crate::addresses::ipv4::Ipv4Addr;
// use crate::addresses::mac::MacAddr;
// use crate::arp_table::ArpTable;
// use crate::datalink::rawsock::RawSock;
// use crate::datalink::tap::TapDevice;
// use crate::datalink::traits::DatalinkReaderWriter;
// use crate::datalink::writer::write;
// use crate::frames::arp::ArpFrame;
// use crate::frames::ethernet::{EtherType, EthernetFrame, EthernetPayload};
// use crate::frames::frame::Frame;
// use crate::frames::icmp::{IcmpFrame, IcmpType};
// use crate::frames::ipv4::{IpProtocol, Ipv4Frame, Ipv4Payload};
// use crate::frames::tcp::TcpFrame;
// use crate::io_handler::IoHandler;
// use crate::tcp::active_session::ActiveSession;
// use anyhow::Result;
// use bytes::BytesMut;
// use log::info;
// use once_cell::sync::Lazy;
// use rand::{thread_rng, Rng};
// use std::cmp::min;
// use std::collections::HashMap;
// use std::collections::VecDeque;
// use std::mem::swap;
// use std::sync::{Arc, Mutex};
// use tokio::sync::mpsc;
// use tokio::time::{interval, Duration, Instant};

// // TODO: thread local
// static mut ARP_TABLE: Lazy<ArpTable> = Lazy::new(|| ArpTable::new());

// enum ArpPacketType {
//     ArpRequest(ArpFrame),
//     ArpResponse(ArpFrame),
//     None,
// }

// impl Default for ArpPacketType {
//     fn default() -> Self {
//         ArpPacketType::None
//     }
// }

// #[derive(Default)]
// pub struct ArpPacket {
//     ether: Option<EthernetFrame>,
//     packet: ArpPacketType,
// }

// impl ArpPacket {
//     pub fn set_ether(mut self, saddr: MacAddr, daddr: MacAddr) -> Self {
//         let mut payload = ArpFrame::default();
//         swap(
//             match self.packet {
//                 ArpPacketType::ArpRequest(ref mut payload2)
//                 | ArpPacketType::ArpResponse(ref mut payload2) => payload2,
//                 ArpPacketType::None => panic!("arp payload must be set"),
//             },
//             &mut payload,
//         );
//         self.ether = Some(EthernetFrame::new(
//             saddr,
//             daddr,
//             EtherType::Arp,
//             EthernetPayload::ArpPayload(payload),
//         ));
//         self
//     }

//     pub fn set_arp_request(
//         mut self,
//         smac_addr: MacAddr,
//         sipaddr: Ipv4Addr,
//         dipaddr: Ipv4Addr,
//     ) -> Self {
//         self.packet = ArpPacketType::ArpRequest(ArpFrame::new_request(smac_addr, sipaddr, dipaddr));
//         self
//     }

//     pub fn set_arp_reply(
//         mut self,
//         smac_addr: MacAddr,
//         dmac_addr: MacAddr,
//         sipaddr: Ipv4Addr,
//         dipaddr: Ipv4Addr,
//     ) -> Self {
//         self.packet =
//             ArpPacketType::ArpResponse(ArpFrame::new_reply(sipaddr, dipaddr, smac_addr, dmac_addr));
//         self
//     }

//     pub fn build(self) -> BytesMut {
//         self.ether.unwrap().to_bytes()
//     }
// }

// enum IcmpPacketType {
//     IcmpEchoRequest(IcmpFrame),
//     IcmpEchoReply(IcmpFrame),
//     None,
// }

// impl Default for IcmpPacketType {
//     fn default() -> Self {
//         IcmpPacketType::None
//     }
// }

// #[derive(Default)]
// pub struct IcmpPacket {
//     ether: Option<EthernetFrame>,
//     ipv4_packet: Option<Ipv4Frame>,
//     icmp_packet: IcmpPacketType,
// }

// impl IcmpPacket {
//     pub fn set_ether(mut self, saddr: MacAddr, daddr: MacAddr) -> Self {
//         let mut payload = Ipv4Frame::default();
//         swap(self.ipv4_packet.as_mut().unwrap(), &mut payload);
//         self.ether = Some(EthernetFrame::new(
//             saddr,
//             daddr,
//             EtherType::Ipv4,
//             EthernetPayload::Ipv4Payload(payload),
//         ));
//         self
//     }

//     pub fn set_ipv4(mut self, sipaddr: Ipv4Addr, dipaddr: Ipv4Addr) -> Self {
//         let mut payload = IcmpFrame::default();
//         swap(
//             match self.icmp_packet {
//                 IcmpPacketType::IcmpEchoRequest(ref mut payload2)
//                 | IcmpPacketType::IcmpEchoReply(ref mut payload2) => payload2,
//                 IcmpPacketType::None => panic!("arp payload must be set"),
//             },
//             &mut payload,
//         );
//         self.ipv4_packet = Some(Ipv4Frame::new(
//             sipaddr,
//             dipaddr,
//             IpProtocol::Icmp,
//             Ipv4Payload::IcmpPayload(payload),
//         ));
//         self
//     }

//     pub fn set_icmp_echo_request(mut self, seq_num: u16) -> Self {
//         let icmp = IcmpFrame::new(IcmpType::EchoRequest, seq_num);
//         self.icmp_packet = IcmpPacketType::IcmpEchoRequest(icmp);
//         self
//     }

//     pub fn set_icmp_echo_reply(mut self, seq_num: u16) -> Self {
//         let icmp = IcmpFrame::new(IcmpType::EchoReply, seq_num);
//         self.icmp_packet = IcmpPacketType::IcmpEchoReply(icmp);
//         self
//     }

//     pub fn build(self) -> BytesMut {
//         self.ether.unwrap().to_bytes()
//     }
// }

// pub struct ArpLayer<T>
// where
//     T: DatalinkReaderWriter + 'static,
// {
//     smacaddr: MacAddr,
//     sipaddr: Ipv4Addr,
//     layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
// }

// impl<T> ArpLayer<T>
// where
//     T: DatalinkReaderWriter + 'static,
// {
//     pub fn new(
//         smacaddr: MacAddr,
//         sipaddr: Ipv4Addr,
//         layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
//     ) -> Self {
//         Self {
//             smacaddr,
//             sipaddr,
//             layers_storage,
//         }
//     }

//     pub async fn send(&self, dipaddr: Ipv4Addr) {
//         let arp_frame = ArpFrame::new_request(self.smacaddr, self.sipaddr, dipaddr);
//     }
// }

// pub struct EthernetLayer<T>
// where
//     T: DatalinkReaderWriter + 'static,
// {
//     smacaddr: MacAddr,
//     layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
//     sock: Arc<T>,
// }

// impl<T> EthernetLayer<T>
// where
//     T: DatalinkReaderWriter + 'static,
// {
//     pub fn new(
//         sock: Arc<T>,
//         smacaddr: MacAddr,
//         layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
//     ) -> EthernetLayer<T> {
//         EthernetLayer {
//             smacaddr,
//             layers_storage,
//             sock,
//         }
//     }

//     pub async fn send_ip_frame(&self, frame: Ipv4Frame) {
//         let dmacaddr = unsafe { ARP_TABLE.lookup(frame.dest_ip_addr()).unwrap() };

//         let ether = EthernetFrame::new(
//             self.smacaddr,
//             dmacaddr,
//             EtherType::Ipv4,
//             EthernetPayload::Ipv4Payload(frame),
//         );
//         write(self.sock.clone(), ether.to_bytes(), None).await;
//     }

//     pub async fn send_arp_frame(&self, frame: ArpFrame) {
//         let ether = EthernetFrame::new(
//             self.smacaddr,
//             MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
//             EtherType::Arp,
//             EthernetPayload::ArpPayload(frame),
//         );
//         write(self.sock.clone(), ether.to_bytes(), None).await;
//     }
// }

// pub struct Ipv4Layer<T>
// where
//     T: DatalinkReaderWriter + 'static,
// {
//     sipaddr: Ipv4Addr,
//     layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
// }

// impl<T> Ipv4Layer<T>
// where
//     T: DatalinkReaderWriter + 'static,
// {
//     pub fn new(
//         sipaddr: Ipv4Addr,
//         layers_storage: Arc<dyn IoThreadLayersStorageWrapper<T>>,
//     ) -> Self {
//         Ipv4Layer {
//             sipaddr,
//             layers_storage,
//         }
//     }

//     pub async fn send_tcp_frame(&self, dipaddr: Ipv4Addr, frame: TcpFrame) {
//         let ipv4_frame = Ipv4Frame::new(
//             self.sipaddr,
//             dipaddr,
//             IpProtocol::Tcp,
//             Ipv4Payload::TcpPayload(frame),
//         );
//         self.layers_storage
//             .ethernet_layer()
//             .send_ip_frame(ipv4_frame)
//             .await;
//     }
// }

// // TODO: thread local
// static mut ETHERNET_LAYER_RAW_SOCK: Lazy<Option<EthernetLayer<RawSock>>> = Lazy::new(|| None);
// static mut ARP_LAYER_RAW_SOCK: Lazy<Option<ArpLayer<RawSock>>> = Lazy::new(|| None);
// static mut IPV4_LAYER_RAW_SOCK: Lazy<Option<Ipv4Layer<RawSock>>> = Lazy::new(|| None);

// static mut ETHERNET_LAYER_TAP: Lazy<Option<EthernetLayer<TapDevice>>> = Lazy::new(|| None);
// static mut ARP_LAYER_TAP: Lazy<Option<ArpLayer<TapDevice>>> = Lazy::new(|| None);
// static mut IPV4_LAYER_TAP: Lazy<Option<Ipv4Layer<TapDevice>>> = Lazy::new(|| None);

// pub trait IoThreadLayersStorageWrapper<T>
// where
//     T: DatalinkReaderWriter,
// {
//     fn ethernet_layer(&self) -> &EthernetLayer<T>;

//     fn arp_layer(&self) -> &ArpLayer<T>;

//     fn ipv4_layer(&self) -> &Ipv4Layer<T>;
// }

// pub struct IoThreadLayersStorageWrapperRawSock;

// impl IoThreadLayersStorageWrapperRawSock {
//     pub fn init(sock: Arc<RawSock>, sipaddr: Ipv4Addr, smacaddr: MacAddr) -> Arc<Self> {
//         let storage = Arc::new(Self {});

//         unsafe {
//             ETHERNET_LAYER_RAW_SOCK.insert(EthernetLayer::new(sock, smacaddr, storage.clone()));
//             ARP_LAYER_RAW_SOCK.insert(ArpLayer::new(smacaddr, sipaddr, storage.clone()));
//             IPV4_LAYER_RAW_SOCK.insert(Ipv4Layer::new(sipaddr, storage.clone()));
//         }

//         storage
//     }
// }

// impl IoThreadLayersStorageWrapper<RawSock> for IoThreadLayersStorageWrapperRawSock {
//     fn ethernet_layer(&self) -> &EthernetLayer<RawSock> {
//         unsafe { &ETHERNET_LAYER_RAW_SOCK.as_ref().unwrap() }
//     }

//     fn arp_layer(&self) -> &ArpLayer<RawSock> {
//         unsafe { &ARP_LAYER_RAW_SOCK.as_ref().unwrap() }
//     }

//     fn ipv4_layer(&self) -> &Ipv4Layer<RawSock> {
//         unsafe { &IPV4_LAYER_RAW_SOCK.as_ref().unwrap() }
//     }
// }
