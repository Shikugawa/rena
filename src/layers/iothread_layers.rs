use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::traits::DatalinkReaderWriter;
use crate::datalink::writer::write;
use crate::frames::arp::ArpFrame;
use crate::frames::ethernet::{EtherType, EthernetFrame, EthernetPayload};
use crate::frames::frame::Frame;
use crate::frames::icmp::IcmpFrame;
use crate::frames::ipv4::{IpProtocol, Ipv4Frame, Ipv4Payload};
use crate::frames::tcp::TcpFrame;
use crate::layers::shared::arp_table::ArpTable;
use crate::layers::storage_wrapper::{
    IoThreadLayersStorageWrapper, IoThreadLayersStorageWrapperRawSock,
};
use once_cell::sync::Lazy;
use std::marker::PhantomData;
use std::sync::Arc;

// TODO: thread local
static mut ARP_TABLE: Lazy<ArpTable> = Lazy::new(|| ArpTable::new());

pub struct ArpLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    smacaddr: MacAddr,
    sipaddr: Ipv4Addr,
    layers_storage: IoThreadLayersStorageWrapperRawSock,
    _phantom: PhantomData<T>,
}

impl<T> ArpLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    pub fn new(
        smacaddr: MacAddr,
        sipaddr: Ipv4Addr,
        layers_storage: IoThreadLayersStorageWrapperRawSock,
    ) -> Self {
        Self {
            smacaddr,
            sipaddr,
            layers_storage,
            _phantom: PhantomData,
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
    layers_storage: IoThreadLayersStorageWrapperRawSock,
    sock: Arc<T>,
}

impl<T> EthernetLayer<T>
where
    T: DatalinkReaderWriter + 'static,
{
    pub fn new(
        sock: Arc<T>,
        smacaddr: MacAddr,
        layers_storage: IoThreadLayersStorageWrapperRawSock,
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

pub struct Ipv4Layer<T> {
    sipaddr: Ipv4Addr,
    layers_storage: IoThreadLayersStorageWrapperRawSock,
    _phantom: PhantomData<T>,
}

impl<T> Ipv4Layer<T> {
    pub fn new(sipaddr: Ipv4Addr, layers_storage: IoThreadLayersStorageWrapperRawSock) -> Self {
        Ipv4Layer {
            sipaddr,
            layers_storage,
            _phantom: PhantomData,
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

    pub async fn send_icmp_frame(&self, dipaddr: Ipv4Addr, frame: IcmpFrame) {
        let ipv4_frame = Ipv4Frame::new(
            self.sipaddr,
            dipaddr,
            IpProtocol::Icmp,
            Ipv4Payload::IcmpPayload(frame),
        );
        self.layers_storage
            .ethernet_layer()
            .send_ip_frame(ipv4_frame)
            .await;
    }
}
