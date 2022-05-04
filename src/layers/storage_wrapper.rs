use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::rawsock::RawSock;
use crate::datalink::tap::TapDevice;
use crate::datalink::traits::DatalinkReaderWriter;
use crate::layers::iothread_layers::{ArpLayer, EthernetLayer, Ipv4Layer};
use once_cell::sync::Lazy;
use std::sync::Arc;

// TODO: thread local
static mut ETHERNET_LAYER_RAW_SOCK: Lazy<Option<EthernetLayer<RawSock>>> = Lazy::new(|| None);
static mut ARP_LAYER_RAW_SOCK: Lazy<Option<ArpLayer<RawSock>>> = Lazy::new(|| None);
static mut IPV4_LAYER_RAW_SOCK: Lazy<Option<Ipv4Layer<RawSock>>> = Lazy::new(|| None);

static mut ETHERNET_LAYER_TAP: Lazy<Option<EthernetLayer<TapDevice>>> = Lazy::new(|| None);
static mut ARP_LAYER_TAP: Lazy<Option<ArpLayer<TapDevice>>> = Lazy::new(|| None);
static mut IPV4_LAYER_TAP: Lazy<Option<Ipv4Layer<TapDevice>>> = Lazy::new(|| None);

pub trait IoThreadLayersStorageWrapper<T>
where
    T: DatalinkReaderWriter,
{
    fn ethernet_layer(&self) -> &EthernetLayer<T>;

    fn arp_layer(&self) -> &ArpLayer<T>;

    fn ipv4_layer(&self) -> &Ipv4Layer<T>;
}

#[derive(Clone, Copy)]
pub struct IoThreadLayersStorageWrapperRawSock;

impl IoThreadLayersStorageWrapper<RawSock> for IoThreadLayersStorageWrapperRawSock {
    fn ethernet_layer(&self) -> &EthernetLayer<RawSock> {
        unsafe { &ETHERNET_LAYER_RAW_SOCK.as_ref().unwrap() }
    }

    fn arp_layer(&self) -> &ArpLayer<RawSock> {
        unsafe { &ARP_LAYER_RAW_SOCK.as_ref().unwrap() }
    }

    fn ipv4_layer(&self) -> &Ipv4Layer<RawSock> {
        unsafe { &IPV4_LAYER_RAW_SOCK.as_ref().unwrap() }
    }
}

impl IoThreadLayersStorageWrapperRawSock {
    pub fn init(sock: Arc<RawSock>, sipaddr: Ipv4Addr, smacaddr: MacAddr) -> Self {
        let storage = Self {};

        unsafe {
            ETHERNET_LAYER_RAW_SOCK.insert(EthernetLayer::new(sock, smacaddr, storage));
            ARP_LAYER_RAW_SOCK.insert(ArpLayer::new(smacaddr, sipaddr, storage));
            IPV4_LAYER_RAW_SOCK.insert(Ipv4Layer::new(sipaddr, storage));
        }

        storage
    }
}
