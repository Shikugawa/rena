use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::event::event_loop::ThreadEventHandler;
use once_cell::sync::Lazy;

use super::arp_layer::ArpLayer;
use super::ether_layer::EthernetLayer;
use super::ip_layer::Ipv4Layer;

// TODO: thread local
static mut ETHERNET_LAYER: Lazy<Option<EthernetLayer>> = Lazy::new(|| None);
static mut ARP_LAYER: Lazy<Option<ArpLayer>> = Lazy::new(|| None);
static mut IPV4_LAYER: Lazy<Option<Ipv4Layer>> = Lazy::new(|| None);

#[derive(Clone, Copy)]
pub struct IoThreadLayersStorageWrapper;

impl IoThreadLayersStorageWrapper {
    pub fn init(event_handler: ThreadEventHandler, sipaddr: Ipv4Addr, smacaddr: MacAddr) -> Self {
        let storage = Self {};

        unsafe {
            ETHERNET_LAYER.insert(EthernetLayer::new(smacaddr, event_handler, storage));
            ARP_LAYER.insert(ArpLayer::new(smacaddr, sipaddr, storage));
            IPV4_LAYER.insert(Ipv4Layer::new(sipaddr, storage));
        }

        storage
    }

    pub fn ethernet_layer(&self) -> &mut EthernetLayer {
        unsafe { ETHERNET_LAYER.as_mut().unwrap() }
    }

    pub fn arp_layer(&self) -> &mut ArpLayer {
        unsafe { ARP_LAYER.as_mut().unwrap() }
    }

    pub fn ipv4_layer(&self) -> &mut Ipv4Layer {
        unsafe { IPV4_LAYER.as_mut().unwrap() }
    }
}
