use std::collections::HashMap;

use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::io::thread_event_handler::ThreadEventHandler;
use once_cell::sync::Lazy;

use super::arp_layer::ArpLayer;
use super::ether_layer::EthernetLayer;
use super::icmp_layer::{self, IcmpLayer};
use super::ip_layer::Ipv4Layer;
use super::tcp_layer::TcpLayer;

struct Layers {
    ethernet: Option<EthernetLayer>,
    arp: Option<ArpLayer>,
    ipv4: Option<Ipv4Layer>,
    tcp: Option<TcpLayer>,
    icmp: Option<IcmpLayer>,
}

impl Layers {
    pub fn new() -> Self {
        Layers {
            ethernet: None,
            arp: None,
            ipv4: None,
            tcp: None,
            icmp: None,
        }
    }

    pub fn set_ethernet(&mut self, ethernet: EthernetLayer) {
        self.ethernet = Some(ethernet);
    }

    pub fn set_arp(&mut self, arp: ArpLayer) {
        self.arp = Some(arp);
    }

    pub fn set_ipv4(&mut self, ipv4: Ipv4Layer) {
        self.ipv4 = Some(ipv4);
    }

    pub fn set_tcp(&mut self, tcp: TcpLayer) {
        self.tcp = Some(tcp);
    }

    pub fn set_icmp(&mut self, icmp: IcmpLayer) {
        self.icmp = Some(icmp);
    }

    pub fn get_ethernet(&mut self) -> &mut EthernetLayer {
        self.ethernet.as_mut().unwrap()
    }

    pub fn get_arp(&mut self) -> &mut ArpLayer {
        self.arp.as_mut().unwrap()
    }

    pub fn get_ipv4(&mut self) -> &mut Ipv4Layer {
        self.ipv4.as_mut().unwrap()
    }

    pub fn get_tcp(&mut self) -> &mut TcpLayer {
        self.tcp.as_mut().unwrap()
    }

    pub fn get_icmp(&mut self) -> &mut IcmpLayer {
        self.icmp.as_mut().unwrap()
    }
}

struct ThreadLocalStorage {
    storage_map: HashMap<u64, Layers>,
}

impl ThreadLocalStorage {
    pub fn new() -> Self {
        ThreadLocalStorage {
            storage_map: HashMap::new(),
        }
    }

    pub fn set_ethernet(&mut self, thread_id: u64, ethernet_layer: EthernetLayer) {
        if !self.storage_map.contains_key(&thread_id) {
            self.storage_map.insert(thread_id, Layers::new());
        }

        self.storage_map
            .get_mut(&thread_id)
            .unwrap()
            .set_ethernet(ethernet_layer);
    }

    pub fn set_arp(&mut self, thread_id: u64, arp_layer: ArpLayer) {
        if !self.storage_map.contains_key(&thread_id) {
            self.storage_map.insert(thread_id, Layers::new());
        }

        self.storage_map
            .get_mut(&thread_id)
            .unwrap()
            .set_arp(arp_layer);
    }

    pub fn set_ipv4(&mut self, thread_id: u64, ipv4_layer: Ipv4Layer) {
        if !self.storage_map.contains_key(&thread_id) {
            self.storage_map.insert(thread_id, Layers::new());
        }

        self.storage_map
            .get_mut(&thread_id)
            .unwrap()
            .set_ipv4(ipv4_layer);
    }

    pub fn set_tcp(&mut self, thread_id: u64, tcp_layer: TcpLayer) {
        if !self.storage_map.contains_key(&thread_id) {
            self.storage_map.insert(thread_id, Layers::new());
        }

        self.storage_map
            .get_mut(&thread_id)
            .unwrap()
            .set_tcp(tcp_layer);
    }

    pub fn set_icmp(&mut self, thread_id: u64, icmp_layer: IcmpLayer) {
        if !self.storage_map.contains_key(&thread_id) {
            self.storage_map.insert(thread_id, Layers::new());
        }

        self.storage_map
            .get_mut(&thread_id)
            .unwrap()
            .set_icmp(icmp_layer);
    }

    pub fn get_ethernet(&mut self, thread_id: u64) -> &mut EthernetLayer {
        if !self.storage_map.contains_key(&thread_id) {
            panic!("invalid thread id {}", thread_id);
        }

        self.storage_map.get_mut(&thread_id).unwrap().get_ethernet()
    }

    pub fn get_arp(&mut self, thread_id: u64) -> &mut ArpLayer {
        if !self.storage_map.contains_key(&thread_id) {
            panic!("invalid thread id {}", thread_id);
        }

        self.storage_map.get_mut(&thread_id).unwrap().get_arp()
    }

    pub fn get_ipv4(&mut self, thread_id: u64) -> &mut Ipv4Layer {
        if !self.storage_map.contains_key(&thread_id) {
            panic!("invalid thread id {}", thread_id);
        }

        self.storage_map.get_mut(&thread_id).unwrap().get_ipv4()
    }

    pub fn get_tcp(&mut self, thread_id: u64) -> &mut TcpLayer {
        if !self.storage_map.contains_key(&thread_id) {
            panic!("invalid thread id {}", thread_id);
        }

        self.storage_map.get_mut(&thread_id).unwrap().get_tcp()
    }

    pub fn get_icmp(&mut self, thread_id: u64) -> &mut IcmpLayer {
        if !self.storage_map.contains_key(&thread_id) {
            panic!("invalid thread id {}", thread_id);
        }

        self.storage_map.get_mut(&thread_id).unwrap().get_icmp()
    }

    pub fn is_thread_layer_exist(&self, thread_id: u64) -> bool {
        self.storage_map.contains_key(&thread_id)
    }
}

static mut THREAD_LOCAL_STORAGE: Lazy<ThreadLocalStorage> = Lazy::new(|| ThreadLocalStorage::new());

#[derive(Clone, Copy)]
pub struct ThreadLocalStorageCopyableWrapper;

impl ThreadLocalStorageCopyableWrapper {
    pub fn ethernet_layer(&self, thread_id: u64) -> &mut EthernetLayer {
        unsafe { THREAD_LOCAL_STORAGE.get_ethernet(thread_id) }
    }

    pub fn arp_layer(&self, thread_id: u64) -> &mut ArpLayer {
        unsafe { THREAD_LOCAL_STORAGE.get_arp(thread_id) }
    }

    pub fn ipv4_layer(&self, thread_id: u64) -> &mut Ipv4Layer {
        unsafe { THREAD_LOCAL_STORAGE.get_ipv4(thread_id) }
    }

    pub fn tcp_layer(&self, thread_id: u64) -> &mut TcpLayer {
        unsafe { THREAD_LOCAL_STORAGE.get_tcp(thread_id) }
    }

    pub fn icmp_layer(&self, thread_id: u64) -> &mut IcmpLayer {
        unsafe { THREAD_LOCAL_STORAGE.get_icmp(thread_id) }
    }
}

pub fn create_tcp_layers(
    thread_id: u64,
    event_handler: ThreadEventHandler,
    sipaddr: Ipv4Addr,
    smacaddr: MacAddr,
) -> ThreadLocalStorageCopyableWrapper {
    if unsafe { THREAD_LOCAL_STORAGE.is_thread_layer_exist(thread_id) } {
        panic!("thread id <{}> has already existed", thread_id);
    }

    let storage = ThreadLocalStorageCopyableWrapper {};

    unsafe {
        THREAD_LOCAL_STORAGE.set_ethernet(
            thread_id,
            EthernetLayer::new(smacaddr, event_handler, storage, thread_id),
        );
        THREAD_LOCAL_STORAGE.set_arp(
            thread_id,
            ArpLayer::new(smacaddr, sipaddr, storage, thread_id),
        );
        THREAD_LOCAL_STORAGE.set_ipv4(thread_id, Ipv4Layer::new(sipaddr, storage, thread_id));
        THREAD_LOCAL_STORAGE.set_tcp(thread_id, TcpLayer::new(storage, sipaddr, thread_id));
    }

    storage
}

pub fn create_icmp_layers(
    thread_id: u64,
    event_handler: ThreadEventHandler,
    sipaddr: Ipv4Addr,
    smacaddr: MacAddr,
) -> ThreadLocalStorageCopyableWrapper {
    if unsafe { THREAD_LOCAL_STORAGE.is_thread_layer_exist(thread_id) } {
        panic!("thread id <{}> has already existed", thread_id);
    }

    let storage = ThreadLocalStorageCopyableWrapper {};

    unsafe {
        THREAD_LOCAL_STORAGE.set_ethernet(
            thread_id,
            EthernetLayer::new(smacaddr, event_handler, storage, thread_id),
        );
        THREAD_LOCAL_STORAGE.set_arp(
            thread_id,
            ArpLayer::new(smacaddr, sipaddr, storage, thread_id),
        );
        THREAD_LOCAL_STORAGE.set_ipv4(thread_id, Ipv4Layer::new(sipaddr, storage, thread_id));
        THREAD_LOCAL_STORAGE.set_icmp(thread_id, IcmpLayer::new(storage, thread_id));
    }

    storage
}
