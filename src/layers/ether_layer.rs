use super::storage_wrapper::IoThreadLayersStorageWrapper;
use crate::addresses::mac::MacAddr;
use crate::event::event_loop::ThreadEventHandler;
use crate::frames::arp::ArpFrame;
use crate::frames::ethernet::{EtherType, EthernetFrame, EthernetPayload};
use crate::frames::ipv4::Ipv4Frame;
use crate::layers::shared::arp_table::ArpTable;
use once_cell::sync::Lazy;

// TODO: thread local
static mut ARP_TABLE: Lazy<ArpTable> = Lazy::new(|| ArpTable::new());

pub struct EthernetLayer {
    smacaddr: MacAddr,
    event_handler: ThreadEventHandler,
    layers_storage: IoThreadLayersStorageWrapper,
}

impl EthernetLayer {
    pub fn new(
        smacaddr: MacAddr,
        event_handler: ThreadEventHandler,
        layers_storage: IoThreadLayersStorageWrapper,
    ) -> EthernetLayer {
        EthernetLayer {
            smacaddr,
            event_handler,
            layers_storage,
        }
    }

    pub async fn send_ip_frame(&mut self, frame: Ipv4Frame) {
        let dmacaddr = unsafe {
            let dipaddr = frame.dest_ip_addr();
            ARP_TABLE.lookup(dipaddr).unwrap()
            // if let Ok(macaddr) = ARP_TABLE.lookup(dipaddr) {
            //     return macaddr;
            // }

            // self.layers_storage.arp_layer().send(dipaddr).await;
        };

        let frame = EthernetFrame::new(
            self.smacaddr,
            dmacaddr,
            EtherType::Ipv4,
            EthernetPayload::Ipv4Payload(frame),
        );
        self.event_handler.send(frame).await;
    }

    pub async fn send_arp_frame(&mut self, frame: ArpFrame) {
        let ether_frame = EthernetFrame::new(
            self.smacaddr,
            MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
            EtherType::Arp,
            EthernetPayload::ArpPayload(frame),
        );
        self.event_handler.send(ether_frame).await;
    }

    pub async fn poll(&mut self) -> Option<EthernetFrame> {
        match self.event_handler.recv().await {
            Some((frame, ip)) => Some(frame),
            None => None,
        }
    }
}
