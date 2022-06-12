use super::thread_local_layer_storage::ThreadLocalStorageCopyableWrapper;
use crate::addresses::mac::MacAddr;
use crate::frames::arp::ArpFrame;
use crate::frames::ethernet::{EtherType, EthernetFrame, EthernetPayload};
use crate::frames::ipv4::Ipv4Frame;
use crate::io::thread_event_handler::ThreadEventHandler;
use crate::layers::shared::arp_table::ArpTable;
use log::error;
use once_cell::sync::Lazy;

// TODO: thread local
static mut ARP_TABLE: Lazy<ArpTable> = Lazy::new(|| ArpTable::new());

pub struct EthernetLayer {
    smacaddr: MacAddr,
    event_handler: ThreadEventHandler,
    layers_storage: ThreadLocalStorageCopyableWrapper,

    // the thread id that EthernetLayer is owned by
    thread_id: u64,
}

impl EthernetLayer {
    pub fn new(
        smacaddr: MacAddr,
        event_handler: ThreadEventHandler,
        layers_storage: ThreadLocalStorageCopyableWrapper,
        thread_id: u64,
    ) -> EthernetLayer {
        EthernetLayer {
            smacaddr,
            event_handler,
            layers_storage,
            thread_id,
        }
    }

    pub async fn send_ip_frame(&mut self, frame: Ipv4Frame) {
        let dipaddr = frame.dest_ip_addr();
        let res = unsafe { ARP_TABLE.lookup(dipaddr) };
        let dmacaddr: MacAddr = match res {
            Ok(addr) => addr,
            Err(_) => {
                self.layers_storage
                    .arp_layer(self.thread_id)
                    .send_arp_frame(dipaddr)
                    .await;

                let arp_resp = self.layers_storage.arp_layer(self.thread_id).poll().await;
                let smacaddr = arp_resp.unwrap().source_macaddr();

                if let Err(err) = unsafe { ARP_TABLE.add(dipaddr, smacaddr) } {
                    error!("{}", err);
                }

                smacaddr
            }
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
            Some(frame) => Some(frame),
            None => None,
        }
    }
}
