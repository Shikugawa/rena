use super::storage_wrapper::IoThreadLayersStorageWrapper;
use crate::addresses::{ipv4::Ipv4Addr, mac::MacAddr};
use crate::frames::arp::ArpFrame;

pub struct ArpLayer {
    smacaddr: MacAddr,
    sipaddr: Ipv4Addr,
    layers_storage: IoThreadLayersStorageWrapper,
}

impl ArpLayer {
    pub fn new(
        smacaddr: MacAddr,
        sipaddr: Ipv4Addr,
        layers_storage: IoThreadLayersStorageWrapper,
    ) -> Self {
        Self {
            smacaddr,
            sipaddr,
            layers_storage,
        }
    }

    pub async fn send_arp_frame(&mut self, dipaddr: Ipv4Addr) {
        let arp_frame = ArpFrame::new_request(self.smacaddr, self.sipaddr, dipaddr);
        self.layers_storage
            .ethernet_layer()
            .send_arp_frame(arp_frame)
            .await;
    }

    // TODO: implement poll valid frame
    pub async fn poll(&self) -> Option<ArpFrame> {
        let frame = self.layers_storage.ethernet_layer().poll().await;

        if frame.is_none() {
            return None;
        }

        let frame = frame.unwrap();

        if frame.frame_type().is_arp() {
            Some(frame.arp_payload().unwrap().to_owned())
        } else {
            None
        }
    }
}
