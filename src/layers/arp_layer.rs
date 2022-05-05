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
}
