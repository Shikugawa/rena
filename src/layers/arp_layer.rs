use super::thread_local_layer_storage::ThreadLocalStorageCopyableWrapper;
use crate::addresses::{ipv4::Ipv4Addr, mac::MacAddr};
use crate::frames::arp::ArpFrame;

pub struct ArpLayer {
    smacaddr: MacAddr,
    sipaddr: Ipv4Addr,
    layers_storage: ThreadLocalStorageCopyableWrapper,

    // the thread id that EthernetLayer is owned by
    thread_id: u64,
}

impl ArpLayer {
    pub fn new(
        smacaddr: MacAddr,
        sipaddr: Ipv4Addr,
        layers_storage: ThreadLocalStorageCopyableWrapper,
        thread_id: u64,
    ) -> Self {
        Self {
            smacaddr,
            sipaddr,
            layers_storage,
            thread_id,
        }
    }

    pub async fn send_arp_frame(&mut self, dipaddr: Ipv4Addr) {
        let arp_frame = ArpFrame::new_request(self.smacaddr, self.sipaddr, dipaddr);
        self.layers_storage
            .ethernet_layer(self.thread_id)
            .send_arp_frame(arp_frame)
            .await;
    }

    // TODO: implement poll valid frame
    pub async fn poll(&self) -> Option<ArpFrame> {
        let frame = self
            .layers_storage
            .ethernet_layer(self.thread_id)
            .poll()
            .await;

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
