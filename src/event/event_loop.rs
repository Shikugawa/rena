use tokio::sync::mpsc;

use crate::{addresses::ipv4::Ipv4Addr, frames::ethernet::EthernetFrame};

pub struct ThreadEventHandler {
    read_rx: mpsc::Receiver<(EthernetFrame, Ipv4Addr)>,
    write_tx: mpsc::Sender<EthernetFrame>,
}

impl ThreadEventHandler {
    pub fn new(
        read_rx: mpsc::Receiver<(EthernetFrame, Ipv4Addr)>,
        write_tx: mpsc::Sender<EthernetFrame>,
    ) -> Self {
        Self { read_rx, write_tx }
    }

    pub async fn send(&mut self, ether_frame: EthernetFrame) {
        self.write_tx.send(ether_frame).await;
    }

    pub async fn recv(&mut self) -> Option<(EthernetFrame, Ipv4Addr)> {
        if let Some(frame) = self.read_rx.recv().await {
            Some(frame)
        } else {
            None
        }
    }
}
