use tokio::sync::mpsc;
use log::error;

use crate::frames::ethernet::EthernetFrame;

pub struct ThreadEventHandler {
    read_rx: mpsc::Receiver<EthernetFrame>,
    write_tx: mpsc::Sender<EthernetFrame>,
}

impl ThreadEventHandler {
    pub fn new(
        read_rx: mpsc::Receiver<EthernetFrame>,
        write_tx: mpsc::Sender<EthernetFrame>,
    ) -> Self {
        Self { read_rx, write_tx }
    }

    pub async fn send(&mut self, ether_frame: EthernetFrame) {
        if let Err(err) = self.write_tx.send(ether_frame).await {
            error!("{}", err);
        }
    }

    pub async fn recv(&mut self) -> Option<EthernetFrame> {
        if let Some(frame) = self.read_rx.recv().await {
            Some(frame)
        } else {
            None
        }
    }
}
