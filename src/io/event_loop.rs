use crate::datalink::rawsock::RawSock;
use crate::datalink::reader::{read, ReadResult};
use crate::datalink::writer::write;
use crate::frames::ethernet::EthernetFrame;
use crate::frames::frame::Frame;
use log::error;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct EventLoop {
    sock: Arc<RawSock>,
    write_rx: mpsc::Receiver<EthernetFrame>,
    read_tx: mpsc::Sender<EthernetFrame>,
    shutdown_rx: mpsc::Receiver<bool>,
}

impl EventLoop {
    pub fn new(
        sock: Arc<RawSock>,
        write_rx: mpsc::Receiver<EthernetFrame>,
        read_tx: mpsc::Sender<EthernetFrame>,
    ) -> (Self, mpsc::Sender<bool>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        (
            Self {
                sock,
                write_rx,
                read_tx,
                shutdown_rx,
            },
            shutdown_tx,
        )
    }

    pub async fn start(&mut self) {
        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    break;
                }
                res = self.write_rx.recv() => {
                    let frame = res.unwrap();
                    write(self.sock.clone(), frame.to_bytes(), None).await;
                },
                res = read(self.sock.clone(), None) => {
                    let buf = match res {
                        ReadResult::Success(buf) => Some(buf),
                        ReadResult::Timeout => None
                    };

                    if buf.is_none() {
                        continue;
                    }

                    let ether = EthernetFrame::from_raw(&mut buf.unwrap());
                    if let Err(err) = self.read_tx.send(ether).await {
                        error!("{}", err);
                    }
                }
            }
        }
    }
}
