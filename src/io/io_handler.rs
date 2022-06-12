use crate::datalink::rawsock::RawSock;
use crate::frames::ethernet::EthernetFrame;
use crate::frames::icmp::IcmpFrame;
use crate::frames::tcp::TcpFrame;
use crate::io::event_loop::EventLoop;
use log::{info, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct IoHandler {
    iothread_handle: Option<JoinHandle<()>>,
    shutdown_tx: Option<mpsc::Sender<bool>>,
}

pub enum L4Frame {
    Tcp(TcpFrame),
    Icmp(IcmpFrame),
}

impl IoHandler {
    pub fn new(
        sock: RawSock,
    ) -> (
        Self,
        mpsc::Sender<EthernetFrame>,
        mpsc::Receiver<EthernetFrame>,
    ) {
        let (write_tx, write_rx) = mpsc::channel(1 << 10);
        let (read_tx, read_rx) = mpsc::channel(1 << 10);

        let mut receiver = IoHandler {
            iothread_handle: None,
            shutdown_tx: None,
        };

        let (mut event_loop, shutdown_tx) = EventLoop::new(Arc::new(sock), write_rx, read_tx);

        receiver.shutdown_tx = Some(shutdown_tx);
        receiver.iothread_handle = Some(tokio::spawn(async move {
            info!("Start event loop");
            event_loop.start().await;
            info!("Close event loop");
        }));
        (receiver, write_tx, read_rx)
    }

    pub async fn close(&mut self) {
        if let Err(err) = self.shutdown_tx.as_ref().unwrap().send(true).await {
            warn!("{}", err);
            return;
        }

        let handle = self.iothread_handle.as_mut();
        if let Err(err) = handle.unwrap().await {
            warn!("{}", err);
            return;
        }
    }
}
