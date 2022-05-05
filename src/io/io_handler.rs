use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::rawsock::RawSock;
use crate::datalink::reader::{read, ReadResult};
use crate::datalink::writer::write;
use crate::frames::ethernet::{EtherType, EthernetFrame};
use crate::frames::frame::Frame;
use crate::frames::icmp::IcmpFrame;
use crate::frames::ipv4::IpProtocol;
use crate::frames::tcp::TcpFrame;
use crate::layers::storage_wrapper::IoThreadLayersStorageWrapper;
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
        smacaddr: MacAddr,
        sipaddr: Ipv4Addr,
    ) -> (
        Self,
        mpsc::Sender<(EthernetFrame, Ipv4Addr)>,
        mpsc::Receiver<EthernetFrame>,
    ) {
        let (write_tx, write_rx) = mpsc::channel(1 << 10);
        let (read_tx, read_rx) = mpsc::channel(1 << 10);

        let mut receiver = IoHandler {
            iothread_handle: None,
            shutdown_tx: None,
        };

        let (mut event_loop, shutdown_tx) = IoEventLoop::new(Arc::new(sock), write_rx, read_tx);

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

struct IoEventLoop {
    sock: Arc<RawSock>,
    write_rx: mpsc::Receiver<(EthernetFrame, Ipv4Addr)>,
    read_tx: mpsc::Sender<EthernetFrame>,
    shutdown_rx: mpsc::Receiver<bool>,
}

impl IoEventLoop {
    pub fn new(
        sock: Arc<RawSock>,
        write_rx: mpsc::Receiver<(EthernetFrame, Ipv4Addr)>,
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
                    let (frame, dipaddr) = res.unwrap();
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
                    self.read_tx.send(ether).await;
                }
            }
        }
    }
}
