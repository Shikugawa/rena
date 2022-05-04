use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::rawsock::RawSock;
use crate::datalink::reader::{read, ReadResult};
use crate::frames::ethernet::{EtherType, EthernetFrame};
use crate::frames::icmp::IcmpFrame;
use crate::frames::ipv4::IpProtocol;
use crate::frames::tcp::TcpFrame;
use crate::layers::storage_wrapper::{
    IoThreadLayersStorageWrapper, IoThreadLayersStorageWrapperRawSock,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct IoHandler {
    handle: Option<JoinHandle<()>>,
    sock: Arc<RawSock>,
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
        mpsc::Sender<(L4Frame, Ipv4Addr)>,
        mpsc::Receiver<L4Frame>,
    ) {
        let (write_tx, mut write_rx) = mpsc::channel(1 << 10);
        let (read_tx, read_rx) = mpsc::channel(1 << 10);

        let mut receiver = IoHandler {
            handle: None,
            sock: Arc::new(sock),
        };

        let read_sock = receiver.sock.clone();
        let write_sock = receiver.sock.clone();

        receiver.handle = Some(tokio::spawn(async move {
            let layer_storage =
                IoThreadLayersStorageWrapperRawSock::init(write_sock, sipaddr, smacaddr);
            let mut event_loop = EventLoop::new(read_sock, write_rx, read_tx, layer_storage);

            event_loop.start().await;
            // TODO: graceful loop close
        }));
        (receiver, write_tx, read_rx)
    }

    pub async fn close(&mut self) {
        if self.handle.is_some() {
            let handle = self.handle.as_mut();
            // TODO: prepare shutdown signal
            handle.unwrap().await;
        }
    }
}

struct EventLoop {
    read_sock: Arc<RawSock>,
    write_rx: mpsc::Receiver<(L4Frame, Ipv4Addr)>,
    read_tx: mpsc::Sender<L4Frame>,
    layer_storage: IoThreadLayersStorageWrapperRawSock,
}

impl EventLoop {
    pub fn new(
        read_sock: Arc<RawSock>,
        write_rx: mpsc::Receiver<(L4Frame, Ipv4Addr)>,
        read_tx: mpsc::Sender<L4Frame>,
        layer_storage: IoThreadLayersStorageWrapperRawSock,
    ) -> Self {
        Self {
            read_sock,
            write_rx,
            read_tx,
            layer_storage,
        }
    }

    pub async fn start(&mut self) {
        loop {
            tokio::select! {
                res = self.write_rx.recv() => {
                    let (frame, dipaddr) = res.unwrap();

                    match frame {
                        L4Frame::Tcp(frame) => self.handle_send_tcp(dipaddr, frame).await,
                        L4Frame::Icmp(frame) => self.handle_send_icmp(dipaddr, frame).await
                    }
                },
                res = read(self.read_sock.clone(), None) => {
                    let buf = match res {
                        ReadResult::Success(buf) => Some(buf),
                        ReadResult::Timeout => None
                    };

                    if buf.is_none() {
                        continue;
                    }

                    let ether = EthernetFrame::from_raw(&mut buf.unwrap());
                    match ether.frame_type() {
                        EtherType::Arp => unimplemented!("arp"),
                        EtherType::Ipv4 => self.handle_recv_ipv4(ether).await,
                        EtherType::Ipv6 | EtherType::Unknown => unimplemented!("ipv6 not supported"),
                    };
                }
            }
        }
    }

    async fn handle_recv_ipv4(&self, ether: EthernetFrame) {
        let ip_frame = ether.ipv4_payload().unwrap().to_owned();
        match ip_frame.protocol() {
            IpProtocol::Tcp => {
                let tcp_frame = ip_frame.tcp_payload().unwrap().to_owned();
                self.read_tx.send(L4Frame::Tcp(tcp_frame)).await;
            }
            IpProtocol::Icmp => {}
            IpProtocol::Unknown => {}
        }
    }

    async fn handle_send_tcp(&self, dipaddr: Ipv4Addr, frame: TcpFrame) {
        self.layer_storage
            .ipv4_layer()
            .send_tcp_frame(dipaddr, frame)
            .await;
    }

    async fn handle_send_icmp(&self, dipaddr: Ipv4Addr, frame: IcmpFrame) {
        self.layer_storage
            .ipv4_layer()
            .send_icmp_frame(dipaddr, frame)
            .await;
    }
}
