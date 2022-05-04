use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::rawsock::RawSock;
use crate::datalink::reader::{read, ReadResult};
use crate::datalink::traits::DatalinkReaderWriter;
use crate::datalink::writer::write;
use crate::frames::ethernet::{EtherType, EthernetFrame};
use crate::frames::frame::Frame;
use crate::frames::icmp::IcmpFrame;
use crate::frames::ipv4::IpProtocol;
use crate::frames::tcp::TcpFrame;
use crate::layers::storage_wrapper::IoThreadLayersStorageWrapperRawSock;
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

            loop {
                tokio::select! {
                    res = write_rx.recv() => {
                        let (tcp_frame, dipaddr) = res.unwrap();
                        // layer_storage.ipv4_layer().send_tcp_frame(dipaddr, tcp_frame).await;
                    },
                    res = read(read_sock.clone(), None) => {
                        match res {
                            ReadResult::Success(mut buf) => {
                                let ether = EthernetFrame::from_raw(&mut buf);
                                match ether.frame_type() {
                                    EtherType::Arp => unimplemented!("arp"),
                                    EtherType::Ipv4 => {
                                        let ip_frame = ether.ipv4_payload().unwrap().to_owned();
                                        match ip_frame.protocol() {
                                            IpProtocol::Tcp => {
                                                let tcp_frame = ip_frame.tcp_payload().unwrap().to_owned();
                                                let _ = read_tx.send(L4Frame::Tcp(tcp_frame)).await;
                                            }
                                            IpProtocol::Icmp | IpProtocol::Unknown => unimplemented!("unknown"),
                                        }
                                    }
                                    EtherType::Ipv6 | EtherType::Unknown => unimplemented!("ipv6 not supported"),
                                };
                            }
                            ReadResult::Timeout => continue
                        }
                    }
                }
            }
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
