use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::reader::{read, ReadResult};
use crate::datalink::traits::DatalinkReaderWriter;
use crate::datalink::writer::write;
use crate::frames::ethernet::{EtherType, EthernetFrame};
use crate::frames::frame::Frame;
use crate::frames::ipv4::IpProtocol;
use crate::frames::tcp::TcpFrame;
use crate::packet::{EthernetLayer, Ipv4Layer};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct IoHandler<T>
where
    T: DatalinkReaderWriter + 'static,
{
    handle: Option<JoinHandle<()>>,
    sock: T,

    write_tx: mpsc::Sender<(TcpFrame, Ipv4Addr)>,
    write_rx: mpsc::Receiver<(TcpFrame, Ipv4Addr)>,
    read_tx: mpsc::Sender<TcpFrame>,
    read_rx: mpsc::Receiver<TcpFrame>,
}

impl<T> IoHandler<T>
where
    T: DatalinkReaderWriter + 'static,
{
    pub fn new(sock: T, smacaddr: MacAddr, sipaddr: Ipv4Addr) -> Self {
        let (write_tx, write_rx) = mpsc::channel(1 << 10);
        let (read_tx, read_rx) = mpsc::channel(1 << 10);

        let mut receiver = IoHandler::<T> {
            handle: None,
            sock,
            write_tx,
            write_rx,
            read_tx,
            read_rx,
        };
        receiver.handle = Some(tokio::spawn(async move {
            async fn handle_ether(read_tx: mpsc::Sender<TcpFrame>, ether: EthernetFrame) {
                match ether.frame_type() {
                    EtherType::Arp => unimplemented!("arp"),
                    EtherType::Ipv4 => {
                        let ip_frame = ether.ipv4_payload().unwrap().to_owned();
                        match ip_frame.protocol() {
                            IpProtocol::Tcp => {
                                let tcp_frame = ip_frame.tcp_payload().unwrap().to_owned();
                                read_tx.send(tcp_frame).await;
                            }
                            IpProtocol::Icmp | IpProtocol::Unknown => unimplemented!("unknown"),
                        }
                    }
                    EtherType::Ipv6 => unimplemented!("ipv6 not supported"),
                }
            }

            let ether_layer = EthernetLayer::new(smacaddr);
            let ip_layer = Ipv4Layer::new(sipaddr);

            loop {
                tokio::select! {
                    res = receiver.write_rx.recv() => {
                        let (tcp_frame, dipaddr) = res.unwrap();
                        let ip_frame = ip_layer.send(dipaddr, tcp_frame);
                        let ether_frame = ether_layer.send(ip_frame);
                        write(Arc::new(receiver.sock), ether_frame.to_bytes(), None);
                    },
                    res = read(Arc::new(receiver.sock), None) => {
                      match res {
                        ReadResult::Success(buf) => {
                            let ether_frame = EthernetFrame::from_raw(&mut buf);
                            handle_ether(read_tx, ether_frame);
                        }
                        ReadResult::Timeout => continue
                      }
                    }
                }
            }
        }));
        receiver
    }

    pub async fn send(&mut self, frame: TcpFrame, dipaddr: Ipv4Addr) {
        let _ = self.write_tx.send((frame, dipaddr)).await;
    }

    pub async fn recv(&mut self) -> Option<TcpFrame> {
        self.read_rx.recv().await
    }

    pub async fn close(&mut self) {
        if self.handle.is_some() {
            let handle = self.handle.as_mut();
            // TODO: prepare shutdown signal
            handle.unwrap().await;
        }
    }
}
