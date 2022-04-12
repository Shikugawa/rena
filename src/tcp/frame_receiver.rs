use std::{collections::HashMap, sync::Arc};

use crate::frames::tcp::TcpFrame;
use crate::{
    datalink::{
        reader::{read, ReadResult},
        traits::DatalinkReaderWriter,
    },
    frames::{
        ethernet::{EtherType, EthernetFrame},
        ipv4::IpProtocol,
    },
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub struct FrameReceiver {
    handle: Option<JoinHandle<()>>,
    subscriptions: HashMap<u16, mpsc::Sender<TcpFrame>>,
}

impl FrameReceiver {
    pub fn new(sock: Arc<dyn DatalinkReaderWriter>) -> Self {
        let receiver = Self {
            handle: None,
            subscriptions: HashMap::new(),
        };

        let handle = tokio::spawn(async {
            loop {
                let res = read(sock, None).await;
                match res {
                    ReadResult::Success(buf) => {
                        let ether = EthernetFrame::from_raw(&mut buf);
                        if ether.frame_type() != EtherType::Ipv4 {
                            continue;
                        }

                        let ip = ether.ipv4_payload();
                        if ip.is_err() {
                            continue;
                        }

                        let ip = ip.unwrap();
                        if ip.protocol() != IpProtocol::Tcp {
                            continue;
                        }

                        let tcp = ip.tcp_payload();
                        if tcp.is_err() {
                            continue;
                        }

                        let dport = tcp.unwrap().dport();
                    }
                    ReadResult::Timeout => {}
                }
            }
        });

        receiver.handle = Some(handle);
        receiver
    }
}
