use std::{collections::HashMap, sync::Arc};

use crate::frames::tcp::TcpFrame;
use crate::tcp::subscriber::Subscriber;
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
use log::error;
use once_cell::sync::Lazy;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

static mut WORKER_SUBSCRIPTIONS: Lazy<HashMap<u16, mpsc::Sender<TcpFrame>>> =
    Lazy::new(|| HashMap::new());

pub struct FrameReceiver {
    handle: Option<JoinHandle<()>>,
    subscriptions_locked: bool,
}

impl FrameReceiver {
    pub fn new() -> Self {
        Self {
            handle: None,
            subscriptions_locked: false,
        }
    }

    pub fn subscribe(&self, sport: u16, subscriber: &mut dyn Subscriber) {
        if self.subscriptions_locked {
            return;
        }

        let (tx, rx) = mpsc::channel(1 << 10);
        subscriber.subscribe(rx);

        // This unsafe is safe because subscription is not allowed after receiver thread is started.
        unsafe {
            WORKER_SUBSCRIPTIONS.insert(sport, tx);
        }
    }

    pub fn run(&mut self, sock: Arc<dyn DatalinkReaderWriter>) {
        self.subscriptions_locked = true;
        self.handle = Some(tokio::spawn(async move {
            loop {
                let res = read(sock.clone(), None).await;
                match res {
                    ReadResult::Success(mut buf) => {
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
                        let tcp_owned = tcp.unwrap().to_owned();
                        let dport = tcp_owned.dport();

                        unsafe {
                            if WORKER_SUBSCRIPTIONS.contains_key(&dport) {
                                if let Err(err) = WORKER_SUBSCRIPTIONS
                                    .get(&dport)
                                    .unwrap()
                                    .send(tcp_owned)
                                    .await
                                {
                                    error!("failed to read packet due to some reasons: {}", err)
                                }
                            }
                        }
                    }
                    ReadResult::Timeout => {}
                }
            }
        }));
    }

    pub async fn close(&mut self) {
        if self.handle.is_some() {
            let handle = self.handle.as_mut();
            // TODO: prepare shutdown signal
            handle.unwrap().await;
        }
    }
}
