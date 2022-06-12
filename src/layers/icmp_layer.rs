use crate::addresses::ipv4::Ipv4Addr;
use crate::frames::icmp::{self, IcmpFrame, IcmpType};
use anyhow::Result;
use log::warn;
use std::time::Duration;

use super::thread_local_layer_storage::ThreadLocalStorageCopyableWrapper;

pub struct IcmpLayer {
    layers_storage: ThreadLocalStorageCopyableWrapper,

    // the thread id that EthernetLayer is owned by
    thread_id: u64,
}

impl IcmpLayer {
    pub fn new(layers_storage: ThreadLocalStorageCopyableWrapper, thread_id: u64) -> Self {
        Self {
            layers_storage,
            thread_id,
        }
    }

    pub async fn send_icmp_echo_request(&mut self, dipaddr: Ipv4Addr, seq_num: u16) {
        let frame = IcmpFrame::new(IcmpType::EchoRequest, seq_num);
        self.send_internal(dipaddr, frame).await;

        if let Err(err) = self.poll_valid_frame(seq_num, None).await {
            warn!("{}", err);
            return;
        }
    }

    async fn send_internal(&mut self, dipaddr: Ipv4Addr, frame: IcmpFrame) {
        self.layers_storage
            .ipv4_layer(self.thread_id)
            .send_icmp_frame(dipaddr, frame)
            .await;
    }

    // TODO: timeout
    async fn poll_valid_frame(
        &mut self,
        expected_num: u16,
        timeout: Option<Duration>,
    ) -> Result<IcmpFrame> {
        loop {
            if let Some(icmp_frame) = self.poll().await {
                println!("{}", icmp_frame);
                if icmp_frame.seq_num() == expected_num {
                    return Ok(icmp_frame);
                }
            } else {
                continue;
            }
        }
    }

    async fn poll(&self) -> Option<IcmpFrame> {
        let frame = self.layers_storage.ipv4_layer(self.thread_id).poll().await;

        if frame.is_none() {
            return None;
        }

        let frame = frame.unwrap();

        if frame.protocol().is_icmp() {
            Some(frame.icmp_payload().unwrap().to_owned())
        } else {
            None
        }
    }
}
