use crate::addresses::ipv4::Ipv4Addr;
use crate::frames::icmp::{IcmpFrame, IcmpType};
use anyhow::Result;
use log::warn;
use std::time::Duration;

use super::storage_wrapper::IoThreadLayersStorageWrapper;

pub struct IcmpLayer {
    layers_storage: IoThreadLayersStorageWrapper,
}

impl IcmpLayer {
    pub fn new(layers_storage: IoThreadLayersStorageWrapper) -> Self {
        Self { layers_storage }
    }

    pub async fn ping(&mut self, dipaddr: Ipv4Addr) {
        let seq_num = 0;

        let frame = IcmpFrame::new(IcmpType::EchoRequest, seq_num);
        self.send_internal(dipaddr, frame).await;

        if let Err(err) = self.poll_valid_frame(seq_num + 1, None).await {
            warn!("{}", err);
            return;
        }
    }

    async fn send_internal(&mut self, dipaddr: Ipv4Addr, frame: IcmpFrame) {
        self.layers_storage
            .ipv4_layer()
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
                if icmp_frame.seq_num() == expected_num + 1 {
                    return Ok(icmp_frame);
                }
            } else {
                continue;
            }
        }
    }

    async fn poll(&self) -> Option<IcmpFrame> {
        let frame = self.layers_storage.ipv4_layer().poll().await;

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
