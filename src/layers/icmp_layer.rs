use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::rawsock::RawSock;
use crate::frames::icmp::{IcmpFrame, IcmpType};
use crate::io::io_handler::{IoHandler, L4Frame};
use anyhow::Result;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct IcmpLayer {
    io_handler: IoHandler,
    write_tx: mpsc::Sender<(L4Frame, Ipv4Addr)>,
    read_rx: mpsc::Receiver<L4Frame>,
}

impl IcmpLayer {
    pub fn new(sock: RawSock, smacaddr: MacAddr, sipaddr: Ipv4Addr) -> Self {
        let (io_handler, write_tx, read_rx) = IoHandler::new(sock, smacaddr, sipaddr);
        Self {
            io_handler,
            write_tx,
            read_rx,
        }
    }

    pub async fn close(&mut self) {
      self.io_handler.close().await;
    }

    pub async fn ping(&mut self, dipaddr: Ipv4Addr) {
        let seq_num = 0;

        let frame = IcmpFrame::new(IcmpType::EchoRequest, seq_num);
        self.write_tx.send((L4Frame::Icmp(frame), dipaddr)).await;

        self.wait_valid_frame(seq_num + 1, None).await;
    }

    async fn send_internal(&mut self, dipaddr: Ipv4Addr, frame: IcmpFrame) {
        self.write_tx.send((L4Frame::Icmp(frame), dipaddr)).await;
    }

    // TODO: timeout
    async fn wait_valid_frame(
        &mut self,
        expected_num: u16,
        timeout: Option<Duration>,
    ) -> Result<IcmpFrame> {
        loop {
            if let Some(icmp_frame) = self.read().await {
                if icmp_frame.seq_num() == expected_num + 1 {
                    return Ok(icmp_frame);
                }
            } else {
                continue;
            }
        }
    }

    async fn read(&mut self) -> Option<IcmpFrame> {
        if let Some(frame) = self.read_rx.recv().await {
            return match frame {
                L4Frame::Tcp(_) => None,
                L4Frame::Icmp(frame) => Some(frame),
            };
        } else {
            None
        }
    }
}
