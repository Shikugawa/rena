use crate::addresses::ipv4::Ipv4Addr;
use crate::frames::icmp::IcmpFrame;
use crate::frames::ipv4::{IpProtocol, Ipv4Frame, Ipv4Payload};
use crate::frames::tcp::TcpFrame;

use super::thread_local_layer_storage::ThreadLocalStorageCopyableWrapper;

pub struct Ipv4Layer {
    sipaddr: Ipv4Addr,
    layers_storage: ThreadLocalStorageCopyableWrapper,

    // the thread id that EthernetLayer is owned by
    thread_id: u64,
}

impl Ipv4Layer {
    pub fn new(
        sipaddr: Ipv4Addr,
        layers_storage: ThreadLocalStorageCopyableWrapper,
        thread_id: u64,
    ) -> Self {
        Ipv4Layer {
            sipaddr,
            layers_storage,
            thread_id,
        }
    }

    pub async fn send_tcp_frame(&mut self, dipaddr: Ipv4Addr, frame: TcpFrame) {
        let ipv4_frame = Ipv4Frame::new(
            self.sipaddr,
            dipaddr,
            IpProtocol::Tcp,
            Ipv4Payload::TcpPayload(frame),
        );

        self.layers_storage
            .ethernet_layer(self.thread_id)
            .send_ip_frame(ipv4_frame)
            .await;
    }

    pub async fn send_icmp_frame(&mut self, dipaddr: Ipv4Addr, frame: IcmpFrame) {
        let ipv4_frame = Ipv4Frame::new(
            self.sipaddr,
            dipaddr,
            IpProtocol::Icmp,
            Ipv4Payload::IcmpPayload(frame),
        );

        self.layers_storage
            .ethernet_layer(self.thread_id)
            .send_ip_frame(ipv4_frame)
            .await;
    }

    pub async fn poll(&mut self) -> Option<Ipv4Frame> {
        let frame = self
            .layers_storage
            .ethernet_layer(self.thread_id)
            .poll()
            .await;

        if frame.is_none() {
            return None;
        }

        let frame = frame.unwrap();

        if frame.frame_type().is_ipv4() {
            Some(frame.ipv4_payload().unwrap().to_owned())
        } else {
            None
        }
    }
}
