use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::buffer::Buffer;
use crate::datalink::rawsock::RawSock;
use crate::datalink::reader::{read, ReadResult};
use crate::datalink::writer::{write, WriteResult};
use crate::frames::ethernet::{EtherType, EthernetFrame};
use crate::frames::ipv4::IpProtocol;
use crate::frames::tcp::TcpFrame;
use crate::packet::TcpPacket;
use crate::tcp::active_session::ActiveSession;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use log::{info, warn};
use tokio::time::{Duration, Instant};

const ACK_TIMEOUT_SEC: u64 = 3;

pub struct LocalHandler {
    smacaddr: MacAddr,
    dmacaddr: MacAddr,
    sipaddr: Ipv4Addr,
    dipaddr: Ipv4Addr,
    session: ActiveSession,
    sock: RawSock,
}

impl LocalHandler {
    pub async fn connect(
        smacaddr: MacAddr,
        dmacaddr: MacAddr,
        sipaddr: Ipv4Addr,
        dipaddr: Ipv4Addr,
        sport: u16,
        dport: u16,
        sock: RawSock,
    ) -> Result<Self> {
        let session = ActiveSession::new(sipaddr, dipaddr, sport, dport);
        let mut local_handler = LocalHandler {
            smacaddr,
            dmacaddr,
            sipaddr,
            dipaddr,
            session,
            sock,
        };
        if let Err(err) = local_handler.handshake().await {
            return Err(anyhow!("handshake failed: {}", err));
        }
        Ok(local_handler)
    }

    pub async fn send(&mut self, payload: BytesMut) -> Result<()> {
        let packet = self.create_tcp_data_packet(payload);
        self.send_internal(packet).await
    }

    async fn send_internal(&mut self, packet: (BytesMut, TcpFrame)) -> Result<()> {
        loop {
            let packet_c = packet.0.clone();
            let tcp_frame_c = packet.1.clone();
            let res = self.send_packet((packet_c, tcp_frame_c)).await;
            if res == WriteResult::Timeout {
                warn!("write timeout, retransmission");
                continue;
            }
            // ack receive
            let res = self.recv_packet().await;
            if res == ReadResult::Timeout {
                warn!("read timeout, retransmission");
                continue;
            }
            break;
        }
        Ok(())
    }

    pub async fn close(&mut self) -> Result<()> {
        // start close handshake
        let stream_id = self.session.stream_id();
        info!("session {} close handshake", stream_id);

        let packet = self.create_tcp_packet(true);
        let res = self.send_packet(packet).await;
        // TODO: execute retransmission
        match res {
            WriteResult::Timeout => return Err(anyhow!("write timeout")),
            _ => {}
        }

        let res = self.recv_packet().await;
        // TODO: execute retransmission
        match res {
            ReadResult::Timeout => return Err(anyhow!("read timeout")),
            _ => {}
        }

        let packet = self.create_tcp_packet(false);
        let res = self.send_packet(packet).await;
        match res {
            WriteResult::Timeout => return Err(anyhow!("write timeout")),
            _ => {}
        }
        Ok(())
    }

    async fn handshake(&mut self) -> Result<()> {
        let stream_id = self.session.stream_id();
        info!("session {} start handshake", stream_id);

        let packet = self.create_tcp_packet(false);
        let res = self.send_packet(packet).await;
        // TODO: execute retransmission
        match res {
            WriteResult::Timeout => return Err(anyhow!("write timeout")),
            _ => {}
        }

        let res = self.recv_packet().await;
        // TODO: execute retransmission
        match res {
            ReadResult::Timeout => return Err(anyhow!("read timeout")),
            _ => {}
        }

        let packet = self.create_tcp_packet(false);
        let res = self.send_packet(packet).await;
        match res {
            WriteResult::Timeout => return Err(anyhow!("write timeout")),
            _ => {}
        }
        Ok(())
    }

    async fn send_packet(&mut self, (tcp_packet, tcp_frame): (BytesMut, TcpFrame)) -> WriteResult {
        let res = write(&self.sock, tcp_packet, Duration::from_secs(ACK_TIMEOUT_SEC)).await;
        match res {
            WriteResult::Success(_) => self.session.on_send_tcp_frame(&tcp_frame),
            _ => {}
        }
        res
    }

    async fn recv_packet(&mut self) -> ReadResult {
        let deadline = Instant::now() + Duration::from_secs(ACK_TIMEOUT_SEC);
        loop {
            if deadline < Instant::now() {
                return ReadResult::Timeout;
            }
            let next_duration = deadline - Instant::now();
            let res = read(&self.sock, next_duration).await;
            match res {
                ReadResult::Success(buf) => {
                    let res2 = parse_tcp_packet(buf);
                    if res2.is_err() {
                        continue;
                    }
                    let tcp_frame = res2.unwrap();
                    if !self.session.is_recv_frame_in_this_session(&tcp_frame)
                        || !self.session.on_recv_tcp_frame(&tcp_frame)
                    {
                        continue;
                    }

                    return res;
                }
                ReadResult::Timeout => {
                    return res;
                }
            }
        }
    }

    fn create_tcp_packet(&mut self, close: bool) -> (BytesMut, TcpFrame) {
        let tcp_frame = self.session.create_next_frame(close).unwrap();
        let packet = TcpPacket::default()
            .set_tcp(tcp_frame.clone())
            .set_ipv4(self.sipaddr, self.dipaddr)
            .set_ether(self.smacaddr, self.dmacaddr)
            .build();
        (packet, tcp_frame)
    }

    fn create_tcp_data_packet(&mut self, payload: BytesMut) -> (BytesMut, TcpFrame) {
        let tcp_frame = self.session.create_next_data_frame(payload).unwrap();
        let packet = TcpPacket::default()
            .set_tcp(tcp_frame.clone())
            .set_ipv4(self.sipaddr, self.dipaddr)
            .set_ether(self.smacaddr, self.dmacaddr)
            .build();
        (packet, tcp_frame)
    }
}

fn parse_tcp_packet<'a>(mut buf: Buffer) -> Result<TcpFrame> {
    let ether = EthernetFrame::from_raw(&mut buf);
    if ether.frame_type() != EtherType::Ipv4 {
        return Err(anyhow!("not ipv4"));
    }

    let ip = ether.ipv4_payload();
    if ip.is_err() {
        return Err(anyhow!("failed to parse ipv4"));
    }

    let ip = ip.unwrap();
    if ip.protocol() != IpProtocol::Tcp {
        return Err(anyhow!("not tcp"));
    }

    let tcp = ip.tcp_payload();
    if tcp.is_err() {
        return Err(anyhow!("failed to parse tcp payload"));
    }

    Ok(tcp.unwrap().to_owned())
}
