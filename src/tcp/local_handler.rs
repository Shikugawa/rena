use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::buffer::Buffer;
use crate::datalink::rawsock::RawSock;
use crate::datalink::reader::{read, ReadResult};
use crate::datalink::traits::DatalinkReaderWriter;
use crate::datalink::writer::{write, WriteResult};
use crate::frames::ethernet::{EtherType, EthernetFrame};
use crate::frames::frame::Frame;
use crate::frames::ipv4::IpProtocol;
use crate::frames::tcp::TcpFrame;
use crate::packet::TcpPacket;
use crate::tcp::active_session::ActiveSession;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use log::{info, warn};
use std::cmp::min;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::time::{interval, Duration, Instant};

pub struct LocalHandler {
    smacaddr: MacAddr,
    dmacaddr: MacAddr,
    sipaddr: Ipv4Addr,
    dipaddr: Ipv4Addr,
    session: ActiveSession,
    sock: Arc<dyn DatalinkReaderWriter>,

    // pending_message_queue is used to hold inflight segments.
    // If retransmission which is triggered by 1) duplicated ack_num, 2) ack timeout
    // is occurred, the number of packet will be enqueued repeatedly here.
    pending_message_queue: VecDeque<(usize, Instant)>,
}

impl LocalHandler {
    pub async fn connect(
        smacaddr: MacAddr,
        dmacaddr: MacAddr,
        sipaddr: Ipv4Addr,
        dipaddr: Ipv4Addr,
        sport: u16,
        dport: u16,
        sock: Arc<RawSock>,
    ) -> Result<Self> {
        let session = ActiveSession::new(sipaddr, dipaddr, sport, dport);
        let mut local_handler = LocalHandler {
            smacaddr,
            dmacaddr,
            sipaddr,
            dipaddr,
            session,
            sock: sock,
            pending_message_queue: VecDeque::new(),
        };
        local_handler.handshake().await;
        Ok(local_handler)
    }

    pub async fn send(&mut self, payload: BytesMut) -> Result<()> {
        let raw_packets = self.create_tcp_data_packet(payload);

        let mut next_idx = 0;
        let pending_buf_size = min(self.session.can_send_packet_num(), raw_packets.len());

        // Init data send state
        self.pending_message_queue = VecDeque::with_capacity(pending_buf_size);

        // Initial flight
        let start_idx = next_idx;
        while next_idx < start_idx + pending_buf_size {
            self.send_data_internal(next_idx, raw_packets[next_idx].1.clone())
                .await;
            next_idx += 1;
        }

        let mut interval = interval(Duration::from_secs(1));

        // Wait ACKs for pending messages. If it succeeded, it executes
        // 1) If it has remaining segment, handler sends it.
        // 2) If ACKs can't be received via timeout, handler execute transmission
        //    for failed SYN message immediately.
        while next_idx < raw_packets.len() {
            tokio::select! {
                instant = interval.tick() => {
                    while !self.pending_message_queue.is_empty() {
                        let (_, deadline) = self.pending_message_queue.front().unwrap();

                        if deadline <= &instant {
                            break;
                        }

                        let (idx, _) = self.pending_message_queue.pop_front().unwrap();
                        let packet = raw_packets[idx].1.clone();

                        write(self.sock.clone(), packet, None).await;

                        // TODO: fix backoff timeout
                        let new_deadline = Instant::now() + Duration::from_secs(3);
                        self.pending_message_queue.push_back((idx, new_deadline));
                    }
                },
                res = read(self.sock.clone(), None) => {
                    match res {
                        ReadResult::Success(buf) => {
                            let tcp_frame = parse_tcp_packet(buf);
                            if tcp_frame.is_err() {
                                continue;
                            }

                            let tcp_frame = tcp_frame.unwrap();
                            self.pending_message_queue.pop_front().unwrap();

                            if !self.session.on_recv_tcp_frame(&tcp_frame) {
                                continue;
                            }

                            next_idx += 1;

                            if next_idx >= raw_packets.len() {
                                break;
                            }

                            self.send_data_internal(next_idx, raw_packets[next_idx].1.clone()).await;
                        }
                        ReadResult::Timeout => {}
                    }
                }
            }
        }

        self.pending_message_queue.clear();
        Ok(())
    }

    pub async fn close(&mut self) {
        // start close handshake
        let stream_id = self.session.stream_id();
        info!("session {} close handshake", stream_id);

        let packet = self.create_tcp_packet(true);
        self.send_internal(packet, None).await;

        self.recv_packet(None).await;

        let packet = self.create_tcp_packet(false);
        self.send_internal(packet, None).await;
    }

    async fn handshake(&mut self) {
        let stream_id = self.session.stream_id();
        info!("session {} start handshake", stream_id);

        let packet = self.create_tcp_packet(false);
        self.send_internal(packet, None).await;

        self.recv_packet(None).await;

        let packet = self.create_tcp_packet(false);
        self.send_internal(packet, None).await;
    }

    // TODO: handle timeout if local transmission failed
    async fn send_data_internal(&mut self, idx: usize, packet: BytesMut) {
        write(self.sock.clone(), packet, None).await;
        // TODO: fix backoff timeout
        let deadline = Instant::now() + Duration::from_secs(3);
        self.pending_message_queue.push_back((idx, deadline));
    }

    // Retransmit after timeout expired
    async fn send_internal(
        &mut self,
        tcp_packet: BytesMut,
        timeout: Option<Duration>,
    ) -> WriteResult {
        loop {
            let res = write(self.sock.clone(), tcp_packet.clone(), timeout).await;
            if res == WriteResult::Timeout {
                continue;
            }
            return res;
        }
    }

    async fn recv_packet(&mut self, timeout: Option<Duration>) -> ReadResult {
        // TODO: current implementation is not enough because it may occur massive packet copies
        // if user has many handlers. We should create receive handler which transports received message
        // to the destination handler.
        loop {
            let res = read(self.sock.clone(), timeout).await;
            match res {
                ReadResult::Success(buf) => {
                    let tcp_frame = parse_tcp_packet(buf);
                    if tcp_frame.is_err() {
                        continue;
                    }
                    if !self.session.on_recv_tcp_frame(&tcp_frame.unwrap()) {
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

    fn create_tcp_packet(&mut self, close: bool) -> BytesMut {
        let tcp_frame = self.session.create_next_frame(close).unwrap();
        let packet = TcpPacket::default()
            .set_tcp(tcp_frame.clone())
            .set_ipv4(self.sipaddr, self.dipaddr)
            .set_ether(self.smacaddr, self.dmacaddr)
            .build();
        packet
    }

    fn create_tcp_data_packet(
        &mut self,
        payload: BytesMut,
    ) -> Vec<(u32 /* exepcted ack num */, BytesMut)> {
        let tcp_frames = self.session.create_next_data_frame(payload).unwrap();
        let mut chunked_raw_frames = Vec::new();

        for frame in tcp_frames {
            let tcp_seq_num = frame.seq_num();
            let tcp_payload_len = frame.payload_length();
            let raw_packet = TcpPacket::default()
                .set_tcp(frame)
                .set_ipv4(self.sipaddr, self.dipaddr)
                .set_ether(self.smacaddr, self.dmacaddr)
                .build();
            chunked_raw_frames.push((tcp_seq_num + tcp_payload_len as u32, raw_packet));
        }

        chunked_raw_frames
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
