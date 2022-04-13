use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::datalink::rawsock::RawSock;
use crate::datalink::traits::DatalinkReaderWriter;
use crate::datalink::writer::{write, WriteResult};
use crate::frames::frame::Frame;
use crate::frames::tcp::TcpFrame;
use crate::packet::TcpPacket;
use crate::tcp::active_session::ActiveSession;
use crate::tcp::subscriber::Subscriber;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use log::{info, warn};
use std::cmp::min;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::mpsc;
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
    rx: Option<mpsc::Receiver<TcpFrame>>,
}

impl Subscriber for LocalHandler {
    fn subscribe(&mut self, rx: mpsc::Receiver<TcpFrame>) {
        self.rx = Some(rx);
    }
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
            rx: None,
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
            let rx = self.rx.as_mut().unwrap();

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
                res = rx.recv() => {
                    match res {
                        Some(tcp_frame) => {
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
                        None => {}
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

    // TODO: timeout
    async fn recv_packet(&mut self, timeout: Option<Duration>) -> bool {
        loop {
            let rx = self.rx.as_mut().unwrap();
            let res = rx.recv().await;
            match res {
                Some(tcp_frame) => {
                    if !self.session.on_recv_tcp_frame(&tcp_frame) {
                        continue;
                    }
                    return true;
                }
                None => return false,
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
