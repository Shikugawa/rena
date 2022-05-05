use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::frames::frame::Frame;
use crate::frames::tcp::TcpFrame;
use crate::tcp::active_session::ActiveSession;
use anyhow::Result;
use bytes::BytesMut;
use log::info;
use rand::{thread_rng, Rng};
use std::cmp::min;
use std::collections::HashMap;
use std::collections::VecDeque;
use tokio::time::{interval, Duration, Instant};

use super::storage_wrapper::IoThreadLayersStorageWrapper;

pub struct TcpLayer {
    sipaddr: Ipv4Addr,
    sessions: HashMap<u16, ActiveSession>,
    layers_storage: IoThreadLayersStorageWrapper,

    // pending_message_queue is used to hold inflight segments.
    // If retransmission which is triggered by 1) duplicated ack_num, 2) ack timeout
    // is occurred, the number of packet will be enqueued repeatedly here.
    pending_message_queue: VecDeque<(usize, Instant)>,
}

impl TcpLayer {
    pub fn new(layers_storage: IoThreadLayersStorageWrapper, sipaddr: Ipv4Addr) -> Self {
        Self {
            layers_storage,
            sessions: HashMap::new(),
            sipaddr,
            pending_message_queue: VecDeque::new(),
        }
    }

    pub async fn handshake(&mut self, dipaddr: Ipv4Addr, dport: u16) {
        let mut rand_gen = thread_rng();

        // Same as linux's default range
        // https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables
        let sport: u16 = rand_gen.gen_range(32768..60999);

        let mut new_session = ActiveSession::new(self.sipaddr, dipaddr, sport, dport);
        let stream_id = new_session.stream_id();
        info!("session {} start handshake", stream_id);

        // send SYN
        let syn_frame = new_session.create_next_frame(false, true).unwrap();
        self.send_internal(dipaddr, syn_frame).await;

        // wait ACK
        let frame = self.wait_valid_frame(&mut new_session, None).await;
        if frame.is_err() {
            return;
        }
        new_session.on_recv(&frame.unwrap());

        // send SYN
        let syn_frame = new_session.create_next_frame(false, false).unwrap();
        self.send_internal(dipaddr, syn_frame).await;
    }

    pub async fn close_session(&mut self, sess: &mut ActiveSession, dipaddr: Ipv4Addr, dport: u16) {
        let stream_id = sess.stream_id();
        info!("session {} start handshake", stream_id);

        // send SYN
        let syn_frame = sess.create_next_frame(true, true).unwrap();
        self.send_internal(dipaddr, syn_frame).await;

        // wait ACK
        let frame = self.wait_valid_frame(sess, None).await;
        if frame.is_err() {
            return;
        }
        sess.on_recv(&frame.unwrap());

        // send SYN
        let syn_frame = sess.create_next_frame(false, false).unwrap();
        self.send_internal(dipaddr, syn_frame).await;
    }

    pub async fn get_session(&mut self, dport: u16) -> Option<&mut ActiveSession> {
        if !self.sessions.contains_key(&dport) {
            return None;
        }
        Some(self.sessions.get_mut(&dport).unwrap())
    }

    pub async fn send(&mut self, sess: &mut ActiveSession, dipaddr: Ipv4Addr, payload: BytesMut) {
        let tcp_frames = self.create_tcp_data_packet(sess, payload);

        let mut next_idx = 0;
        let pending_buf_size = min(sess.can_send_packet_num(), tcp_frames.len());

        // Init data send state
        self.pending_message_queue = VecDeque::with_capacity(pending_buf_size);

        // Initial flight
        while next_idx < pending_buf_size {
            let frame = tcp_frames[next_idx].1.clone();
            self.send_data_internal(next_idx, dipaddr, frame).await;
            next_idx += 1;
        }

        let mut interval = interval(Duration::from_secs(1));

        // Wait ACKs for pending messages. If it succeeded, it executes
        // 1) If it has remaining segment, handler sends it.
        // 2) If ACKs can't be received via timeout, handler execute transmission
        //    for failed SYN message immediately.
        while !self.pending_message_queue.is_empty() {
            tokio::select! {
                instant = interval.tick() => {
                    loop {
                        let (_, deadline) = self.pending_message_queue.front().unwrap();
                        if instant < *deadline {
                            break;
                        }

                        let (idx, _) = self.pending_message_queue.pop_front().unwrap();
                        let frame = tcp_frames[idx].1.clone();

                        self.send_data_internal(idx, dipaddr, frame).await;
                    }
                },
                res = self.poll() => {
                    match res {
                        Some(tcp_frame) => {
                            self.pending_message_queue.pop_front().unwrap();
                            if !sess.on_recv(&tcp_frame) {
                                continue;
                            }

                            if next_idx >= tcp_frames.len() {
                                continue;
                            }

                            next_idx += 1;

                            let frame = tcp_frames[next_idx].1.clone();
                            self.send_data_internal(next_idx, dipaddr, frame).await;
                        }
                        None => {}
                    }
                }
            }
        }

        info!("segment write succeded");
        self.pending_message_queue.clear();
    }

    async fn poll(&mut self) -> Option<TcpFrame> {
        let frame = self.layers_storage.ipv4_layer().poll().await;

        if frame.is_none() {
            return None;
        }

        let frame = frame.unwrap();

        if frame.protocol().is_tcp() {
            Some(frame.tcp_payload().unwrap().to_owned())
        } else {
            None
        }
    }

    async fn send_internal(&mut self, dipaddr: Ipv4Addr, frame: TcpFrame) {
        self.layers_storage
            .ipv4_layer()
            .send_tcp_frame(dipaddr, frame)
            .await;
    }

    // TODO: handle timeout if local transmission failed
    async fn send_data_internal(&mut self, idx: usize, dipaddr: Ipv4Addr, frame: TcpFrame) {
        self.send_internal(dipaddr, frame).await;

        // TODO: fix backoff timeout
        let deadline = Instant::now() + Duration::from_secs(3);
        self.pending_message_queue.push_back((idx, deadline));
    }

    // TODO: timeout
    async fn wait_valid_frame(
        &mut self,
        sess: &mut ActiveSession,
        timeout: Option<Duration>,
    ) -> Result<TcpFrame> {
        loop {
            if let Some(tcp_frame) = self.poll().await {
                if sess.is_valid_frame(&tcp_frame) {
                    return Ok(tcp_frame);
                }
            } else {
                continue;
            }
        }
    }

    fn create_tcp_data_packet(
        &self,
        sess: &mut ActiveSession,
        payload: BytesMut,
    ) -> Vec<(u32 /* exepcted ack num */, TcpFrame)> {
        let tcp_frames = sess.create_next_data_frame(payload).unwrap();
        let mut chunked_raw_frames = Vec::new();

        for frame in tcp_frames {
            let tcp_seq_num = frame.seq_num();
            let tcp_payload_len = frame.payload_length();
            chunked_raw_frames.push((tcp_seq_num + tcp_payload_len as u32, frame));
        }

        chunked_raw_frames
    }
}
