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
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration, Instant};

pub struct LocalHandler {
    smacaddr: MacAddr,
    dmacaddr: MacAddr,
    sipaddr: Ipv4Addr,
    dipaddr: Ipv4Addr,
    session: ActiveSession,
    sock: Arc<dyn DatalinkReaderWriter>,

    // pending_buffer is used to hold inflight segments.
    // If retransmission which is triggered by 1) duplicated ack_num, 2) ack timeout
    // is occurred, the number of packet will be enqueued repeatedly here.
    pending_buffer: HashMap<u32, Instant>,

    // acknum_counter is used to accumulate local-side segment retransmission,
    // which is exepcted to be used after the count is larger than 4.
    acknum_counter: HashMap<u32, usize>,
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
            pending_buffer: HashMap::new(),
            acknum_counter: HashMap::new(),
        };
        local_handler.handshake().await;
        Ok(local_handler)
    }

    pub async fn send(&mut self, payload: BytesMut) -> Result<()> {
        let raw_packets = self.create_tcp_data_packet(payload);
        let mut acknum_idx_table: HashMap<u32, usize> = HashMap::new();

        // Construct reverse loopup table expected_ack_num -> idx
        for (i, entry) in raw_packets.iter().enumerate() {
            let ack_num = entry.0.clone();
            acknum_idx_table.insert(ack_num, i);
        }

        let mut next_idx = 0;
        let buf_size = min(self.session.send_buf_size(), raw_packets.len());

        // Init data send state
        self.pending_buffer = HashMap::with_capacity(buf_size);
        self.acknum_counter = HashMap::new();

        // Initial flight
        while next_idx != buf_size {
            self.send_data_internal(raw_packets[next_idx].0, raw_packets[next_idx].1.clone())
                .await;
            next_idx += 1;
        }

        let mut interval = interval(Duration::from_secs(1));

        // Wait responses and handle retransmission
        while next_idx < raw_packets.len() {
            tokio::select! {
                mut instant = interval.tick() => {
                    for (ack_num, deadline) in self.pending_buffer.iter_mut() {
                        if deadline > &mut instant {
                            let packet = raw_packets[acknum_idx_table[ack_num]].1.clone();

                            write(self.sock.clone(), packet, None).await;
                            // TODO: fix backoff timeout
                            let new_deadline = Instant::now() + Duration::from_secs(3);
                            *deadline = new_deadline;
                        }
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

                            let recvd_ack_num = tcp_frame.ack_num();
                            if !self.pending_buffer.contains_key(&recvd_ack_num) {
                                continue;
                            }

                            if !self.session.on_recv_tcp_frame(&tcp_frame) {
                                continue;
                            }

                            self.pending_buffer.remove(&recvd_ack_num);
                            next_idx += 1;

                            self.send_data_internal(raw_packets[next_idx].0, raw_packets[next_idx].1.clone()).await;

                            // Manipulate acknum counter and prepare for retransmission
                            self.inc_acknum_counter(recvd_ack_num);
                            if self.should_retransmit(recvd_ack_num) {
                                unimplemented!()
                            }
                        }
                        ReadResult::Timeout => {
                            unimplemented!()
                        }
                    }
                }
            }
        }

        self.pending_buffer.clear();
        self.acknum_counter.clear();
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

    async fn send_data_internal(&mut self, acknum_expected: u32, packet: BytesMut) {
        write(self.sock.clone(), packet, None).await;
        // TODO: fix backoff timeout
        let deadline = Instant::now() + Duration::from_secs(3);
        self.pending_buffer.insert(acknum_expected, deadline);
    }

    fn inc_acknum_counter(&mut self, ack_num: u32) {
        if !self.acknum_counter.contains_key(&ack_num) {
            self.acknum_counter.insert(ack_num, 0);
        }
        let next_val = self.acknum_counter.get(&ack_num).unwrap() + 1;
        self.acknum_counter.insert(ack_num, next_val);
    }

    fn should_retransmit(&self, ack_num: u32) -> bool {
        if !self.acknum_counter.contains_key(&ack_num) {
            return false;
        }
        self.acknum_counter[&ack_num] >= 4
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
