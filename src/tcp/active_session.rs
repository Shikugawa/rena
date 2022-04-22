use crate::addresses::ipv4::Ipv4Addr;
use crate::frames::frame::Frame;
use crate::frames::tcp::TcpFrame;
use crate::tcp::state::{Event, State};
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use log::info;
use rand::{thread_rng, Rng};
use std::collections::{HashMap, HashSet};

// TODO: follow spec
fn isn_gen() -> u32 {
    let mut rng = thread_rng();
    rng.gen()
}

pub struct ActiveSession {
    state: State,
    sipaddr: Ipv4Addr,
    dipaddr: Ipv4Addr,
    sport: u16,
    dport: u16,
    next_seq_num: u32,
    next_ack_num: u32,
    init_seq_num: u32,
    sent_bytes: u32,
    window_size: u16,
    mss: u16,
    waiting_acks: HashSet<u32>,

    // acknum_counter is used to accumulate local-side segment retransmission,
    // which is exepcted to be used after the count is larger than 4.
    acknum_counter: HashMap<u32, usize>,
}

impl ActiveSession {
    pub fn new(sipaddr: Ipv4Addr, dipaddr: Ipv4Addr, sport: u16, dport: u16) -> Self {
        let isn = isn_gen();
        Self {
            sipaddr,
            dipaddr,
            sport,
            dport,
            next_seq_num: isn,
            next_ack_num: 0,
            init_seq_num: isn,
            sent_bytes: 0,
            window_size: 1000,
            mss: 1460,
            waiting_acks: HashSet::new(),
            acknum_counter: HashMap::new(),
            state: State::Closed,
        }
    }

    pub fn create_next_frame(&mut self, close: bool, should_wait_ack: bool) -> Result<TcpFrame> {
        let mut frame = TcpFrame::new(
            self.sipaddr,
            self.dipaddr,
            self.sport,
            self.dport,
            self.next_seq_num,
            self.next_ack_num,
            self.window_size,
            BytesMut::new(),
        );

        match self.state {
            State::Closed => {
                frame.set_syn();
            }
            State::WaitSendAckToEstablished => {
                frame.set_ack();
            }
            State::Established => {
                if close {
                    frame.set_fin();
                    frame.set_ack();
                }
            }
            State::WaitSendAckToTimeWait => {
                frame.set_ack();
            }
            State::CloseWait => {
                frame.set_fin();
            }
            _ => return Err(anyhow!("failed to create TCP frame")),
        }

        if should_wait_ack {
            let waiting_ack = frame.seq_num() + 1;
            self.waiting_acks.insert(waiting_ack);
        }

        self.on_send(&frame);

        Ok(frame)
    }

    pub fn create_next_data_frame(&mut self, payload: BytesMut) -> Result<Vec<TcpFrame>> {
        if self.state != State::Established {
            return Err(anyhow!("session state must be ESTABLISHED"));
        }
        let chunked_payloads = payload.chunks(self.mss as usize);
        let mut frames = Vec::new();

        for chunk in chunked_payloads {
            let mut frame = TcpFrame::new(
                self.sipaddr,
                self.dipaddr,
                self.sport,
                self.dport,
                self.next_seq_num,
                self.next_ack_num,
                self.window_size,
                BytesMut::from(chunk),
            );
            frame.set_ack();

            let waiting_ack = frame.seq_num() + (frame.payload_length() as u32);
            self.waiting_acks.insert(waiting_ack);
            self.on_send(&frame);

            frames.push(frame);
        }

        Ok(frames)
    }

    pub fn on_recv(&mut self, frame: &TcpFrame) -> bool {
        let ack_num = frame.ack_num();
        if !self.waiting_acks.contains(&ack_num) {
            return false;
        }

        self.waiting_acks.remove(&ack_num);

        self.inc_acknum_counter(&ack_num);
        self.update(Event::ReceiveFrame(frame));

        true
    }

    pub fn stream_id(&self) -> u32 {
        // we treat ISN as the stream identification. Expecting no collision of it.
        self.init_seq_num
    }

    pub fn can_send_packet_num(&self) -> usize {
        (self.window_size / self.mss) as usize
    }

    fn on_send(&mut self, frame: &TcpFrame) {
        self.update(Event::SendFrame(frame));
    }

    fn inc_acknum_counter(&mut self, ack_num: &u32) {
        if !self.acknum_counter.contains_key(&ack_num) {
            self.acknum_counter.insert(*ack_num, 0);
        }
        let next_val = self.acknum_counter.get(&ack_num).unwrap() + 1;
        self.acknum_counter.insert(*ack_num, next_val);
    }

    fn update_next_seq_num(&mut self, num: u32) {
        let tmp = self.next_seq_num - self.init_seq_num;
        self.next_seq_num += num;
        info!(
            "seq (offset) number updated {} -> {}",
            tmp,
            self.next_seq_num - self.init_seq_num
        );
    }

    fn update_next_ack_num(&mut self, num: u32) {
        let tmp = self.next_ack_num;
        self.next_ack_num = num;
        info!("ack number updated {} -> {}", tmp, self.next_ack_num);
    }

    fn update_sent_bytes(&mut self, num: u32) {
        let tmp = self.sent_bytes;
        self.sent_bytes += num;
        info!("sent bytes updated {} -> {}", tmp, self.sent_bytes);
    }

    fn update_window_size(&mut self, num: u16) {
        let tmp = self.window_size;
        self.window_size = num;
        info!("window size updated {} -> {}", tmp, self.window_size);
    }

    // TODO: need refactor
    fn update(&mut self, event: Event) {
        match self.state {
            State::Closed => {
                if event.frame().is_none() {
                    self.update_state(event.frame(), State::Listen);
                } else if event.frame().is_some() && event.frame().unwrap().is_syn() {
                    self.update_state(event.frame(), State::SynSent)
                }
            }
            State::Listen => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_syn() {
                    self.update_state(event.frame(), State::WaitSendAckToSynReceived);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_syn() {
                    self.update_state(event.frame(), State::SynSent);
                }
            }
            State::SynSent => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_syn() && frame_internal.is_ack() {
                    self.update_state(event.frame(), State::WaitSendAckToEstablished);
                    return;
                }

                if event.is_recv_frame() && frame_internal.is_syn() {
                    self.update_state(event.frame(), State::SynReceived);
                    return;
                }
            }
            State::SynReceived => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_syn() && frame_internal.is_ack() {
                    self.update_state(event.frame(), State::Established);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::FinWait1);
                    return;
                }
            }
            State::Established => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::WaitSendAckToCloseWait);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::FinWait1);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_ack() {
                    let payload_bytes = frame_internal.payload_length() as u32;
                    self.update_sent_bytes(payload_bytes);
                    self.update_next_seq_num(payload_bytes);
                }
            }
            State::CloseWait => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::LastAck);
                    return;
                }
            }
            State::LastAck => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::Closed);
                    return;
                }
            }
            State::FinWait1 => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_ack() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::FinWait2);
                    return;
                }

                if event.is_recv_frame() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::WaitSendAckToClosing);
                    return;
                }
            }
            State::FinWait2 => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::WaitSendAckToTimeWait);
                    return;
                }
            }
            State::Closing => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_ack() && frame_internal.is_fin() {
                    self.update_state(event.frame(), State::TimeWait);
                    return;
                }
            }
            State::TimeWait => {
                if event.is_timeout() {
                    self.update_state(None, State::Closed);
                }
            }
            State::WaitSendAckToSynReceived => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(event.frame(), State::SynReceived);
                }
            }
            State::WaitSendAckToEstablished => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(event.frame(), State::Established);
                }
            }
            State::WaitSendAckToCloseWait => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(event.frame(), State::CloseWait);
                }
            }
            State::WaitSendAckToClosing => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(event.frame(), State::Closing);
                }
            }
            State::WaitSendAckToTimeWait => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(event.frame(), State::TimeWait);
                }
            }
        }
    }

    fn update_state(&mut self, frame: Option<&TcpFrame>, next_state: State) {
        let prev_state = self.state;
        self.state = next_state;

        if let Some(frame) = frame {
            match self.state {
                State::Closed => {}
                State::Listen => {}
                State::SynSent => self.on_syn_sent(frame),
                State::SynReceived => self.on_syn_received(frame),
                State::Established => self.on_established(frame),
                State::LastAck => {}
                State::CloseWait => {}
                State::FinWait1 => self.on_fin_wait1(frame),
                State::FinWait2 => self.on_fin_wait2(frame),
                State::Closing => {}
                State::TimeWait => {}
                State::WaitSendAckToSynReceived => {}
                State::WaitSendAckToEstablished => self.on_wait_send_ack_to_established(frame),
                State::WaitSendAckToCloseWait => {}
                State::WaitSendAckToClosing => {}
                State::WaitSendAckToTimeWait => {}
            }
        }

        info!("TCP Session changed state {} -> {}", prev_state, self.state)
    }

    fn on_syn_sent(&mut self, _: &TcpFrame) {
        // In handshake, payload bytes should be treated as 1 bytes.
        let payload_bytes = 1;
        self.update_sent_bytes(payload_bytes);
        self.update_next_seq_num(payload_bytes);
    }

    fn on_wait_send_ack_to_established(&mut self, frame: &TcpFrame) {
        self.update_next_ack_num(frame.seq_num() + 1);
        self.update_window_size(frame.window_size());
    }

    fn on_established(&mut self, _: &TcpFrame) {}

    fn on_fin_wait1(&mut self, _: &TcpFrame) {
        // In close handshake, payload bytes should be treated as 1 bytes.
        let payload_bytes = 1;
        self.update_sent_bytes(payload_bytes);
        self.update_next_seq_num(payload_bytes);
    }

    fn on_fin_wait2(&mut self, frame: &TcpFrame) {
        self.update_next_ack_num(frame.seq_num() + 1);
    }

    fn on_syn_received(&mut self, frame: &TcpFrame) {
        self.update_next_ack_num(frame.seq_num() + 1);
    }
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        // TODO: send drop packet in close
        // self.update_state(State::Closed);
    }
}
