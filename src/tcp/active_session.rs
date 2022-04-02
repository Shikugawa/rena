use crate::addresses::ipv4::Ipv4Addr;
use crate::frames::frame::Frame;
use crate::frames::tcp::TcpFrame;
use crate::tcp::state::State;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use log::info;
use rand::{thread_rng, Rng};

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
}

impl ActiveSession {
    pub fn new(sipaddr: Ipv4Addr, dipaddr: Ipv4Addr, sport: u16, dport: u16) -> Self {
        let isn = isn_gen();
        ActiveSession {
            state: State::Closed,
            sipaddr,
            dipaddr,
            sport,
            dport,
            next_seq_num: isn,
            next_ack_num: 0,
            init_seq_num: isn,
            sent_bytes: 0,
            window_size: 1000, // Is the initial window size correct?
        }
    }

    pub fn create_next_frame(&mut self, close: bool) -> Result<TcpFrame> {
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
            State::SynSent => {
                frame.set_ack();
            }
            State::Established => {
                if close {
                    frame.set_fin();
                    frame.set_ack();
                }
            }
            State::FinWait2 => {
                frame.set_ack();
            }
            State::CloseWait => {
                frame.set_fin();
            }
            State::LastAck => {
                frame.set_ack();
            }
            _ => return Err(anyhow!("failed to create TCP frame")),
        }

        Ok(frame)
    }

    pub fn create_next_data_frame(&mut self, payload: BytesMut) -> Result<TcpFrame> {
        if self.state != State::Established {
            return Err(anyhow!("session state must be ESTABLISHED"));
        }
        let mut frame = TcpFrame::new(
            self.sipaddr,
            self.dipaddr,
            self.sport,
            self.dport,
            self.next_seq_num,
            self.next_ack_num,
            self.window_size,
            payload,
        );
        frame.set_ack();
        Ok(frame)
    }

    pub fn on_send_tcp_frame(&mut self, frame: &TcpFrame) {
        match self.state {
            State::Closed => {
                self.update_state(State::SynSent);

                // In handshake, payload bytes should be treated as 1 bytes.
                let payload_bytes = 1;
                self.update_sent_bytes(payload_bytes);
                self.update_next_seq_num(payload_bytes);
            }
            State::SynSent => {
                self.update_state(State::Established);
            }
            State::Established => {
                if frame.is_fin() {
                    self.update_state(State::FinWait1);

                    // In close handshake, payload bytes should be treated as 1 bytes.
                    let payload_bytes = 1;
                    self.update_sent_bytes(payload_bytes);
                    self.update_next_seq_num(payload_bytes);
                } else {
                    let payload_bytes = frame.payload_length() as u32;
                    self.update_sent_bytes(payload_bytes);
                    self.update_next_seq_num(payload_bytes);
                }
            }
            State::FinWait2 => {
                self.update_state(State::TimeWait);
            }
            State::CloseWait => {
                self.update_state(State::LastAck);
            }
            _ => {}
        }
    }

    pub fn on_recv_tcp_frame(&mut self, frame: &TcpFrame) -> bool {
        // If received frame is not belonging to this stream. Session disposes it.
        if !self.is_recv_frame_in_this_session(frame) {
            return false;
        }

        let mut valid = true;
        match self.state {
            State::SynSent => {
                if frame.is_rst() {
                    self.update_state(State::Closed);
                } else if frame.is_ack() && frame.is_syn() {
                    self.update_next_ack_num(frame.seq_num() + 1);
                } else {
                    valid = false;
                }
            }
            State::Established => {
                if frame.is_fin() && frame.is_ack() {
                    self.update_state(State::CloseWait);
                } else if frame.is_ack() {
                    self.update_next_ack_num(frame.seq_num() + frame.payload_length() as u32);
                } else {
                    valid = false;
                }
            }
            State::FinWait1 => {
                if frame.is_fin() && frame.is_ack() {
                    self.update_state(State::FinWait2);
                    self.update_next_ack_num(frame.seq_num() + 1);
                } else {
                    valid = false;
                }
            }
            _ => valid = false,
        };

        valid
    }

    pub fn stream_id(&self) -> u32 {
        // we treat ISN as the stream identification. Expecting no collision of it.
        self.init_seq_num
    }

    pub fn is_recv_frame_in_this_session(&self, frame: &TcpFrame) -> bool {
        // we treat ISN as the stream identification. Expecting no collision of it.
        (frame.ack_num() - self.sent_bytes) == self.init_seq_num
    }

    pub fn state(&self) -> State {
        self.state
    }

    fn update_state(&mut self, next_state: State) {
        let prev_state = self.state;
        self.state = next_state;
        info!("TCP Session changed state {} -> {}", prev_state, self.state)
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
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.update_state(State::Closed);
    }
}
