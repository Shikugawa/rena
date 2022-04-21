use crate::addresses::ipv4::Ipv4Addr;
use crate::frames::frame::Frame;
use crate::frames::tcp::TcpFrame;
use crate::tcp::finite_state_machine::State;
// use crate::tcp::finite_state_machine::TcpFiniteStateMachineCallbacks;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use log::info;
use rand::{thread_rng, Rng};
use std::collections::{HashMap, HashSet};
// use super::finite_state_machine::Event;
// use super::finite_state_machine::TcpFiniteStateMachine;

// TODO: follow spec
fn isn_gen() -> u32 {
    let mut rng = thread_rng();
    rng.gen()
}

pub struct ActiveSession {
    // state_machine: Option<TcpFiniteStateMachine<Self>>,
    state: Box<dyn TcpState>,
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

// impl TcpFiniteStateMachineCallbacks for ActiveSession {
//     fn on_syn_sent(&mut self, _: &TcpFrame) {
//         // In handshake, payload bytes should be treated as 1 bytes.
//         let payload_bytes = 1;
//         self.update_sent_bytes(payload_bytes);
//         self.update_next_seq_num(payload_bytes);
//     }

//     fn on_wait_send_ack_to_established(&mut self, frame: &TcpFrame) {
//         self.update_next_ack_num(frame.seq_num() + 1);
//         self.update_window_size(frame.window_size());
//     }

//     fn on_established(&mut self, _: &TcpFrame) {}

//     fn on_fin_wait1(&mut self, _: &TcpFrame) {
//         // In close handshake, payload bytes should be treated as 1 bytes.
//         let payload_bytes = 1;
//         self.update_sent_bytes(payload_bytes);
//         self.update_next_seq_num(payload_bytes);
//     }

//     fn on_fin_wait2(&mut self, frame: &TcpFrame) {
//         self.update_next_ack_num(frame.seq_num() + 1);
//     }

//     fn on_syn_received(&mut self, frame: &TcpFrame) {
//         self.update_next_ack_num(frame.seq_num() + 1);
//     }
// }

trait TcpState {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState>;

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState>;

    fn open(&mut self) -> Box<dyn TcpState>;

    fn close(&mut self) -> Box<dyn TcpState>;
}

struct Closed;

impl TcpState for Closed {
    fn recv(&mut self, _: &TcpFrame, _: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        // In handshake, payload bytes should be treated as 1 bytes.
        let payload_bytes = 1;
        session.update_sent_bytes(payload_bytes);
        session.update_next_seq_num(payload_bytes);
        Box::new(SynSent {})
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        Box::new(Listen {})
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct Listen;

impl TcpState for Listen {
    fn recv(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        unimplemented!()
    }

    fn sent(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        unimplemented!()
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        Box::new(Closed {})
    }
}

struct SynSent;

impl TcpState for SynSent {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_syn() && frame.is_ack() {
            return Box::new(WaitSendAckToEstablished {});
        }

        if frame.is_syn() {
            return Box::new(WaitSendAckToSynReceived {});
        }

        panic!("not reached")
    }

    fn sent(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct WaitSendAckToSynReceived;

impl TcpState for WaitSendAckToSynReceived {
    fn recv(&mut self, _: &TcpFrame, _: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_ack() {
            return Box::new(SynReceived {});
        }

        panic!("not reached")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct SynReceived;

impl TcpState for SynReceived {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_syn() && frame.is_ack() {
            return Box::new(Established {});
        }

        panic!("not reached")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() {
            return Box::new(FinWait1 {});
        }

        panic!("not reached")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct WaitSendAckToEstablished;

impl TcpState for WaitSendAckToEstablished {
    fn recv(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_ack() {
            return Box::new(Established {});
        }

        panic!("undefined state change")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct Established;

impl TcpState for Established {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() {
            return Box::new(WaitSendAckToCloseWait {});
        }

        panic!("not reached")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() {
            return Box::new(FinWait1 {});
        }

        panic!("not reached")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct WaitSendAckToCloseWait;

impl TcpState for WaitSendAckToCloseWait {
    fn recv(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_ack() {
            return Box::new(CloseWait {});
        }

        panic!("undefined state change")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct CloseWait;

impl TcpState for CloseWait {
    fn recv(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() {
            return Box::new(LastAck {});
        }

        panic!("undefined state change")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct FinWait1;

impl TcpState for FinWait1 {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() && frame.is_ack() {
            return Box::new(FinWait2 {});
        }

        if frame.is_fin() {
            return Box::new(Closing {});
        }

        panic!("not reached")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("not reached")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}
struct FinWait2;

impl TcpState for FinWait2 {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() {
            return Box::new(WaitSendAckToTimeWait {});
        }

        panic!("not reached")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("not reached")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct WaitSendAckToClosing;

impl TcpState for WaitSendAckToClosing {
    fn recv(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_ack() {
            return Box::new(Closing {});
        }

        panic!("undefined state change")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct Closing;

impl TcpState for Closing {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() && frame.is_ack() {
            return Box::new(TimeWait {});
        }

        panic!("not reached")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("not reached")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct LastAck;

impl TcpState for LastAck {
    fn recv(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_fin() && frame.is_ack() {
            return Box::new(Closed {});
        }

        panic!("not reached")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("not reached")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct WaitSendAckToTimeWait;

impl TcpState for WaitSendAckToTimeWait {
    fn recv(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        if frame.is_ack() {
            return Box::new(Closing {});
        }

        panic!("undefined state change")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

struct TimeWait;

impl TcpState for TimeWait {
    fn recv(&mut self, _: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn sent(&mut self, frame: &TcpFrame, session: &mut ActiveSession) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn open(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }

    fn close(&mut self) -> Box<dyn TcpState> {
        panic!("undefined state change")
    }
}

impl ActiveSession {
    pub fn new(sipaddr: Ipv4Addr, dipaddr: Ipv4Addr, sport: u16, dport: u16) -> Self {
        let isn = isn_gen();
        let mut session = ActiveSession {
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
            state: Box::new(SynSent {}),
        };
        // Box::new(session);
        // session.state_machine = Some(TcpFiniteStateMachine::new(Box::new(&session)));
        session
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

        match self.state() {
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

        let waiting_ack = frame.seq_num() + 1;
        self.waiting_acks.insert(waiting_ack);

        self.on_send(&frame);

        Ok(frame)
    }

    pub fn create_next_data_frame(&mut self, payload: BytesMut) -> Result<Vec<TcpFrame>> {
        if self.state() != State::Established {
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

        // self.state_machine
        //     .as_mut()
        //     .unwrap()
        //     .update(Event::ReceiveFrame(frame));
        true
    }

    pub fn stream_id(&self) -> u32 {
        // we treat ISN as the stream identification. Expecting no collision of it.
        self.init_seq_num
    }

    pub fn can_send_packet_num(&self) -> usize {
        (self.window_size / self.mss) as usize
    }

    fn state(&self) -> State {
        State::Closed
        // self.state_machine.unwrap().get_state()
    }

    fn on_send(&mut self, frame: &TcpFrame) {
        // self.state_machine
        //     .as_mut()
        //     .unwrap()
        //     .update(Event::SendFrame(frame));
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
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        // TODO: send drop packet in close
        // self.update_state(State::Closed);
    }
}
