use crate::frames::tcp::TcpFrame;
use log::info;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    LastAck,
    CloseWait,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,

    // Custom states
    WaitSendAckToSynReceived,
    WaitSendAckToEstablished,
    WaitSendAckToCloseWait,
    WaitSendAckToClosing,
    WaitSendAckToTimeWait,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            State::Closed => write!(f, "Closed"),
            State::Listen => write!(f, "Listen"),
            State::SynSent => write!(f, "Syn Sent"),
            State::SynReceived => write!(f, "Syn Received"),
            State::Established => write!(f, "Established"),
            State::LastAck => write!(f, "LastAck"),
            State::CloseWait => write!(f, "CloseWait"),
            State::FinWait1 => write!(f, "FinWait1"),
            State::FinWait2 => write!(f, "FinWait2"),
            State::Closing => write!(f, "Closing"),
            State::TimeWait => write!(f, "TimeWait"),
            State::WaitSendAckToSynReceived => write!(f, "WaitSendAckToSynReceived"),
            State::WaitSendAckToEstablished => write!(f, "WaitSendAckToEstablished"),
            State::WaitSendAckToCloseWait => write!(f, "WaitSendAckToCloseWait"),
            State::WaitSendAckToClosing => write!(f, "WaitSendAckToClosing"),
            State::WaitSendAckToTimeWait => write!(f, "WaitSendAckToTimeWait"),
        }
    }
}

enum Event<'a> {
    SendFrame(&'a TcpFrame),
    ReceiveFrame(&'a TcpFrame),
    Timeout,
}

impl<'a> Event<'a> {
    pub fn is_send_frame(&self) -> bool {
        match *self {
            Event::SendFrame(_) => true,
            _ => false,
        }
    }

    pub fn is_recv_frame(&self) -> bool {
        match *self {
            Event::ReceiveFrame(_) => true,
            _ => false,
        }
    }

    pub fn is_timeout(&self) -> bool {
        match *self {
            Event::Timeout => true,
            _ => false,
        }
    }

    pub fn frame(&self) -> Option<&'a TcpFrame> {
        match *self {
            Event::SendFrame(frame) => Some(frame),
            Event::ReceiveFrame(frame) => Some(frame),
            _ => None,
        }
    }
}

// ref: https://datatracker.ietf.org/doc/html/rfc793
//
//                               +---------+ ---------\      active OPEN
//                               |  CLOSED |            \    -----------
//                               +---------+<---------\   \   create TCB
//                                 |     ^              \   \  snd SYN
//                    passive OPEN |     |   CLOSE        \   \
//                    ------------ |     | ----------       \   \ **(1)**
//                     create TCB  |     | delete TCB         \   \
//                                 V     |                      \   \
//                              +---------+            CLOSE    |    \
//                              |  LISTEN |          ---------- |     |
//                              +---------+          delete TCB |     |
//                   rcv SYN      |     |     SEND              |     |
//                  -----------   |     |    -------            |     V
// +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
// |         |<-----------------           ------------------>|         |
// |   SYN   |                    rcv SYN  **(2), (6)**       |   SYN   |
// |   RCVD  |<-----------------------------------------------|   SENT  |
// |         |                    snd ACK  **(3)**            |         |
// |         |------------------           -------------------|         |
// +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//  |           --------------   |     |   -----------
//  |                  x         |     |     snd ACK
//  | **(4)**                    V     V
//  |  CLOSE                   +---------+
//  | -------                  |  ESTAB  |
//  | snd FIN                  +---------+
//  |                   CLOSE    |     |    rcv FIN
//  V                  -------   |     |    -------
// +---------+          snd FIN  /       \   snd ACK          +---------+
// |  FIN    |<-----------------           ------------------>|  CLOSE  |
// | WAIT-1  |------------------                              |   WAIT  |
// +---------+         rcv FIN  \                             +---------+
// | rcv ACK of FIN   -------   |                            CLOSE  |
// | --------------   snd ACK   |                           ------- |
// |        x                   |                                   |
// V  **(5)**                   V                           snd FIN V
// +---------+                  +---------+                   +---------+
// |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
// +---------+                  +---------+                   +---------+
// |                rcv ACK of FIN |                 rcv ACK of FIN |
// |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
// |  -------              x       V    ------------        x       V
//  \ snd ACK               +---------+  delete TCB       +---------+
// ------------------------>|TIME WAIT|------------------>| CLOSED  |
//                          +---------+                   +---------+
//
pub trait TcpFiniteStateMachineCallbacks {
    // **(1)**
    fn on_syn_sent(&mut self, frame: &TcpFrame);

    // **(2)**
    fn on_wait_send_ack_to_established(&mut self, frame: &TcpFrame);

    // **(3)**
    fn on_established(&mut self, frame: &TcpFrame);

    // **(4)**
    fn on_fin_wait1(&mut self, frame: &TcpFrame);

    // **(5)**
    fn on_fin_wait2(&mut self, frame: &TcpFrame);

    // **(6)**
    fn on_syn_received(&mut self, frame: &TcpFrame);
}

pub struct TcpFiniteStateMachine<'a, T>
where
    T: TcpFiniteStateMachineCallbacks,
{
    state: State,
    callbacks: &'a T,
}

impl<'a, T> TcpFiniteStateMachine<'a, T>
where
    T: TcpFiniteStateMachineCallbacks,
{
    pub fn new(callbacks: &'a T) -> Self {
        Self {
            state: State::Closed,
            callbacks,
        }
    }

    pub fn get_state(&self) -> State {
        self.state
    }

    pub fn update(&mut self, event: Event) {
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
                State::SynSent => self.callbacks.on_syn_sent(frame),
                State::SynReceived => self.callbacks.on_syn_received(frame),
                State::Established => self.callbacks.on_established(frame),
                State::LastAck => {}
                State::CloseWait => {}
                State::FinWait1 => self.callbacks.on_fin_wait1(frame),
                State::FinWait2 => self.callbacks.on_fin_wait2(frame),
                State::Closing => {}
                State::TimeWait => {}
                State::WaitSendAckToSynReceived => {}
                State::WaitSendAckToEstablished => {
                    self.callbacks.on_wait_send_ack_to_established(frame)
                }
                State::WaitSendAckToCloseWait => {}
                State::WaitSendAckToClosing => {}
                State::WaitSendAckToTimeWait => {}
            }
        }

        info!("TCP Session changed state {} -> {}", prev_state, self.state)
    }
}
