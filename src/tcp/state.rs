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

pub trait TcpFiniteStateMachineCallbacks {
    fn on_syn_sent(&mut self);
}

struct FiniteStateMachine<'a> {
    state: State,
    callbacks: &'a dyn TcpFiniteStateMachineCallbacks,
}

impl<'a> FiniteStateMachine<'a> {
    pub fn update(&mut self, event: Event) {
        match self.state {
            State::Closed => {
                if event.frame().is_none() {
                    self.update_state(State::Listen);
                } else if event.frame().is_some() && event.frame().unwrap().is_syn() {
                    self.update_state(State::SynSent)
                }
            }
            State::Listen => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_syn() {
                    self.update_state(State::WaitSendAckToSynReceived);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_syn() {
                    self.update_state(State::SynSent);
                }
            }
            State::SynSent => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_syn() {
                    self.update_state(State::SynReceived);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_syn() && frame_internal.is_ack() {
                    self.update_state(State::WaitSendAckToEstablished);
                    return;
                }
            }
            State::SynReceived => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_syn() && frame_internal.is_ack() {
                    self.update_state(State::Established);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_fin() {
                    self.update_state(State::FinWait1);
                    return;
                }
            }
            State::Established => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_fin() {
                    self.update_state(State::WaitSendAckToCloseWait);
                    return;
                }

                if event.is_send_frame() && frame_internal.is_fin() {
                    self.update_state(State::FinWait1);
                    return;
                }
            }
            State::CloseWait => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_fin() {
                    self.update_state(State::LastAck);
                    return;
                }
            }
            State::LastAck => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() && frame_internal.is_fin() {
                    self.update_state(State::Closed);
                    return;
                }
            }
            State::FinWait1 => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_ack() && frame_internal.is_fin() {
                    self.update_state(State::FinWait2);
                    return;
                }

                if event.is_recv_frame() && frame_internal.is_fin() {
                    self.update_state(State::WaitSendAckToClosing);
                    return;
                }
            }
            State::FinWait2 => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_fin() {
                    self.update_state(State::WaitSendAckToTimeWait);
                    return;
                }
            }
            State::Closing => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_recv_frame() && frame_internal.is_ack() && frame_internal.is_fin() {
                    self.update_state(State::TimeWait);
                    return;
                }
            }
            State::TimeWait => {
                if event.is_timeout() {
                    self.update_state(State::Closed);
                }
            }
            State::WaitSendAckToSynReceived => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(State::SynReceived);
                }
            }
            State::WaitSendAckToEstablished => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(State::Established);
                }
            }
            State::WaitSendAckToCloseWait => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(State::CloseWait);
                }
            }
            State::WaitSendAckToClosing => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(State::Closing);
                }
            }
            State::WaitSendAckToTimeWait => {
                if event.frame().is_none() {
                    return;
                }
                let frame_internal = event.frame().unwrap();

                if event.is_send_frame() && frame_internal.is_ack() {
                    self.update_state(State::TimeWait);
                }
            }
        }
    }

    fn update_state(&mut self, next_state: State) {
        let prev_state = self.state;
        self.state = next_state;
        info!("TCP Session changed state {} -> {}", prev_state, self.state)
    }
}
