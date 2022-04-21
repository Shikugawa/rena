use crate::frames::tcp::TcpFrame;
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

pub enum Event<'a> {
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
