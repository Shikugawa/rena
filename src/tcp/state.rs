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
            _ => write!(f, "undefined"),
        }
    }
}
