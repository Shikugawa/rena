use crate::tcp::state::State;
use crate::frames::tcp::TcpFrame;
use log::info;

pub struct PassiveSession {
  state: State,
  listen_port: u16
}

impl PassiveSession {
  pub fn new(listen_port: u16) -> Self {
    Self {
      state: State::Closed,
      listen_port
    }
  }

  pub fn start_listen(&mut self) {
    if self.state == State::Closed {
      self.state = State::Listen;
    }
  }

  pub fn on_recv_tcp_frame(&mut self, frame: &TcpFrame) {
    match self.state {
      State::Listen => {
        self.update_state(State::SynReceived);
      },
      State::SynReceived => {
        self.update_state(State::Established);
      },
      State::Established => {
        if frame.is_fin() {
          self.update_state(State::CloseWait);
        }
      },
      State::FinWait1 => {
        if frame.is_fin() && frame.is_ack() {
          self.update_state(State::FinWait2)
        } else if frame.is_fin() {
          self.update_state(State::Closing);
        }
      },
      State::FinWait2 => {
        self.update_state(State::TimeWait);
      }
      State::LastAck => {
        self.update_state(State::Closed);
      }
      _ => {}
    }
  }

  fn update_state(&mut self, next_state: State) {
    let prev_state = self.state;
    self.state = next_state;
    info!("TCP Session changed state {} -> {}", prev_state, self.state)
  }
}
