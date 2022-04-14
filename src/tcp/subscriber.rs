use tokio::sync::mpsc;

use crate::frames::tcp::TcpFrame;

pub trait Subscriber {
    fn subscribe(&mut self, rx: mpsc::Receiver<TcpFrame>);
}
