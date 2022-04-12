use crate::buffer::Buffer;
use crate::datalink::traits::DatalinkReaderWriter;
use anyhow::{anyhow, Result};
use futures::future::poll_fn;
use nix::libc::{self, EAGAIN};
use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::time::{Duration, Instant};

#[derive(PartialEq)]
pub enum ReadResult {
    Success(Buffer),
    Timeout,
}

impl fmt::Display for ReadResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadResult::Success(_) => write!(f, "Success"),
            ReadResult::Timeout => write!(f, "Timeout"),
        }
    }
}

impl ReadResult {
    pub fn is_err(&self) -> bool {
        match self {
            ReadResult::Success(_) => return false,
            _ => return true,
        }
    }

    pub fn data(&self) -> Result<Buffer> {
        match self {
            ReadResult::Success(buf) => Ok(buf.to_owned()),
            ReadResult::Timeout => Err(anyhow!("read timeout")),
        }
    }
}

/// Read buffer from datalink
pub async fn read(reader: Arc<dyn DatalinkReaderWriter>, duration: Option<Duration>) -> ReadResult {
    let mut buf = Buffer::default();
    let deadline = if duration.is_some() {
        Some(Instant::now() + duration.unwrap())
    } else {
        None
    };

    let future = poll_fn(|cx: &mut Context<'_>| -> Poll<ReadResult> {
        if deadline.is_some() && Instant::now() > deadline.unwrap() {
            return Poll::Ready(ReadResult::Timeout);
        }
        let code = reader.read(&mut buf);

        if code == EAGAIN as isize || code == -1 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            buf.set_buffer_size(code as usize);
            Poll::Ready(ReadResult::Success(buf))
        }
    });
    if reader.async_fd().readable().await.is_ok() {
        let res = future.await;
        return res;
    }
    // not reached
    unimplemented!()
}
