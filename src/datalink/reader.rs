use crate::buffer::Buffer;
use anyhow::{anyhow, Result};
use futures::future::poll_fn;
use nix::libc::{self, EAGAIN};
use std::fmt;
use std::task::{Context, Poll};
use tokio::io::unix::AsyncFd;
use tokio::time::{Duration, Instant};

// Abstractive reader object which enables to implement read operation with async support.
pub trait DatalinkReader: Sync + Send {
    // Read buffer from datalink synchoronosly.
    fn read(&self, buf: &mut Buffer) -> isize;

    // Get abstractive non-blocking file descriptor to support async operation.
    fn async_fd(&self) -> &AsyncFd<i32>;
}

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
pub async fn read(reader: &dyn DatalinkReader, duration: Duration) -> ReadResult {
    let mut buf = Buffer::default();
    let deadline = Instant::now() + duration;

    let future = poll_fn(|cx: &mut Context<'_>| -> Poll<ReadResult> {
        if Instant::now() > deadline {
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
