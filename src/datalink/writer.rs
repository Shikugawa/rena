use anyhow::{anyhow, Result};
use bytes::BytesMut;
use core::fmt;
use futures::future::poll_fn;
use nix::libc::{self, EAGAIN};
use std::{
    task::{Context, Poll},
    time::Duration,
};
use tokio::{io::unix::AsyncFd, time::Instant};

// Abstractive writer object which enables to implement write operation with async support.
pub trait DatalinkWriter: Sync + Send {
    // Write buffer from datalink synchoronosly.
    fn write(&self, buf: BytesMut) -> isize;

    // Get abstractive non-blocking file descriptor to support async operation.
    fn async_fd(&self) -> &AsyncFd<i32>;
}

#[derive(PartialEq)]
pub enum WriteResult {
    Success(isize),
    Timeout,
}

impl fmt::Display for WriteResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteResult::Success(_) => write!(f, "Success"),
            WriteResult::Timeout => write!(f, "Timeout"),
        }
    }
}

impl WriteResult {
    pub fn is_err(&self) -> bool {
        match self {
            WriteResult::Success(_) => return false,
            _ => return true,
        }
    }
}

/// Write buffer into datalink.
pub async fn write(writer: &dyn DatalinkWriter, buf: BytesMut, duration: Duration) -> WriteResult {
    let deadline = Instant::now() + duration;

    let future = poll_fn(|cx: &mut Context<'_>| -> Poll<WriteResult> {
        if Instant::now() > deadline {
            return Poll::Ready(WriteResult::Timeout);
        }
        let code = writer.write(buf.to_owned());

        if code == EAGAIN as isize || code == -1 {
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            Poll::Ready(WriteResult::Success(code))
        }
    });
    if writer.async_fd().writable().await.is_ok() {
        let res = future.await;
        return res;
    }
    // not reached
    unimplemented!()
}
