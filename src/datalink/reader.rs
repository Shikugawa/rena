use crate::buffer::Buffer;
use crate::datalink::traits::DatalinkReaderWriter;
use anyhow::{anyhow, Result};
use futures::Future;
use nix::libc::{self, EAGAIN};
use std::fmt;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::time::{interval, Duration, Instant};

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

    pub fn data(self) -> Result<Buffer> {
        match self {
            ReadResult::Success(buf) => Ok(buf),
            ReadResult::Timeout => Err(anyhow!("read timeout")),
        }
    }
}

struct ReadFuture {
    deadline: Option<Instant>,
    reader: Arc<dyn DatalinkReaderWriter>,
    pub buf: Buffer,
}

impl Future for ReadFuture {
    type Output = ReadResult;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_mut = self.get_mut();
        if self_mut.deadline.is_some() && Instant::now() > self_mut.deadline.unwrap() {
            return Poll::Ready(ReadResult::Timeout);
        }

        let code = self_mut.reader.read(&mut self_mut.buf);

        if code == EAGAIN as isize || code == -1 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        } else {
            self_mut.buf.set_buffer_size(code as usize);
            let owned_buf = std::mem::replace(&mut self_mut.buf, Buffer::default());
            return Poll::Ready(ReadResult::Success(owned_buf));
        }
    }
}

fn exec(deadline: Option<Instant>, reader: Arc<dyn DatalinkReaderWriter>) -> ReadFuture {
    ReadFuture {
        deadline,
        buf: Buffer::default(),
        reader,
    }
}

/// Read buffer from datalink
pub async fn read(reader: Arc<dyn DatalinkReaderWriter>, duration: Option<Duration>) -> ReadResult {
    if duration.is_none() {
        let _ = reader.async_fd().readable().await;
        return exec(None, reader).await;
    } else {
        let mut interval = interval(duration.unwrap());
        let deadline = Instant::now() + duration.unwrap();

        tokio::select! {
            _ = interval.tick() => ReadResult::Timeout,
            _ = reader.async_fd().readable() => exec(Some(deadline), reader).await
        }
    }
}
