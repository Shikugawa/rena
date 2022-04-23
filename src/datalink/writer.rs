use crate::datalink::traits::DatalinkReaderWriter;
use bytes::BytesMut;
use core::fmt;
use futures::Future;
use std::sync::Arc;
use std::{
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{interval, Instant};

use super::traits::DatalinkWriteStatus;

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

struct WriteFuture {
    deadline: Option<Instant>,
    writer: Arc<dyn DatalinkReaderWriter>,
    buf: BytesMut,
}

impl Future for WriteFuture {
    type Output = WriteResult;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let self_mut = self.get_mut();

        if self_mut.deadline.is_some() && Instant::now() > self_mut.deadline.unwrap() {
            return Poll::Ready(WriteResult::Timeout);
        }

        let owned_buf = std::mem::replace(&mut self_mut.buf, BytesMut::default());
        let status = self_mut.writer.write(owned_buf);

        match status {
            DatalinkWriteStatus::Pending(buf) => {
                cx.waker().wake_by_ref();
                self_mut.buf = buf;
                Poll::Pending
            }
            DatalinkWriteStatus::Succees(code) => Poll::Ready(WriteResult::Success(code)),
        }
    }
}

fn exec(
    deadline: Option<Instant>,
    buf: BytesMut,
    writer: Arc<dyn DatalinkReaderWriter>,
) -> WriteFuture {
    WriteFuture {
        deadline,
        writer,
        buf,
    }
}

/// Write buffer into datalink.
pub async fn write(
    writer: Arc<dyn DatalinkReaderWriter>,
    buf: BytesMut,
    duration: Option<Duration>,
) -> WriteResult {
    if duration.is_none() {
        let _ = writer.async_fd().writable().await;
        return exec(None, buf, writer).await;
    } else {
        let mut interval = interval(duration.unwrap());
        let deadline = Instant::now() + duration.unwrap();

        tokio::select! {
            _ = interval.tick() => WriteResult::Timeout,
            _ = writer.async_fd().writable() => exec(Some(deadline), buf, writer).await
        }
    }
}
