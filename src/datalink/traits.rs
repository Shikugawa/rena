use crate::buffer::Buffer;
use bytes::BytesMut;
use tokio::io::unix::AsyncFd;

// Abstractive reader/writer object which enables to implement read operation with async support.
pub trait DatalinkReaderWriter: Sync + Send {
    // Read buffer from datalink synchoronosly.
    fn read(&self, buf: &mut Buffer) -> isize;

    // Write buffer from datalink synchoronosly.
    fn write(&self, buf: BytesMut) -> isize;

    // Get abstractive non-blocking file descriptor to support async operation.
    fn async_fd(&self) -> &AsyncFd<i32>;
}
