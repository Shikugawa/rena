use bytes::BytesMut;

// A decoded frame object.
pub trait Frame {
    // Convert this frame into bytes
    fn to_bytes(&self) -> BytesMut;

    // Get frame length. It means the sum of header and payload.
    fn frame_length(&self) -> usize;

    // Get header length.
    fn header_length(&self) -> usize;

    // Get payload length.
    fn payload_length(&self) -> usize;
}
