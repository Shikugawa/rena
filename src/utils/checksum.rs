use crate::buffer::Buffer;
use crate::utils::bit_calculation::extract_u16_from_2u8;
use bytes::BytesMut;

pub fn verify_checksum(buffer: &Buffer, offset: usize) -> Option<u16> {
    let mut sum: u32 = 0;
    let mut start = buffer.start_from - offset;

    loop {
        if start >= buffer.start_from {
            break;
        }
        let r1 = buffer.at(start).clone();
        let r2 = buffer.at(start + 1).clone();
        start += 2;
        sum += extract_u16_from_2u8([r1, r2]) as u32;
    }

    if sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    if sum == 0xFFFF {
        None
    } else {
        Some(sum as u16)
    }
}

pub fn calculate_checksum(buffer: BytesMut, len: usize) -> u32 {
    let mut raw_bytes = buffer.to_vec();
    let mut sum: u32 = 0;
    let mut ptr = 0;

    // If the length of tcp payload is odd, it will cause out-of-range
    // exception. This sections is to prevent this phenomenon.
    if len % 2 != 0 {
        raw_bytes.push(0x0000);
    }

    loop {
        if ptr >= len {
            break;
        }

        let r1 = raw_bytes[ptr];
        let r2 = raw_bytes[ptr + 1];
        ptr += 2;
        sum += extract_u16_from_2u8([r1, r2]) as u32;
    }

    while sum > 0xFFFF {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    sum ^ 0xFFFF
}
