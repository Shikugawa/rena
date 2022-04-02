use bytes::{BufMut, BytesMut};
use core::slice::Iter;

pub fn extract_2u8_from_u16(val: u16) -> [u8; 2] {
    [(val >> 8) as u8, val as u8]
}

pub fn extract_u16_from_2u8(val: [u8; 2]) -> u16 {
    (val[0] as u16) << 8 | val[1] as u16
}

pub fn extract_u32_from_4u8(val: [u8; 4]) -> u32 {
    let mut result = 0;
    for i in 0..4 {
        result |= (val[i] as u32) << 32 - (8 * (i + 1))
    }
    result
}

// Extract left n bit from u8 (Big Endian)
// e.g. f(10101101) -> 00000101
pub fn extract_nbit_be_left_from_u8(val: u8, bits: usize) -> u8 {
    let mask: u8 = 0xFF << (8 - bits);
    (mask & val) >> (8 - bits)
}

// Extract right n bit from u8 (Big Endian)
// e.g. f(10101101) -> 00001101
pub fn extract_nbit_be_right_from_u8(val: u8, bits: usize) -> u8 {
    let mask: u8 = 0xFF >> (8 - bits);
    mask & val
}

// Merge two u8 into one u8
// e.g. f(00001101, 00000001, 4) -> 11010001
pub fn merge_2u8_to_u8(left: u8, right: u8, shift: u8) -> u8 {
    (left << shift) | right
}

// Extract left n bit from u16 (Big Endian)
pub fn extract_nbit_be_left_from_u16(val: u16, bits: usize) -> u16 {
    let mask: u16 = 0xFFFF << (16 - bits);
    (mask & val) >> (16 - bits)
}

// Extract right n bit from 16 (Big Endian)
pub fn extract_nbit_be_right_from_u16(val: u16, bits: usize) -> u16 {
    let mask: u16 = 0xFFFF >> (16 - bits);
    mask & val
}

pub fn push_bytes(packet: &mut BytesMut, mut it: Iter<u8>) {
    loop {
        if let Some(value) = it.next() {
            packet.put_u8(value.clone());
        } else {
            break;
        }
    }
}
