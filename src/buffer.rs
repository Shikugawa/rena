use anyhow::{anyhow, Result};
use bytes::{BufMut, BytesMut};

pub const MAX_BUFFER_SIZE: usize = 1024;

#[derive(PartialEq, Clone, Copy)]
pub struct Buffer {
    // TODO: private
    pub start_from: usize,
    buffer_size: usize,
    buf: [u8; MAX_BUFFER_SIZE],
}

impl Default for Buffer {
    fn default() -> Self {
        let buf = [0; MAX_BUFFER_SIZE];
        Buffer {
            start_from: 0,
            buffer_size: 0,
            buf,
        }
    }
}

impl Buffer {
    pub fn get_slice_1(&mut self) -> [u8; 1] {
        let mut dst = [0];

        if self.check(1).is_err() {
            return dst;
        }

        dst[0] = self.buf[self.start_from];

        self.start_from += 1;
        dst
    }

    pub fn get_slice_2(&mut self) -> [u8; 2] {
        let mut dst = [0, 0];

        if self.check(2).is_err() {
            return dst;
        }

        dst[0] = self.buf[self.start_from];
        dst[1] = self.buf[self.start_from + 1];

        self.start_from += 2;
        dst
    }

    pub fn get_slice_3(&mut self) -> [u8; 3] {
        let mut dst = [0, 0, 0];

        if self.check(3).is_err() {
            return dst;
        }

        dst[0] = self.buf[self.start_from];
        dst[1] = self.buf[self.start_from + 1];
        dst[2] = self.buf[self.start_from + 2];

        self.start_from += 3;
        dst
    }

    pub fn get_slice_4(&mut self) -> [u8; 4] {
        let mut dst = [0, 0, 0, 0];

        if self.check(4).is_err() {
            return dst;
        }

        dst[0] = self.buf[self.start_from];
        dst[1] = self.buf[self.start_from + 1];
        dst[2] = self.buf[self.start_from + 2];
        dst[3] = self.buf[self.start_from + 3];

        self.start_from += 4;
        dst
    }

    pub fn get_slice_5(&mut self) -> [u8; 5] {
        let mut dst = [0, 0, 0, 0, 0];

        if self.check(5).is_err() {
            return dst;
        }

        dst[0] = self.buf[self.start_from];
        dst[1] = self.buf[self.start_from + 1];
        dst[2] = self.buf[self.start_from + 2];
        dst[3] = self.buf[self.start_from + 3];
        dst[4] = self.buf[self.start_from + 4];

        self.start_from += 5;
        dst
    }

    pub fn get_slice_6(&mut self) -> [u8; 6] {
        let mut dst = [0, 0, 0, 0, 0, 0];

        if self.check(6).is_err() {
            return dst;
        }

        dst[0] = self.buf[self.start_from];
        dst[1] = self.buf[self.start_from + 1];
        dst[2] = self.buf[self.start_from + 2];
        dst[3] = self.buf[self.start_from + 3];
        dst[4] = self.buf[self.start_from + 4];
        dst[5] = self.buf[self.start_from + 5];

        self.start_from += 6;
        dst
    }

    pub fn get_fixed_sized_bytes(&mut self, size: usize) -> Result<BytesMut> {
        if self.check(size).is_err() {
            return Err(anyhow!("failed to fetch {} bytes", size));
        }
        let mut dst = BytesMut::with_capacity(size);
        let limit = self.start_from + size;

        while self.start_from < limit {
            dst.put_u8(self.buf[self.start_from]);
            self.start_from += 1;
        }

        Ok(dst)
    }

    pub fn get_remain_bytes(&mut self) -> BytesMut {
        let mut dst = BytesMut::new();
        while self.start_from < self.buffer_size {
            dst.put_u8(self.buf[self.start_from]);
            self.start_from += 1;
        }
        dst
    }

    pub fn at(&self, at: usize) -> &u8 {
        &self.buf[at]
    }

    pub fn buf_ptr(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }

    pub fn set_buffer_size(&mut self, size: usize) {
        self.buffer_size = size;
    }

    fn check(&self, size: usize) -> Result<()> {
        if self.start_from + size - 1 < self.buffer_size {
            return Ok(());
        }
        Err(anyhow!("no capacity"))
    }
}
