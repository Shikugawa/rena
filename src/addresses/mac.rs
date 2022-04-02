use anyhow::{anyhow, Result};
use std::fmt;

pub const MACADDR_BYTES: usize = 6;

type RawMacAddr = [u8; MACADDR_BYTES];

#[derive(Default, Clone, Copy)]
pub struct MacAddr {
    addr: RawMacAddr,
}

impl MacAddr {
    pub fn new(buf: RawMacAddr) -> Self {
        MacAddr { addr: buf }
    }

    pub fn from_str(addr: &str) -> Result<Self> {
        let addr_splited: Vec<&str> = Vec::from_iter(addr.split(":"));
        if addr_splited.len() != MACADDR_BYTES {
            return Err(anyhow!("malformed mac address"));
        }
        let mut buf = [0; MACADDR_BYTES];
        for i in 0..MACADDR_BYTES {
            buf[i] = u8::from_str_radix(addr_splited[i], 16).unwrap();
        }
        Ok(MacAddr::new(buf))
    }

    pub fn len(&self) -> usize {
        MACADDR_BYTES
    }

    pub fn to_bytes(&self) -> RawMacAddr {
        self.addr
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut addr = String::default();
        for octet in self.addr.into_iter() {
            addr += format!("{:02x}:", octet).as_str();
        }
        let res = addr.strip_suffix(":").unwrap().to_string();
        write!(f, "{}", res)
    }
}
