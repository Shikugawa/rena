use anyhow::{anyhow, Result};
use nix::sys::socket::SockAddr;
use regex::Regex;
use std::fmt;

pub const IPV4_ADDR_LEN: usize = 4;

type RawIpv4Addr = [u8; IPV4_ADDR_LEN];

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Addr {
    addr: RawIpv4Addr,
    pub subnet_range: u8,
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut addr = String::default();
        for octet in self.addr.into_iter() {
            addr += format!("{}.", octet).as_str();
        }
        let mut res = addr.strip_suffix(".").unwrap().to_string();
        res += &format!("/{}", self.subnet_range);
        write!(f, "{}", res)
    }
}

impl Ipv4Addr {
    pub fn new_without_subnet(buf: RawIpv4Addr) -> Self {
        Ipv4Addr::new(buf, 32)
    }

    pub fn new(buf: RawIpv4Addr, subnet_range: u8) -> Self {
        Ipv4Addr {
            addr: buf,
            subnet_range,
        }
    }

    pub fn from_str(addr: &str) -> Result<Self> {
        let re = Regex::new(r"([./]+)").unwrap();
        let addr_splited: Vec<&str> = Vec::from_iter(re.split(addr));
        if addr_splited.len() != IPV4_ADDR_LEN + 1 {
            return Err(anyhow!("malformed address"));
        }

        let mut buf = [0; IPV4_ADDR_LEN];
        for i in 0..IPV4_ADDR_LEN {
            buf[i] = addr_splited[i].parse::<u8>()?;
        }

        let subnet = addr_splited.last().unwrap().to_owned().parse::<u8>()?;
        if subnet > 32 {
            return Err(anyhow!("malformed subnet range"));
        }

        Ok(Ipv4Addr::new(buf, subnet))
    }

    pub fn from_sockaddr(addr: SockAddr, netmask: SockAddr) -> Result<Self> {
        let addr_str = addr.to_string();
        let netmask_str = netmask.to_string();

        let netmask_splited = netmask_str.strip_suffix(":0").unwrap().split(".");
        let mut netmask_bit: u32 = 0x0000;

        for (i, c) in netmask_splited.enumerate() {
            if i >= 4 {
                return Err(anyhow!("malformed netmask: {}", netmask));
            }

            let n: u32 = c.parse().unwrap();
            netmask_bit = netmask_bit | (n << 8 * (3 - i));
        }

        let mut cidr = 0;

        while netmask_bit != 0x0000 {
            netmask_bit = netmask_bit << 1;
            cidr += 1
        }

        return Ipv4Addr::from_str(
            format!("{}/{}", addr_str.strip_suffix(":0").unwrap(), cidr).as_str(),
        );
    }

    pub fn len(&self) -> usize {
        IPV4_ADDR_LEN
    }

    pub fn to_bytes(&self) -> RawIpv4Addr {
        self.addr
    }

    pub fn as_addr_str(&self) -> String {
        let mut tmp = String::new();
        for (i, c) in self.addr.iter().enumerate() {
            tmp += &c.to_string();
            if i != IPV4_ADDR_LEN - 1 {
                tmp += ".";
            }
        }
        tmp
    }
}
