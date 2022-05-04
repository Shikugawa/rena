use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use anyhow::{anyhow, Result};
use log::info;
use std::collections::HashMap;
use std::fmt;
use std::sync::RwLock;

const MAC_RECORD_SIZE: usize = 1 << 10;

pub struct ArpTable {
    table: RwLock<HashMap<String, MacAddr>>,
}

impl std::fmt::Display for ArpTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let tbl = self.table.read().unwrap();
        let mut res = String::default();
        for (ipaddr, mac) in tbl.iter() {
            res += format!("{:?} {}\n", ipaddr, mac).as_str();
        }
        write!(f, "{}", res)
    }
}

impl ArpTable {
    pub fn new() -> Self {
        ArpTable {
            table: RwLock::new(HashMap::new()),
        }
    }

    pub fn add(&mut self, ipaddr: Ipv4Addr, macaddr: MacAddr) -> Result<()> {
        let mut l = self.table.write().unwrap();
        if l.len() > MAC_RECORD_SIZE {
            return Err(anyhow!("max size of arp table exceeded."));
        }
        l.insert(ipaddr.as_addr_str(), macaddr);
        info!("updated ARP table: {} -> {}", ipaddr, macaddr);
        Ok(())
    }

    pub fn lookup(&self, ipaddr: Ipv4Addr) -> Result<MacAddr> {
        let l = self.table.read().unwrap();
        let addr_str = ipaddr.as_addr_str();
        if l.contains_key(&addr_str) {
            return Ok(l[&addr_str]);
        }
        Err(anyhow!(
            "IP: {} not found. You must broadcast arp packet.",
            ipaddr
        ))
    }

    // Flush MUST be called if belonging network segment changed.
    pub fn flush(&mut self) {
        let mut l = self.table.write().unwrap();
        info!("flushed ARP table");
        l.clear();
    }
}
