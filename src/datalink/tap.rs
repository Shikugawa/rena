use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::buffer::Buffer;
use crate::datalink::traits::DatalinkReaderWriter;
use crate::headers::iface::ifreq;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use log::info;
use nix::ifaddrs::getifaddrs;
use nix::libc::{IFF_NO_PI, IFF_TAP, SIOCGIFHWADDR};
use nix::sys::socket::AddressFamily;
use nix::{ioctl_read_bad, ioctl_write_ptr};
use std::ops::Drop;
use std::process::Command;
use std::{mem, os::unix::prelude::AsRawFd};
use tokio::fs::OpenOptions;
use tokio::io::unix::AsyncFd;

use super::traits::DatalinkWriteStatus;

const TAP_DEV: &str = "/dev/net/tun";
const TUN_IOC_MAGIC: u8 = b'T';
const TUN_IOC_TYPE_MESSAGE: u8 = 202;
ioctl_write_ptr!(setup_tun, TUN_IOC_MAGIC, TUN_IOC_TYPE_MESSAGE, u32);
ioctl_read_bad!(get_hwaddr, SIOCGIFHWADDR, u32);

pub struct TapDevice {
    fd: AsyncFd<i32>,
    device: String,
    macaddr: MacAddr,
    ipaddr: Ipv4Addr,
}

impl DatalinkReaderWriter for TapDevice {
    fn read(&self, buf: &mut Buffer) -> isize {
        0
    }

    fn write(&self, mut buf: BytesMut) -> DatalinkWriteStatus {
        DatalinkWriteStatus::Succees(0)
    }

    fn async_fd(&self) -> &AsyncFd<i32> {
        &self.fd
    }
}

impl TapDevice {
    pub async fn new(device: &str) -> Result<Self> {
        let fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TAP_DEV)
            .await?;

        let dev_exists = getifaddrs()
            .unwrap()
            .map(|d| d.interface_name == device)
            .any(|v| v);

        if !dev_exists {
            return Err(anyhow!("device {} not found", device));
        }

        let mut req: ifreq = unsafe { mem::zeroed() };
        req.ifr_ifru.ifru_flags = (IFF_TAP | IFF_NO_PI).try_into()?;

        let mut dev_name_bytes: [i8; 16] = [0; 16];
        let dev_name_bytes_raw = device.as_bytes();
        if dev_name_bytes_raw.len() > 16
        /* max byte size of dev name */
        {
            return Err(anyhow!("malformed device name: {}, must be <= 16", device));
        }
        for i in 0..dev_name_bytes_raw.len() {
            dev_name_bytes[i] = dev_name_bytes_raw[i] as i8;
        }
        req.ifr_ifrn.ifrn_name = dev_name_bytes;

        unsafe {
            setup_tun(fd.as_raw_fd(), &req as *const _ as *const u32)?;
        };

        let macaddr = unsafe {
            let mut req2: ifreq = mem::zeroed();
            req2.ifr_ifrn.ifrn_name = dev_name_bytes;
            get_hwaddr(fd.as_raw_fd(), &mut req2 as *mut _ as *mut u32)?;
            let addr_data = req2.ifr_ifru.ifru_addr.sa_data;
            MacAddr::new([
                addr_data[0] as u8,
                addr_data[1] as u8,
                addr_data[2] as u8,
                addr_data[3] as u8,
                addr_data[4] as u8,
                addr_data[5] as u8,
            ])
        };

        if let Some(iface) = getifaddrs().unwrap().find(|ifaddr| match ifaddr.address {
            Some(address) => {
                address.family() == AddressFamily::Inet && ifaddr.interface_name == device
            }
            None => false,
        }) {
            let ipaddr = iface.address.unwrap();
            info!(
                "created tap device: {} mac address: {}, IPv4 address: {}",
                device, macaddr, ipaddr
            );
            let device = TapDevice {
                fd: AsyncFd::new(fd.as_raw_fd()).unwrap(),
                device: device.to_string(),
                macaddr,
                ipaddr: Ipv4Addr::from_str(ipaddr.to_string().as_str()).unwrap(),
            };
            return Ok(device);
        }
        return Err(anyhow!(
            "failed to find device {} which have valid address",
            device
        ));
    }

    // TODO: do not rely on ip command.
    fn link_up(&self) {
        Command::new("ip")
            .arg("link")
            .args(["set", "up"])
            .args(["dev", &self.device])
            .output()
            .expect("failed to link up device");
        info!("succeeded to link up device: {}", &self.device);
    }

    // TODO: do not rely on ip command.
    fn add_ipaddress(&self, addr: &str) {
        Command::new("ip")
            .arg("addr")
            .args(["add", addr])
            .args(["dev", &self.device])
            .output()
            .expect("failed to add address to device");
        info!(
            "succeeded to add address: {} to device: {}",
            addr, &self.device
        );
    }
}

impl Drop for TapDevice {
    // TODO: do not rely on ip command.
    fn drop(&mut self) {
        // Command::new("ip")
        //     .arg("link")
        //     .args(["set", "down"])
        //     .args(["dev", &self.device])
        //     .output()
        //     .expect("failed to linkdown device");
        // info!("succeeded to linkdown device: {}", &self.device);
    }
}
