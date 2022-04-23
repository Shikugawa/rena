use crate::addresses::ipv4::Ipv4Addr;
use crate::addresses::mac::MacAddr;
use crate::buffer::{Buffer, MAX_BUFFER_SIZE};
use crate::datalink::traits::DatalinkReaderWriter;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use nix::ifaddrs::getifaddrs;
use nix::libc::{self, EAGAIN};
use nix::sys::socket::{bind, socket, AddressFamily, LinkAddr, SockAddr, SockFlag, SockType};
use std::ffi::c_void;
use std::os::unix::prelude::AsRawFd;
use tokio::io::unix::AsyncFd;

use crate::headers::iface::ifreq;
use nix::ioctl_read_bad;
use nix::libc::SIOCGIFHWADDR;
use std::mem;

use super::traits::DatalinkWriteStatus;

pub struct RawSock {
    pub fd: AsyncFd<i32>,
    dev_name: String,
    pub mac_addr: MacAddr,
    pub ipv4_addr: Ipv4Addr,
    link_addr: Option<LinkAddr>,
}

impl DatalinkReaderWriter for RawSock {
    fn read(&self, buf: &mut Buffer) -> isize {
        unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.buf_ptr() as *mut c_void,
                MAX_BUFFER_SIZE,
            )
        }
    }

    fn write(&self, mut buf: BytesMut) -> DatalinkWriteStatus {
        let link = SockAddr::Link(self.link_addr.unwrap());
        let (ffi_addr, _) = link.as_ffi_pair();

        let len = u32::try_from(mem::size_of::<libc::sockaddr_ll>()).unwrap();
        let code = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                ffi_addr,
                len,
            )
        };

        if code == EAGAIN as isize || code == -1 {
            return DatalinkWriteStatus::Pending(buf);
        } else {
            return DatalinkWriteStatus::Succees(code);
        }
    }

    fn async_fd(&self) -> &AsyncFd<i32> {
        &self.fd
    }
}

impl RawSock {
    pub fn new(dev_name: &str) -> Result<Self> {
        let raw_fd = socket(
            AddressFamily::Packet,
            SockType::Raw,
            SockFlag::SOCK_NONBLOCK,
            None,
        )?;
        let fd = AsyncFd::new(raw_fd).unwrap();
        let mut sock = RawSock {
            fd,
            dev_name: dev_name.to_string(),
            mac_addr: MacAddr::default(),
            ipv4_addr: Ipv4Addr::default(),
            link_addr: None,
        };
        let mut devices = getifaddrs().unwrap().filter(|d| {
            d.interface_name == dev_name && d.address.unwrap().family() == AddressFamily::Packet
        });

        match devices.nth(0).unwrap().address.unwrap() {
            SockAddr::Link(ref ether_addr) => {
                let sll_ifindex = ether_addr.ifindex();
                sock.link_addr = Some(LinkAddr(libc::sockaddr_ll {
                    sll_family: libc::AF_PACKET as libc::c_ushort,
                    sll_protocol: (libc::ETH_P_ALL as libc::c_ushort).to_be(),
                    sll_ifindex: sll_ifindex as i32,
                    sll_hatype: 1,
                    sll_pkttype: 0,
                    sll_halen: 6,
                    sll_addr: [0; 8],
                }));
                bind(raw_fd, &SockAddr::Link(sock.link_addr.unwrap()))?;
                sock.mac_addr = sock.get_smacaddr()?;
                sock.ipv4_addr = sock.get_ipv4addr()?;
            }
            _ => return Err(anyhow!("failed to get idx")),
        };

        Ok(sock)
    }

    fn get_smacaddr(&self) -> Result<MacAddr> {
        ioctl_read_bad!(get_hwaddr, SIOCGIFHWADDR, u32);

        unsafe {
            let mut dev_name_bytes: [i8; 16] = [0; 16];
            let dev_name_bytes_raw = self.dev_name.as_bytes();
            if dev_name_bytes_raw.len() > 16
            /* max byte size of dev name */
            {
                return Err(anyhow!(
                    "malformed device name: {}, must be <= 16",
                    self.dev_name
                ));
            }
            for i in 0..dev_name_bytes_raw.len() {
                dev_name_bytes[i] = dev_name_bytes_raw[i] as i8;
            }
            let dev_name = dev_name_bytes;

            let mut req: ifreq = mem::zeroed();
            req.ifr_ifrn.ifrn_name = dev_name;
            get_hwaddr(self.fd.as_raw_fd(), &mut req as *mut _ as *mut u32)?;
            let addr_data = req.ifr_ifru.ifru_addr.sa_data;

            Ok(MacAddr::new([
                addr_data[0] as u8,
                addr_data[1] as u8,
                addr_data[2] as u8,
                addr_data[3] as u8,
                addr_data[4] as u8,
                addr_data[5] as u8,
            ]))
        }
    }

    fn get_ipv4addr(&self) -> Result<Ipv4Addr> {
        let mut it = getifaddrs().unwrap().filter(|d| {
            d.interface_name == self.dev_name && d.address.unwrap().family() == AddressFamily::Inet
        });
        let addr = it.nth(0).unwrap();
        Ipv4Addr::from_str(&addr.address.unwrap().to_string().replace(":", "/"))
    }
}

impl Drop for RawSock {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd.as_raw_fd());
        }
    }
}
