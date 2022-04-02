use bytes::BytesMut;
use rena::addresses::ipv4::Ipv4Addr;
use rena::addresses::mac::MacAddr;
use rena::arp_table::ArpTable;
use rena::datalink::rawsock::RawSock;
use rena::datalink::reader::read;
use rena::datalink::writer::write;
use rena::frames::arp::ArpOperation;
use rena::frames::ethernet::EtherType;
use rena::frames::ethernet::EthernetFrame;
use rena::packet::{ArpPacket, IcmpPacket};
use std::time::Duration;
use structopt::StructOpt;
use tokio::time::sleep;

#[derive(StructOpt)]
#[structopt(name = "basic")]
struct Opt {
    // Interface name which will be bound with device.
    #[structopt(short, long)]
    interface: String,

    // A dst address.
    #[structopt(short, long)]
    dst_address: String,

    // Ping times
    #[structopt(short, long, default_value = "1")]
    count: u16,
}

fn create_arp_request(sock: &RawSock, src_ip_addr: Ipv4Addr, dst_ip_addr: Ipv4Addr) -> BytesMut {
    ArpPacket::default()
        .set_arp_request(sock.mac_addr, src_ip_addr, dst_ip_addr)
        .set_ether(
            sock.mac_addr,
            MacAddr::from_str("ff:ff:ff:ff:ff:ff").unwrap(),
        )
        .build()
}

struct PingSession {
    seq_num: u16,
    dst_mac_address: MacAddr,
    src_ip_address: Ipv4Addr,
    dst_ip_address: Ipv4Addr,
}

impl PingSession {
    pub fn new(
        dst_mac_address: MacAddr,
        src_ip_address: Ipv4Addr,
        dst_ip_address: Ipv4Addr,
    ) -> Self {
        PingSession {
            seq_num: 1,
            dst_mac_address,
            src_ip_address,
            dst_ip_address,
        }
    }

    fn new_echo_frame(&mut self, sock: &RawSock) -> BytesMut {
        let frame = IcmpPacket::default()
            .set_icmp_echo_request(self.seq_num)
            .set_ipv4(self.src_ip_address, self.dst_ip_address)
            .set_ether(sock.mac_addr, self.dst_mac_address)
            .build();
        self.seq_num += 1;
        frame
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    let sock = RawSock::new(&opt.interface).unwrap();
    let src_ip_addr = sock.ipv4_addr;
    let dst_ip_addr = Ipv4Addr::from_str(&opt.dst_address).unwrap();

    let arp_req = create_arp_request(&sock, src_ip_addr, dst_ip_addr);
    let res = write(&sock, arp_req, Duration::from_secs(3)).await;
    if res.is_err() {
        panic!("error");
    }

    let mut arp_table = ArpTable::new();

    // wait arp response
    let mut buf = read(&sock, Duration::from_secs(3)).await.data().unwrap();
    let ether = EthernetFrame::from_raw(&mut buf);

    match ether.frame_type() {
        EtherType::Arp => {
            let arp = ether.arp_payload().unwrap();

            match arp.opcode() {
                ArpOperation::Response => {
                    arp.source_ipaddr().subnet_range = dst_ip_addr.subnet_range;
                    arp_table
                        .add(arp.source_ipaddr(), arp.source_macaddr())
                        .unwrap();

                    // send icmp echo request
                    let mut ping_session = PingSession::new(
                        arp_table.lookup(dst_ip_addr).unwrap(),
                        src_ip_addr,
                        dst_ip_addr,
                    );

                    for _ in 0..opt.count {
                        let res = write(
                            &sock,
                            ping_session.new_echo_frame(&sock),
                            Duration::from_secs(3),
                        )
                        .await;
                        if res.is_err() {
                            panic!("error");
                        }
                        // wait icmp echo response
                        let mut buf = read(&sock, Duration::from_secs(3)).await.data().unwrap();
                        let ether = EthernetFrame::from_raw(&mut buf);
                        let ip = ether.ipv4_payload().unwrap();
                        let icmp = ip.icmp_payload().unwrap();
                        println!("{}", &icmp);

                        sleep(Duration::from_secs(1)).await;
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}
