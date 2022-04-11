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
use rena::packet::ArpPacket;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::time::Duration;

#[derive(StructOpt)]
#[structopt(name = "basic")]
struct Opt {
    // Interface name which will be bound with device.
    #[structopt(short, long)]
    interface: String,

    // A dst address.
    #[structopt(short, long)]
    dst_address: String,
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

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    let sock = Arc::new(RawSock::new(&opt.interface).unwrap());
    let src_ip_addr = sock.ipv4_addr;
    let dst_ip_addr = Ipv4Addr::from_str(&opt.dst_address).unwrap();

    let arp_req = create_arp_request(&sock, src_ip_addr, dst_ip_addr);
    let res = write(sock.clone(), arp_req, None).await;
    if res.is_err() {
        panic!("{}", res);
    }

    let mut arp_table = ArpTable::new();
    loop {
        let mut buf = read(sock.clone(), None).await.data().unwrap();
        let ether = EthernetFrame::from_raw(&mut buf);

        match ether.frame_type() {
            EtherType::Arp => {
                let arp = ether.arp_payload().unwrap();
                if arp.opcode() == ArpOperation::Response {
                    arp.source_ipaddr().subnet_range = dst_ip_addr.subnet_range;
                    arp_table
                        .add(arp.source_ipaddr(), arp.source_macaddr())
                        .unwrap();
                    break;
                }
            }
            _ => {}
        }
    }
}
