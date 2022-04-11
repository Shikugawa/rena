use bytes::{BufMut, BytesMut};
use rand::{thread_rng, Rng};
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
use rena::tcp::local_handler::LocalHandler;
use std::io;
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

    // dst tcp port
    #[structopt(short, long, default_value = "8000")]
    port: u16,
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
    let mut rand_gen = thread_rng();
    let src_ip_addr = sock.ipv4_addr;
    let dst_ip_addr = Ipv4Addr::from_str(&opt.dst_address).unwrap();
    // Same as linux's default range
    // https://www.kernel.org/doc/html/latest//networking/ip-sysctl.html#ip-variables
    let sport: u16 = rand_gen.gen_range(32768..60999);
    let dport = opt.port;

    let arp_req = create_arp_request(&sock, src_ip_addr, dst_ip_addr);
    let res = write(sock.clone(), arp_req, None).await;
    if res.is_err() {
        panic!("error")
    }
    let mut arp_table = ArpTable::new();

    // wait arp response
    let mut buf = read(sock.clone(), None).await.data().unwrap();
    let ether = EthernetFrame::from_raw(&mut buf);

    // TODO: implement graceful connection draining.
    match ether.frame_type() {
        EtherType::Arp => {
            let arp = ether.arp_payload().unwrap();
            match arp.opcode() {
                ArpOperation::Response => {
                    arp.source_ipaddr().subnet_range = dst_ip_addr.subnet_range;
                    arp_table
                        .add(arp.source_ipaddr(), arp.source_macaddr())
                        .unwrap();

                    let smacaddr = sock.mac_addr;
                    let mut handler = LocalHandler::connect(
                        smacaddr,
                        arp.source_macaddr(),
                        src_ip_addr,
                        dst_ip_addr,
                        sport,
                        dport,
                        sock,
                    )
                    .await
                    .unwrap();

                    loop {
                        let mut buffer = String::new();
                        io::stdin().read_line(&mut buffer).unwrap();

                        if buffer == "close\n" {
                            handler.close().await;
                            break;
                        } else {
                            let n: usize = buffer.parse().unwrap();
                            let mut payload = BytesMut::with_capacity(n);

                            for _ in 0..n {
                                payload.put_slice(&[0x01]);
                            }
                            handler.send(payload).await.unwrap();
                        }
                    }
                }
                _ => {}
            }
        }
        _ => {}
    }
}
