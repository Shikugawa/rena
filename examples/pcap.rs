use rena::datalink::rawsock::RawSock;
use rena::datalink::reader::read;
use rena::frames::ethernet::EtherType;
use rena::frames::ethernet::EthernetFrame;
use rena::frames::ipv4::IpProtocol;
use std::sync::Arc;
use structopt::StructOpt;
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::Duration;

#[derive(StructOpt)]
#[structopt(name = "basic")]
struct Opt {
    // Interface name which will be bound with device.
    #[structopt(short, long)]
    interface: String,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    let sock = Arc::new(RawSock::new(&opt.interface).unwrap());
    let mut stream = signal(SignalKind::interrupt()).unwrap();

    let mut packet_no = 1;
    loop {
        tokio::select! {
            _ = stream.recv() => {
                // TODO: implement graceful shutdown if we have pending operations
                // in async runtime.
                return;
            },
            buf = read(sock.clone(), None) => {
                println!("Packet ID: {}\n", packet_no);
                packet_no += 1;
                let mut buf2 = buf.data().unwrap();
                let ether = EthernetFrame::from_raw(&mut buf2);
                println!("{}", ether);
                match ether.frame_type() {
                    EtherType::Arp => {
                        let arp = ether.arp_payload().unwrap();
                        println!("{}", &arp);
                    },
                    EtherType::Ipv4 => {
                        let ip = ether.ipv4_payload().unwrap();
                        println!("{}", &ip);

                        match ip.protocol() {
                            IpProtocol::Icmp => {
                                let icmp = ip.icmp_payload().unwrap();
                                println!("{}", &icmp);
                            },
                            IpProtocol::Tcp => {
                                let tcp = ip.tcp_payload().unwrap();
                                println!("{}", &tcp);
                            },
                            IpProtocol::Unknown => println!("unknown")
                        }
                    },
                    _ => println!("unsupported type of ether")
                }
            }
        };
    }
}
