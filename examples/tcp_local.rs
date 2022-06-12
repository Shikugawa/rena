use std::io;

use bytes::BytesMut;
use rena::addresses::ipv4::Ipv4Addr;
use rena::tcp::tcp_socket::TcpClient;
use structopt::StructOpt;

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

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    let dipaddr = Ipv4Addr::from_str(&opt.dst_address).unwrap();
    let mut client = TcpClient::new(&opt.interface, dipaddr, opt.port);

    client.handshake().await;

    loop {
        let mut buffer = String::new();
        io::stdin().read_line(&mut buffer).unwrap();

        if buffer == "close\n" {
            break;
        } else {
            buffer = buffer.strip_suffix("\n").unwrap().to_string();
            let payload = BytesMut::from(buffer.as_bytes());
            client.send(payload).await;
        }
    }

    client.close().await;
}
