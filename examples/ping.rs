use rena::addresses::ipv4::Ipv4Addr;
use rena::sockets::ping_socket::PingClient;
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

    // Ping times
    #[structopt(short, long, default_value = "1")]
    count: u16,
}

#[tokio::main]
async fn main() {
    env_logger::init();
    let opt = Opt::from_args();

    let dipaddr = Ipv4Addr::from_str(&opt.dst_address).unwrap();
    let mut client = PingClient::new(&opt.interface, dipaddr);

    for _ in 0..opt.count {
        client.ping().await;
    }

    client.close().await;
}
