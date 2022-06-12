use crate::{
    addresses::ipv4::Ipv4Addr,
    datalink::rawsock::RawSock,
    io::{io_handler::IoHandler, thread_event_handler::ThreadEventHandler},
    layers::thread_local_layer_storage::{create_icmp_layers, ThreadLocalStorageCopyableWrapper},
};

const CLIENT_THREAD_ID: u64 = 0xdeadbeef;

pub struct PingClient {
    dipaddr: Ipv4Addr,
    layer_storage: ThreadLocalStorageCopyableWrapper,
    io_handler: IoHandler,
    next_seq_num: u16,
}

impl PingClient {
    pub fn new(iface: &str, dipaddr: Ipv4Addr) -> Self {
        let sock = RawSock::new(iface).unwrap();

        let smacaddr = sock.mac_addr;
        let sipaddr = sock.ipv4_addr;

        let (io_handler, ethframe_tx, ethframe_rx) = IoHandler::new(sock);
        let thread_event_handler = ThreadEventHandler::new(ethframe_rx, ethframe_tx);

        // In client mode, thread will be created only once in current implementation,
        // thus we allocated hard-coded thread_id.
        let layer_storage =
            create_icmp_layers(CLIENT_THREAD_ID, thread_event_handler, sipaddr, smacaddr);
        PingClient {
            dipaddr,
            layer_storage,
            io_handler,
            next_seq_num: 0,
        }
    }

    pub async fn ping(&mut self) {
        self.layer_storage
            .icmp_layer(CLIENT_THREAD_ID)
            .send_icmp_echo_request(self.dipaddr, self.next_seq_num)
            .await;
        self.next_seq_num += 1;
    }

    pub async fn close(&mut self) {
        self.io_handler.close().await;
    }
}
