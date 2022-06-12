use bytes::BytesMut;

use crate::{
    addresses::ipv4::Ipv4Addr,
    datalink::rawsock::RawSock,
    io::{io_handler::IoHandler, thread_event_handler::ThreadEventHandler},
    layers::thread_local_layer_storage::{create_tcp_layers, ThreadLocalStorageCopyableWrapper},
};

const CLIENT_THREAD_ID: u64 = 0xdeadbeef;

pub struct TcpClient {
    dipaddr: Ipv4Addr,
    dport: u16,
    layer_storage: ThreadLocalStorageCopyableWrapper,
    io_handler: IoHandler,
}

impl TcpClient {
    pub fn new(iface: &str, dipaddr: Ipv4Addr, dport: u16) -> Self {
        let sock = RawSock::new(iface).unwrap();

        let smacaddr = sock.mac_addr;
        let sipaddr = sock.ipv4_addr;

        let (io_handler, ethframe_tx, ethframe_rx) = IoHandler::new(sock);
        let thread_event_handler = ThreadEventHandler::new(ethframe_rx, ethframe_tx);

        // In client mode, thread will be created only once in current implementation,
        // thus we allocated hard-coded thread_id.
        let layer_storage =
            create_tcp_layers(CLIENT_THREAD_ID, thread_event_handler, sipaddr, smacaddr);
        TcpClient {
            dipaddr,
            dport,
            layer_storage,
            io_handler,
        }
    }

    pub async fn handshake(&mut self) {
        self.layer_storage
            .tcp_layer(CLIENT_THREAD_ID)
            .handshake(self.dipaddr, self.dport)
            .await;
    }

    pub async fn send(&mut self, payload: BytesMut) {
        let session = self
            .layer_storage
            .tcp_layer(CLIENT_THREAD_ID)
            .get_session(self.dport);
        self.layer_storage
            .tcp_layer(CLIENT_THREAD_ID)
            .send(session.unwrap(), self.dipaddr, payload)
            .await;
    }

    pub async fn close(&mut self) {
        self.io_handler.close().await;
    }
}
