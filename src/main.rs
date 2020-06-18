#[macro_use]
extern crate enum_dispatch;

mod source;
use source::ConnectionlessChannel;
use source::packets::*;

use std::net::UdpSocket;

fn run() -> anyhow::Result<()>
{
    // bind to some client socket
    let socket = UdpSocket::bind("192.168.1.100:34254")?;

    // "connect" to udp server
    socket.connect("192.168.1.100:6543")?;

    // promote to a connectionless netchannel
    let mut stream = ConnectionlessChannel::new(socket)?;

    // request server info
    let packet = A2sInfo{};
    stream.send_packet(packet.into())?;

    // receive server info response
    let _res = stream.recv_packet()?;
    dbg!(_res);

    Ok(())
}

fn main() {

    let res: anyhow::Result<()> = run();

    if let Err(e) = res
    {
        println!("ERROR: {:?}", e);
    }
}
