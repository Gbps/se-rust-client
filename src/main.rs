#[macro_use]
extern crate enum_dispatch;

#[macro_use]
extern crate num_derive;

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
    let packet = A2sInfo::default();
    dbg!(&packet);
    stream.send_packet(packet.into())?;

    // receive server info response
    let _res: S2aInfoSrc = stream.recv_packet_type()?;
    dbg!(&_res);

    // request challenge
    let packet = A2sGetChallenge::default();
    dbg!(&packet);
    stream.send_packet(packet.into())?;

    // receive challenge response
    let _res: S2cChallenge = stream.recv_packet_type()?;
    dbg!(&_res);

    // verify the challenge
    let packet = A2sGetChallenge::with_challenge(_res.challenge_num);
    dbg!(&packet);
    stream.send_packet(packet.into())?;

    // ensure we have successfully verified the challenge
    let _res: S2cChallenge = stream.recv_packet_type()?;
    dbg!(&_res);

    Ok(())
}

fn main() {

    let res: anyhow::Result<()> = run();

    if let Err(e) = res
    {
        println!("ERROR: {:?}", e);
    }
}
