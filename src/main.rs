#[macro_use]
extern crate enum_dispatch;

#[macro_use]
extern crate num_derive;

mod source;
mod steam;
use source::ConnectionlessChannel;
use source::packets::*;
use steam::SteamClient;

use std::net::{UdpSocket, IpAddr};

fn run() -> anyhow::Result<()>
{
    println!("Connecting to Steam...");
    let _steam = SteamClient::connect()?;
    //_steam.request_join_server(13759, )
    println!("Connected to Steam!");

    // bind to some client socket
    let socket = UdpSocket::bind("172.19.131.177:20403")?;

    // "connect" to udp server
    socket.connect("104.153.105.44:27015")?;
    let addr = socket.peer_addr()?;

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
    let chal: S2cChallenge = stream.recv_packet_type()?;
    dbg!(&_res);

    let ip_encoded: u32;
    if let IpAddr::V4(ip) = addr.ip()
    {
        ip_encoded = u32::from(ip);
    }
    else {
        panic!("ipv6 not supported by source engine");
    }

    // request to join the server through the game coordinator
    _steam.request_join_server(
        chal.host_version,
        chal.gameserver_steamid,
        ip_encoded,
        addr.port() as u32
    )?;

    Ok(())
}

fn main() {

    let res: anyhow::Result<()> = run();

    if let Err(e) = res
    {
        println!("ERROR: {:?}", e);
    }
}
