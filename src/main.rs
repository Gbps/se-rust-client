#[macro_use]
extern crate enum_dispatch;

#[macro_use]
extern crate num_derive;

mod source;
mod steam;
mod protoutil;
use source::ConnectionlessChannel;
use source::packets::*;
use steam::SteamClient;
use source::protos::{CMsg_CVars, CCLCMsg_SplitPlayerConnect, CMsg_CVars_CVar};
use source::NetChannel;

use std::net::{UdpSocket, IpAddr};
use crate::source::netmessages::NetMessage;
use crate::source::protos::NET_Messages;
use log::{info, debug, trace};

fn run() -> anyhow::Result<()>
{
    pretty_env_logger::init();

    info!("Connecting to Steam...");
    let _steam = SteamClient::connect()?;
    //_steam.request_join_server(13759, )
    info!("Connected to Steam!");

    // bind to some client socket
    let socket = UdpSocket::bind("0.0.0.0:0")?;

    // "connect" to udp server
    socket.connect("192.168.201.128:6543")?;
    let addr = socket.peer_addr()?;

    // promote to a connectionless netchannel
    let mut stream = ConnectionlessChannel::new(socket)?;

    // request server info
    let packet = A2sInfo::default();
    //dbg!(&packet);
    stream.send_packet(packet.into())?;

    // receive server info response
    let _res: S2aInfoSrc = stream.recv_packet_type()?;
    //dbg!(&_res);

    // request challenge
    let packet = A2sGetChallenge::default();
    //dbg!(&packet);
    stream.send_packet(packet.into())?;

    // receive challenge response
    let _res: S2cChallenge = stream.recv_packet_type()?;
    //dbg!(&_res);

    // verify the challenge
    let packet = A2sGetChallenge::with_challenge(_res.challenge_num);
    //dbg!(&packet);
    stream.send_packet(packet.into())?;

    // ensure we have successfully verified the challenge
    let chal: S2cChallenge = stream.recv_packet_type()?;
    //dbg!(&_res);

    let ip_encoded: u32;
    if let IpAddr::V4(ip) = addr.ip()
    {
        ip_encoded = u32::from(ip);
    }
    else {
        panic!("ipv6 not supported by source engine");
    }

    // request to join the server through the game coordinator
    // this makes the game coordinator contact the server and tell it that we're about
    // to connect, which generates a reservationid that we must pass in the C2S_CONNECT
    // packet in order to prove that we have registered our connection to the game coordinator
    let reservation = _steam.request_join_server(
        chal.host_version,
        chal.gameserver_steamid,
        ip_encoded,
        addr.port() as u32
    )?;

    // now we need to ask the steamworks api to generate our client an authentication ticket
    // to send to the server
    //
    // this ticket is basically an encrypted blob which is signed by the steam backend which proves
    // that we own the game we are trying to use and that we are who we say we are (so the server
    // can properly assign our steamid)
    let auth_ticket = _steam.get_auth_ticket()?;
    info!("Ticket length: {}", auth_ticket.len());
    info!("SteamID: {}", _steam.get_steam_id().raw());
    info!("ReservationID: {}", reservation.reservationid);


    let auth = SteamAuthInfo {
        steamid: _steam.get_steam_id().raw(),
        auth_ticket,
    };

    // this protobuf packet is encoded directly into the C2S_CONNECT packet
    // it contains all of our userinfo convars, and some of them are verified for integrity
    // in the authentication process
    let mut split_connect = CCLCMsg_SplitPlayerConnect::new();
    let mut convars = CMsg_CVars::new();

    let mut cvar = CMsg_CVars_CVar::new();
    cvar.set_name("cl_session".to_string());
    cvar.set_value(format!("${:#x}", reservation.reservationid));

    convars.cvars.push(cvar);

    split_connect.set_convars(convars);

    let mut player_connects = Vec::with_capacity(1);
    player_connects.push(split_connect);

    let conn = C2sConnect{
        host_version: chal.host_version,
        auth_protocol: AuthProtocolType::PROTOCOL_STEAM,
        challenge_num: chal.challenge_num,
        player_name: String::new(), // not used cs:go, uses "name" from the protobuf above^
        server_password: String::from("a59CdkwjR4"),
        num_players: 1, // no split screen
        split_player_connect: player_connects,
        low_violence: false,
        lobby_cookie: reservation.reservationid,
        crossplay_platform: CrossplayPlatform::Pc,
        encryption_key_index: 0, // no steam2 cert encryption
        auth_info: auth,
    };

    // send off the connect packet
    stream.send_packet(conn.into())?;

    // assuming everything worked out, we should get S2CConnection back, which means we have established
    // a netchannel
    // we actually receive two different S2C_Connection packets, neither of them actually matter.
    let _connection_pkt: S2cConnection = stream.recv_packet_type()?;
    let _connection_pkt: S2cConnection = stream.recv_packet_type()?;
    debug!("Connect packet: {:?}", &_connection_pkt);
    info!("Successfully established a netchannel.");

    let mut channel = NetChannel::upgrade(stream, chal.host_version)?;
    let mut signon = source::protos::CNETMsg_SignonState::new();
    signon.set_signon_state(2);

    let msg = NetMessage::from_proto(Box::new(signon), NET_Messages::net_SignonState as i32);
    let err = channel.write_netmessage(msg);
    debug!("Packet result: {:?}", &err);

    loop{
        // read incoming data
        let datagram = channel.read_data()?;
        if let Some(messages) = datagram.get_messages()
        {
            for msg in messages.into_iter()
            {
                trace!("* {}", msg.get_type_name());
            }
        }

        // blank message just to keep the other side updated
        channel.write_nop()?;
    }
    //::std::thread::sleep(std::time::Duration::from_millis(10000));
    //Ok(())
}

fn main() {

    let res: anyhow::Result<()> = run();

    if let Err(e) = res
    {
        info!("ERROR: {:?}", e);
    }
}
