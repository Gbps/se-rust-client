use steamworks::*;
use std::time::Duration;
use std::thread::JoinHandle;
use std::sync::{Arc, Mutex, mpsc};
use std::net::{Ipv4Addr};
use anyhow::Context;
use csgogcprotos::gcsystemmsgs::{EGCBaseClientMsg};
use csgogcprotos::cstrike15_gcmessages::{ECsgoGCMsg, CMsgGCCStrike15_v2_MatchmakingGC2ClientHello, CMsgGCCStrike15_v2_ClientRequestJoinServerData};
use crate::steam::protoutil;

/// Represents the state of a logged in steam client
pub struct SteamClient
{
    /// Multi-threaded interface
    _client: Client<ClientManager>,

    /// Game coordinator packet queue
    gc_queue: GCMessageQueue<ClientManager>,

    /// Thread object responsible for constantly calling Steam callbacks
    _main_thread: JoinHandle<()>,

    /// The current internal state of this client
    state: Arc<Mutex<SteamClientState>>,
}

/// The current internal state of the steam client
pub struct SteamClientState
{
    /// CS:GO Matchmaking Account ID, received from matchmaking hello
    accountid: u32,
}

/// The result of a call to `request_join_server`
#[derive(Debug)]
pub struct JoinServerReservation
{
    /// The steamid of the server
    pub serverid: u64,

    /// The IP address which Steam asks us to connect to
    pub direct_udp_ip: Ipv4Addr,

    /// Port which Steam asks us to connect to
    pub direct_udp_port: u32,

    /// The reservation ID, used in the C2S_CONNECT packet to verify
    /// a successful Steam request to join
    pub reservationid: u64,
}

/// Helper to transform an enum into a proto id
fn proto_id(msg_type: u32) -> u32
{
    return 0x80000000 | (msg_type);
}

impl SteamClient {
    /// Connect to Steam and the Game Coordinator
    /// Returns an active client
    pub fn connect() -> anyhow::Result<SteamClient>
    {
        // create a steam client interface... the user must be logged in already on Steam
        let res = Client::init();
        if let Err(e) = res {
            return Err(anyhow::anyhow!("Steam error: {}", e))
        }

        let (client, single) = res.unwrap();

        // create a gc packet connection
        let gc_queue = GCMessageQueue::new(client.clone());

        // create a thread to constantly call steam callbacks
        let main_thread = SteamClient::spawn_main_thread(single, Duration::from_millis(10));

        // internal state keeping that is updated when callbacks fire for certain packets
        let state = Arc::new(Mutex::new(SteamClientState{
            accountid: 0xFFFFFFFF,
        }));

        // create steam client object
        let steam = SteamClient {
            _client: client,
            gc_queue,
            _main_thread: main_thread,
            state
        };

        // perform a handshake to login to the GC
        steam.do_hello_handshake()?;

        Ok(steam)
    }


    /// Helper function which wraps a GC packet callback to automatically deserialize a protobuf message
    /// of a particular type before calling the supplied `callback` function.
    ///
    /// # Arguments
    ///
    /// * `enum_val` - The value of the packet type enum converted to a u32. The proto flag is automatically set.
    /// * `callback` - A callback function which accepts one argument, which is a protobuf::Message. This will be
    ///                whatever type is specified by the `ProtoMsgType` type parameter.
    ///
    /// # Example
    /// ```
    ///  let _cb = self.proto_callback_wrapper::<CMsgGCCStrike15_v2_MatchmakingGC2ClientHello, _>
    ///         (
    ///             ECsgoGCMsg::k_EMsgGCCStrike15_v2_MatchmakingGC2ClientHello as u32,
    ///             move |pkt| {
    ///                 let account_id = pkt.get_account_id();
    ///                 println!("Logged into CS:GO Matchmaking accountid='{}'", account_id);
    ///             }
    ///         );
    ///```
    fn proto_callback<ProtoMsgType, CbProto>(&self, enum_val: u32, mut callback: CbProto) -> PktCallbackHandle
        where CbProto: FnMut(ProtoMsgType) + Send + 'static,
              ProtoMsgType: Send + protobuf::Message
    {
        self.gc_queue.install_callback(
            proto_id(enum_val),
            move |_pkt| {
                // decode protobuf packet
                let res = protoutil::deserialize::<ProtoMsgType>(&_pkt.body).unwrap();
                callback(res);
            }
        )
    }

    /// Helper function which performs a protobuf request to the game coordinator and waits on a response for a duration.
    /// When the response is received, calls `callback` with the decoded results of the packet.
    ///
    /// # Arguments
    ///
    /// * `to_send_type` - The packet enum value for the request being sent
    /// * `to_send`      - The `protobuf::Message` structure for the packet being sent
    /// * `to_recv_type` - The packet enum value for the response packet
    /// * `timeout`      - A timeout duration before the call fails and returns Err
    /// * `callback`     - A callback which is executed in a separate thread when the response packet is received.
    ///                    The first argument is a protobuf type specified by `RecvMsgType` of message id `to_recv_type`.
    /// # Example
    /// ```
    ///         self.do_request::<CMsgGCCStrike15_v2_ClientRequestJoinServerData, _, _>(
    ///             ECsgoGCMsg::k_EMsgGCCStrike15_v2_ClientRequestJoinServerData as u32,
    ///             msg,
    ///             ECsgoGCMsg::k_EMsgGCCStrike15_v2_ClientRequestJoinServerData as u32,
    ///             Duration::from_millis(1000),
    ///             move |pkt| {
    ///                println!("Received packet!");
    ///             }
    ///         )?;
    /// ```
    fn do_request<RecvMsgType, CbProto, SendMsgType>(
        &self,
        to_send_type: u32,
        to_send: SendMsgType,
        to_recv_type: u32,
        timeout: Duration,
        mut callback: CbProto
    ) -> anyhow::Result<()>
        where CbProto: FnMut(RecvMsgType) + Send + 'static,
              SendMsgType: Send + protobuf::Message,
              RecvMsgType: Send + protobuf::Message
    {
        let (sender, receiver) = mpsc::sync_channel::<bool>(1);
        let sender_cl = sender.clone();

        let _cb = self.proto_callback::<RecvMsgType, _>
        (
            to_recv_type as u32,
            move |pkt| {
                callback(pkt);
                sender_cl.send(true).unwrap();
            }
        );

        // send request
        if !self.gc_queue.send_message(
            proto_id(to_send_type),
            &protoutil::serialize(to_send)?) {
            return Err(anyhow::anyhow!("Could not send message {}", to_send_type))
        }

        // wait a bit for the response
        receiver
            .recv_timeout(timeout)
            .context("Timeout while waiting for message")?;

        return Ok(())
    }

    /// Get an authentication ticket to authenticate with a server.
    ///
    /// This ticket must be sent to the server to verify that your user's identity
    /// and that you own the game.
    pub fn get_auth_ticket(&self) -> anyhow::Result<Vec<u8>>
    {
        let steam_user = self._client.user();

        // discarding auth_handle because we don't plan to ever cancel this ticket
        let (_auth_handle, ticket) = steam_user.authentication_session_ticket();

        return Ok(ticket)
    }

    /// Get the SteamID of the currently logged in user.
    pub fn get_steam_id(&self) -> steamworks::SteamId
    {
        return self._client.user().steam_id();
    }

    /// Send a request to join a server and wait on the result
    /// Returns a `JoinServerReservation` struct which represents the server reservation
    pub fn request_join_server(&self, version: u32, serverid: u64, server_ip: u32, server_port: u32) -> anyhow::Result<JoinServerReservation>
    {
        let mut msg = CMsgGCCStrike15_v2_ClientRequestJoinServerData::new();

        // matchmaking accountid, derived from steamid but held from matchamking  hello
        msg.set_account_id(self.state.lock().unwrap().accountid);
        // version of the client connecting
        msg.set_version(version);
        // server's steamid
        msg.set_serverid(serverid);
        // server's ip (as we know it)
        msg.set_server_ip(server_ip);
        // server's port (as we know it)
        msg.set_server_port(server_port);

        // channel to wait on reservation when it comes in
        let (send, recv) = mpsc::sync_channel(1);

        // perform the request to join a server
        self.do_request::<CMsgGCCStrike15_v2_ClientRequestJoinServerData, _, _>(
            ECsgoGCMsg::k_EMsgGCCStrike15_v2_ClientRequestJoinServerData as u32,
            msg,
            ECsgoGCMsg::k_EMsgGCCStrike15_v2_ClientRequestJoinServerData as u32,
            Duration::from_millis(1000),
            move |pkt| {
               // we got a reservation from the server
               let reservation = pkt.res.unwrap();

               // interpret the protobuf packet into a structure we actually want to return
               let reservation = JoinServerReservation{
                   reservationid: reservation.get_reservationid(),
                   direct_udp_ip: Ipv4Addr::from(reservation.get_direct_udp_ip()),
                   direct_udp_port: reservation.get_direct_udp_port(),
                   serverid: reservation.get_serverid()
               };

               // send that over the channel, which will hit the recv.recv() and unblock it
               send.send(reservation).unwrap();
            }
        )?;

        // wait until the request finishes or times out
        return Ok(recv.recv()?);
    }

    /// Send a client hello and block waiting for the response
    /// If successfully connected, returns Ok(). Otherwise, returns an error if the timeout was reached
    /// or there was an error sending.
    fn do_hello_handshake(&self) -> anyhow::Result<()>
    {
        let mut result : anyhow::Result<bool> = Ok(true);

        let (sender, receiver) = mpsc::sync_channel::<bool>(1);
        let sender_cl = sender.clone();
        let state_cl = self.state.clone();

        // prepare to receive the welcome message
        // cleans up callback after function exit
        let _cb = self.proto_callback::<CMsgGCCStrike15_v2_MatchmakingGC2ClientHello, _>
        (
            ECsgoGCMsg::k_EMsgGCCStrike15_v2_MatchmakingGC2ClientHello as u32,
            move |pkt| {
                let account_id = pkt.get_account_id();

                println!("Logged into CS:GO Matchmaking accountid='{}'", account_id);

                // remember our account id in the steam state
                state_cl.lock().unwrap().accountid = account_id;

                // alert that we've successfully logged in
                sender_cl.send(true).unwrap();
            }
        );

        // give it a few tries, since sometimes it takes steam a bit to warm up
        for _i in 0..10
        {
            // send a login request to the GC
            if !self.gc_queue.send_message(
                proto_id(EGCBaseClientMsg::k_EMsgGCClientHello as u32),
                &[]) {
                return Err(anyhow::anyhow!("Could not send GC hello"))
            }

            // wait a bit for the response
            result = receiver
                .recv_timeout(Duration::from_millis(1000))
                .context("Timeout while waiting for GC welcome.");

            // did we get a welcome? okay we're good to go, don't retry again
            if let Ok(_) = result {
                return Ok(())
            }
        }

        // we tried some times and failed, must be a true timeout
        Err(result.unwrap_err())
    }

    /// Spawn the main callback handling thread
    fn spawn_main_thread(single: SingleClient<ClientManager>, callback_interval: Duration) -> JoinHandle<()> {
        std::thread::spawn(move || {
            // loop constantly calling steam callbacks every 'frame'
            loop {
                single.run_callbacks();
                ::std::thread::sleep(callback_interval);
            }
        })
    }
}
