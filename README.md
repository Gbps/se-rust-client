# WIP WIP WIP WIP

# It does work!

A full game authentication is performed with Steam's GC as well as the game server itself. Net messages have been successfully sent and received with a community game server.

```
 TRACE se_client::source::subchannel > Fragments successfully decompressed
 TRACE se_client::source::channel    > --- read_messages() begin ---
 TRACE se_client::source::channel    > MESSAGE [id=16, size=113]: <-- svc_Print
 TRACE se_client::source::channel    > MESSAGE [id=34, size=518]: <-- svc_CmdKeyValues
 TRACE se_client::source::channel    > MESSAGE [id=8, size=114]: <-- svc_ServerInfo
 TRACE se_client::source::channel    > MESSAGE [id=4, size=8]: <-- net_Tick
 TRACE se_client::source::channel    > MESSAGE [id=12, size=2630]: <-- svc_CreateStringTable
  TRACE se_client::source::channel    > MESSAGE [id=12, size=12502]: <-- svc_CreateStringTable
   TRACE se_client::source::channel    > MESSAGE [id=12, size=34]: <-- svc_CreateStringTable
    TRACE se_client::source::channel    > MESSAGE [id=12, size=43067]: <-- svc_CreateStringTable
```

# Emulating a source client signon

Source engine's signon process has gotten significantly more complicated over the years as CS:GO has transitioned to matchmaking rather than direct IP connection. In addition, the invention of Steam Game Sockets means that now the traffic that's being communicated between the client and the server is being proxied over a relay network embedded in the Steam backbone.

For this purpose, I'm focusing on the most basic kind of gameserver connection, one that is done directly over UDP to a target port.

For this project, I decided to use Rust to implement the networking... because why not, it's fun and I'm learning the new language.

## Connectionless Packets

Source engine has two kinds of communications with a game client, Connectionless and NetChan. Both of these happen over UDP. Connectionless packets are plain unencrypted UDP packets with a 4 byte `0xFFFFFFFF` header specifying that they are connectionless. Anyone can send a connectionless packet to a game server's UDP port (typically 27015). Typically this is used for querying information about the server before forming an actual connection, such as the legacy server browser which queried information about the current state and map of the server and displays it in a UI before the user connects.

## Forming a new connection: Challenge

When *not* using matchmaking, everything about a connection begins from a client when the `connect` concommand (or similar) is executed pointing the client to connect to a certain ip and port. This bubbles down to the following function:

```c++
(baseclientstate.cpp:1058): 
void CBaseClientState::ConnectInternal( const char *pchPublicAddress, char const *pchPrivateAddress, int numPlayers, const char* szJoinType )
```

Here is the first instance of the function `SetSignonState` being run, which sets the current state of the state machine of the handshake between the server and the client. 

```c++
(baseclientstate.cpp:1089): 
SetSignonState( SIGNONSTATE_CHALLENGE, -1, NULL );
```

Here are all of the states the client and server can be in for a single client connection. At all points of the process, the client and server must agree at what signon state the handshake is in or the process fails.

```c++
enum SIGNONSTATE
{
	SIGNONSTATE_NONE		= 0,	// no state yet; about to connect
	SIGNONSTATE_CHALLENGE	= 1,	// client challenging server; all OOB packets
	SIGNONSTATE_CONNECTED	= 2,	// client is connected to server; netchans ready
	SIGNONSTATE_NEW			= 3,	// just got serverinfo and string tables
	SIGNONSTATE_PRESPAWN	= 4,	// received signon buffers
	SIGNONSTATE_SPAWN		= 5,	// ready to receive entity packets
	SIGNONSTATE_FULL		= 6,	// we are fully connected; first non-delta packet received
	SIGNONSTATE_CHANGELEVEL	= 7,	// server is changing level; please wait
};
```

> OOB packets are synonymous with connectionless packets

This queues the client to begin sending packets to the server requesting a challenge. The actual request of the challenge happens here:

```c++
(baseclientstate.cpp:1381): 
void CBaseClientState::CheckForResend ( bool bForceResendNow /* = false */ )
```

This function is responsible for repeatedly poking the server and asking for a connection challenge. The packet used to request this challenge is `A2S_GETCHALLENGE` and the payload is of the pseudo-structure form:

```
{
	CONNECTIONLESS_HEADER: u32
	TYPE: u8 = A2S_GETCHALLENGE
	CONNECTION_STRING: String = "connect0xAABBCCDD"
}
```

Where the connection string is of the format `connect0x%08X` appending a 4-byte challenge to the message. This challenge is always equal to the *last* challenge value received from *any* server that the client tried to connect to. Otherwise, if the client just launched, this value is equal to `0x00000000`.

Now, the server receives the OOB `A2S_GETCHALLENGE` from a client and processes the inner message to see that it is a `connect` message. It then builds a response, of OOB type `S2C_CHALLENGE`. This takes place in:

```cpp
(baseserver.cpp:1631): 
void CBaseServer::ReplyChallenge( const ns_address &adr, bf_read &inmsg )
```

The server then randomly generates a challenge number to use for the connection and stores it into a large vector of all challenges for all clients that have ever tried to initiate a connection.

The expected result is that the server will respond with `connect-retry` and the cookie the server wants the client to send. Then, on the next attempt, the client will try again but with the requested value. The server will then accept it and respond with a context of `connect` instead.

It then writes back the response:

* [32] Connectionless Header
* [8] Type of connectionless packet
* [32] Randomly generated challenge number from above
* [32] Auth protocol, always `PROTOCOL_STEAM=0x03`
* [16] Steam2 encryption enabled bool? 1/0 (Always 0 now, a different kind of encryption is used)
* [64] Steam gameserver steamid
* [8] Is the game server VAC secured? 1/0

> PROTOCOL_STEAM is always used over PROTOCOL_HASHEDCDKEY except if the server is a listen server on a client which has no steam connection

Gameservers now all have their own steam id, either linked with a steam account or using an anonymous steam id. It can be used to uniquely identify a server, regardless of IP.

Next is the response of the the challenge which determines if the client is allowed to connect. A few factors go into this decision

* Is the server locked to only allow certain lobbies to join?

  * If so, check to make sure the challenge value sent by the client is correct. If not, respond `connect-retry`.

  * If direct connections are not allowed:
    * If it is a Valve Dedicated Server, respond with `connect-matchmaking-only` since Valve DS do not support direct connections, only connections made through their matchmaking system. This is particularly more difficult to trigger now because all Valve DS now hide behind the Steam Socket relays, which means packets are routed directly to the game server through the relay and not over the public internet. More investigation on this later.
    * Otherwise, if it's not a Valve DS, respond with `connect-lan-only` meaning it is a community CS:GO server which is locked down for only LAN connections.

* Otherwise, if the server isn't lobby only, just respond with the requested context (`connect0x....` same as requested context)

* [32] The host version
* [String] The lobby type ("" if unsuccessful, "public" if successful)
* [8] Password required? 1/0
* *some extra valve-specific matchmaking logic*
* [64] Lobby id (always -1 unless lobbies are in use)
* [8] Friends required? (always 0)
* [8] Is valve dedicated server? 1/0
* [8] Requires certificate authentication? 1/0 (should always be 0 unless it's a *special* community game server... maybe something like FACEIT?)
  * If certificate authentication is requested writes the following:
  * [32] size of public key
  * [y bytes] where y is the size of the public key
  * [32] size of encryption signature
  * [z bytes] where z is the size of the encryption signature

That's a big packet.

So at this point it should look like this:

* [client sends A2S_GETCHALLENGE and empty challenge value]

* [server responds with a random challenge in S2C_CHALLENGE]

* [client responds with server's challenge in another A2S_GETCHALLENGE]

* [server responds with success in another S2C_CHALLENGE]

and now both sides have verified the challegne.

Here is a dump of a successful challenge:

```
[src\main.rs:35] &packet = A2sGetChallenge {
    connect_string: "connect0x00000000",
}
[src\main.rs:40] &_res = S2cChallenge {
    challenge_num: 233306117,
    auth_protocol: PROTOCOL_STEAM,
    steam2_encryption_enabled: 0,
    gameserver_steamid: 90136361812869131,
    vac_secured: 0,
    context_response: "connect-retry",
    host_version: 13758,
    lobby_type: "public",
    password_required: 0,
    reservation_cookie: 18446744073709551615,
    friends_required: 0,
    valve_ds: 0,
    require_certificate: 0,
}
[src\main.rs:44] &packet = A2sGetChallenge {
    connect_string: "connect0x0de7f805",
}
[src\main.rs:49] &_res = S2cChallenge {
    challenge_num: 233306117,
    auth_protocol: PROTOCOL_STEAM,
    steam2_encryption_enabled: 0,
    gameserver_steamid: 90136361812869131,
    vac_secured: 0,
    context_response: "connect0x0de7f805",
    host_version: 13758,
    lobby_type: "public",
    password_required: 0,
    reservation_cookie: 18446744073709551615,
    friends_required: 0,
    valve_ds: 0,
    require_certificate: 0,
}
```

## Connect packet + NetChannel creation

Once the challenge handshake is complete, the client calls into:

```cpp
void CBaseClientState::SendConnectPacket ( const ns_address &netAdrRemote, int challengeNr, int authProtocol, uint64 unGSSteamID, bool bGSSecure )
```

to send the `C2S_CONNECT` packet to initiate a netchannel. The connect packet contains extra misc. information about the client. The important part of this packet is the User Info block, which is responsible for encoding all of the CVars on the client marked with `FCVAR_USERINFO`. All of these cvars are marked as such because the server wants to be able to query these without having to do a roundtrip with the client. An example of an `FCVAR_USERINFO` CVar would be `name`, which stores the name of the player they want to use.

This packet is the first instance of Protobuf packets being used in the connection. In the CS:GO version of the engine and beyond, most all packet communication is done using Protobuf packets. Prior to the introduction of Protobuf, everything was done manually by writing and reading values from buffers similarly to how the Connectionless packets still function. Now Protobuf handles that automatically.

This packet is especially curious because it is not a Protobuf packet in itself, but it contains an embedded Protobuf packet. Specifically, it contains the Protobuf packet called `CCLCMsg_SplitPlayerConnect`, which stores all of the User Info CVars talked about previously. Only cvars actually modified from their default value will be sent, otherwise it is assumed on the server to be default values. For each split player connecting, there will be a `CCLCMsg_SplitPlayerConnect` protobuf packet encoded into the packet. All CVars are sent as strings, even if their actual values are integers or floats. The server will interpret these string values as any kind of integer value when it receives the cvars.

The protobuf definition is given to us from Valve:

```protobuf
message CCLCMsg_SplitPlayerConnect
{
	optional CMsg_CVars convars = 1;
}
```

The actual CVars are iterated and added to the Protobuf packet in the function:

```cpp
Host_BuildUserInfoUpdateMessage( playerCount, splitMsg.mutable_convars(), false );
```

Something special about this protobuf message is that the different cvars can be encoded into an index form instead of a full name. These cvars are hardcoded the list appears to include all of the userinfo cvars that are typically sent as part of a connection. Here is the list of all cvars that are encoded this way:

* accountid
* password
* cl_use_opens_buy_menu
* tv_nochat
* cl_clanid
* name
* cl_interp_ratio
* cl_predict
* cl_updaterate
* cl_session
* voice_loopback
* cl_lagcompensation
* cl_color
* cl_cmdrate
* net_maxroutable
* rate
* cl_predictweapons
* cl_autohelp
* cl_interp
* cl_autowepswitch
* cl_spec_mode
* tv_relay
* hltv_slots
* hltv_clients
* hltv_addr
* hltv_proxies
* sv_bot_difficulty_kbm
* hltv_sdr
* steamworks_sessionid_client
* sdr_routing

These can of course also be sent by name rather by index. This seems to mostly be done for performance reasons.

In addition, this is where the Steam authentication process begins.

The call to `GetAuthSessionTicket` is a steamapi function which `Retrieve ticket to be sent to the entity who wishes to authenticate you.` 

The total auth buffer is a combination of:

```
[64] int64 steamid
[X ] auth session ticket
[64] size of ticket + steamid 
```

Then the auth buffer is written in the following form:

```
[16] Size of steam cookie
[X] Auth buffer
```

A curious part of this entire auth buffer is that it has two separate sizes, one for the cookie entirely and another for the size of the ticket itself.

Here's the format:

* [32] Connectionless Packet Header

* [8] C2S_CONNECT

* [32] Host version (in CS:GO this always matches the server, since this version is checked later)

* [32] Authentication protocol (should match server, always `PROTOCOL_STEAM`)

* [32] Challenge number (same from the challenge from `S2C_CHALLENGE`)

* [String] Player name. Not used in CS:GO, this is read from the user info instead.

* [String] Server password to authenticate with, if one is used.

* [8] The number of players preparing to connect. In split screen this could be 2, but typically it is 1.

* [X ] The inline encoded `CCLCMsg_SplitPlayerConnect` for each player (This uses Source Engine's own wrapper for netmessage packets)

* [1] Low violence enabled [NOTE: this is a *single* bit]

* [64] Server reservation cookie

* [8] Current crossplay platform 

  * ```
    enum CrossPlayPlatform_t
    {
    	CROSSPLAYPLATFORM_UNKNOWN = 0,
    	CROSSPLAYPLATFORM_PC,
    	CROSSPLAYPLATFORM_X360,
    	CROSSPLAYPLATFORM_PS3,
    
    	CROSSPLAYPLATFORM_LAST = CROSSPLAYPLATFORM_PS3,
    };
    ```

* [32] If no certificate encryption is used, a 0 is written here.

* [X ] Steam authentication buffer

  * [16] Size of following fields
    * [64] int64 steamid
    * [X ] auth session ticket returned from steam api
    * [64] size of ticket + steamid 

```
-> Reservation cookie 9a2a387bc911bda3:  reason [R] Connect from 192.168.1.100:27005
```

## On Fragments
So most of my time implementing subchannels is learning how fragments actually work. Here's what I've learned so far:

* There are 8 subchannels and 2 streams.
* A stream is either a message (default) steam (index=0) or a file stream (index=1).
* A message stream sends reliable netmessages (large)
* In this case, I believe it's sending the server info and delta updates to us all at once
* The message stream being sent to me has been compressed at the fragment level. Basically LZSS compression is done on the entire payload prior to starting the send. At the beginning of the start of a new transfer on a stream, the sending end alerts the receiving end of the uncompressed and compressed sizes, then starts to send the compressed data in fragments.
* Fragments are 256 byte chunks of data of the overall payload. Can think of the total payload as being split up into these fragment chunks. So rather than transferring to 
* A subchannel is a single instance of a set of fragments being sent. There are 8 of them, one bit to fill the byte in the header. 
  * 
  * Basically, you can think of these like 8 simultaneous transfers, where each individual transfer can mark itself as completed when it's received
  * This is because UDP is not a reliable protocol, so out of order and lost fragments need to be marked and recovered from.
* When sending over a set of, for example, 4 fragments (fragment size = 256, total size = 1024), it will send over a free subchannel (starts at 0). Then when the receiver gets it, it will mark the 0th index bit in its `reliable_state` on its next packet it sends off. Then, when the sender sends the next 4 fragments, it will send it over the next free subchannel (index 1). This will repeat with the sender rotating the free subchannels and the receiver flipping the bit in the reliable state.

# Signon: CONNECTED -> NEW

So, now that we've authenticated and connected and formed a netchannel, the first thing the client must do is send a set signon message to set the signon to `CONNECTED`. This initiates the server to send the set of reliable netmessages to get the player ready to spawn in on their side.

Here are all of the messages sent in the reliable (subchannel) buffer:

* svc_Print - Prints some general info about the server to the client's console:

  * ```
    Counter-Strike: Global Offensive
    Map: de_dust2
    Players: 1 (0 bots) / 20 humans
    Build: 8012
    Server Number: 88
    ```

* svc_CmdKeyValues - `TODO`

* svc_ServerInfo - Contains info about the entity classes and some additional things like the map name and skybox name. Mostly just misc things.

  * ```
     Server Info: protocol: 13770 server_count: 88 is_dedicated: true is_hltv: false is_redirecting_to_proxy_relay: false c_os: 119 map_crc: 282161188 client_crc: 1473533612 string_table_crc: 0 max_clients: 64 max_classes: 283 player_slot: 0 tick_interval: 0.015625 game_dir: "csgo" map_name: "de_dust2" map_group_name: "" sky_name: "nukeblank" host_name: "Counter-Strike: Global Offensive" ugc_map_id: 0
    ```

* net_Tick - Synchronize the server's tick count

* net_SetConVar - A message containing all of the replicated convars set by the server:

  * ```
     DEBUG se_client::source::gamelogic  > Set ConVar: [name=bot_autodifficulty_threshold_high] [value=0]
     DEBUG se_client::source::gamelogic  > Set ConVar: [name=cash_team_win_by_defusing_bomb] [value=2700]
     [...]
    ```

* svc_CreateStringTable - a create string table message for each of the string tables on the server, including its data

  * downloadables
  * modelprecache
  * genericprecache
  * soundprecache
  * decalprecache
  * instancebaseline
  * lightstyles
  * userinfo
  * dynamicmodel
  * server_query_info
  * ExtraParticleFilesTable
  * ParticleEffectNames
  * EffectDispatch
  * VguiScreen
  * Materials
  * InfoPanel
  * Scenes
  * Movies
  * GameRulesCreation

* svc_SignonState - Sets the client's signon state from CONNECTED to NEW.

# Signon (client): CONNECTED (old) -> NEW (new)

When the above finishes, next the client calls `SendClientInfo` which constructs a `CCLCMsg_ClientInfo` to send to the server. Fields here include:

- the SendTable CRC
- The "server count" (kind of like a uid for this particular attempt to connect)
- is_hltv
- is_replay
- friends id (from steam)
- friends name (from steam)
- any custom files (sprays)

Then the client sends a `net_SignonState` for `NEW` containing the spawn_count from the last `net_SignonState` received. This must always be sent on new signon updates, else the server will force a reconnect.

Unfortunately, there is no good way to calculate the send tables CRC on the client.

# Signon (server): NEW (old) -> PRESPAWN (new)

Server verifies the class tables CRC to match its own. If it's invalid (aka the client binary is out of date) it will disconnect with `Server uses different class tables`. This is what spawned me to write the `crcgrab.exe` project which signature scans for the class table crc value and then ReadProcessMemory's it from a real csgo.exe instance.

Server sends the signon data buffer to the client. This signon data is the same thing sent to all clients. It consists of every call to `BroadcastMessage` with `IsInitMessage` set made by the server during this map load. This catches up the client to everything that happened. I am not convinced there are any packets marked with `FLAG_INIT_MESSAGE` right now in the engine.

The server sends a signon state `PRESPAWN` to client.

