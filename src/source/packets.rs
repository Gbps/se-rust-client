use super::packetbase::ConnectionlessPacketTrait;
use super::packetbase::ConnectionlessPacketReceive;

use anyhow::Result;
use num_traits::{FromPrimitive, ToPrimitive};
use crate::source::ConnectionlessPacketType;
use super::bitbuf::*;

use super::protos::CCLCMsg_SplitPlayerConnect;
use protobuf::Message;

#[derive(Debug)]
pub struct A2aAck {}
impl ConnectionlessPacketTrait for A2aAck
{
}

#[derive(Debug)]
pub struct A2aPing {}
impl ConnectionlessPacketTrait for A2aPing
{
}

#[derive(Debug, Default)]
pub struct A2sInfo {}
impl ConnectionlessPacketTrait for A2sInfo
{
    fn serialize_values(&self, target: &mut BitBufWriterType) -> Result<()>
    {
        // write other header info
        target.write_string("Source Engine Query")?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct S2aInfoSrc {
    protocol_num: u8,
    host_name: String,
    map_name: String,
    mod_name: String,
    game_name: String,
    app_id: u16,
    num_players: u8,
    max_players: u8,
    num_bots: u8,
    dedicated_or_listen: u8, // 'd' = dedicated, 'l' = listen
    host_os: u8, // 'w' == windows, 'm' == macos, 'l' == linux
    has_password: u8,
    is_secure: u8,
    host_version_string: String,
}
impl ConnectionlessPacketTrait for S2aInfoSrc
{
}

impl ConnectionlessPacketReceive for S2aInfoSrc
{
    fn get_type() -> ConnectionlessPacketType
    {
        ConnectionlessPacketType::S2A_INFO_SRC
    }

    fn read_values(packet: &mut BitBufReaderType) -> Result<S2aInfoSrc>
    {
        Ok(S2aInfoSrc{
            protocol_num: packet.read_char()?,
            host_name: packet.read_string()?,
            map_name: packet.read_string()?,
            mod_name: packet.read_string()?,
            game_name: packet.read_string()?,
            app_id: packet.read_word()?,
            num_players: packet.read_char()?,
            max_players: packet.read_char()?,
            num_bots: packet.read_char()?,
            dedicated_or_listen: packet.read_char()?,
            host_os: packet.read_char()?,
            has_password: packet.read_char()?,
            is_secure: packet.read_char()?,
            host_version_string: packet.read_string()?,
        })
    }
}

// client requests challenge with server
#[derive(Debug)]
pub struct A2sGetChallenge
{
    // the "type" of challenge
    // normally in the form of "connect0xAABBCCDD"
    // where "connect0x00000000" is a perfectly valid conection string
    connect_string: String
}
impl ConnectionlessPacketTrait for A2sGetChallenge
{
    fn serialize_values(&self, target: &mut BitBufWriterType) -> Result<()>
    {
        // write other header info
        target.write_string(&self.connect_string)?;

        Ok(())
    }
}

impl Default for A2sGetChallenge
{
    // set the default challenge connect string
    fn default() -> A2sGetChallenge
    {
        A2sGetChallenge{
            connect_string: String::from("connect0x00000000")
        }
    }
}

impl A2sGetChallenge
{
    // create a challenge for a specific cookie
    pub fn with_challenge(cookie_value: u32) -> A2sGetChallenge
    {
        A2sGetChallenge {
            connect_string: format!("connect{:#010x}", cookie_value)
        }
    }
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
#[allow(non_camel_case_types)]
#[repr(u32)]
pub enum AuthProtocolType
{
    PROTOCOL_UNUSED = 0x01, // unused
    PROTOCOL_HASHEDCDKEY = 0x02, // only for misconfigured listen servers
    PROTOCOL_STEAM =	0x03,	// auth with steam, default
}

// server responds to challenge with additional server info
#[derive(Debug)]
pub struct S2cChallenge
{
    pub challenge_num: u32, // randomly generated challenge for this client
    pub auth_protocol: AuthProtocolType, // PROTOCOL_STEAM only
    pub steam2_encryption_enabled: u16, // 0 nowadays
    pub gameserver_steamid: u64, // gameserver's steamid
    pub vac_secured: u8, // 0 or 1
    pub context_response: String, // should be "connect0x...." on success, otherwise "connect-retry"
    pub host_version: u32, //server host version
    pub lobby_type: String, // "", "friends", or "public"
    pub password_required: u8, // 1 if password is required to connect
    pub lobby_id: u64, // -1 unless lobby matching is used
    pub friends_required: u8, // 0, unless lobby matching is used
    pub valve_ds: u8, // 1 if this is a valve hosted dedicated server
    pub require_certificate: u8, // 0, unless certificate authentication is used
    /* TODO: Certificate Authentication */
}
impl ConnectionlessPacketTrait for S2cChallenge {}
impl ConnectionlessPacketReceive for S2cChallenge
{
    fn get_type() -> ConnectionlessPacketType
    {
        ConnectionlessPacketType::S2C_CHALLENGE
    }

    fn read_values(packet: &mut BitBufReaderType) -> Result<S2cChallenge>
    {
        Ok(S2cChallenge {
            challenge_num: packet.read_long()?,
            auth_protocol: FromPrimitive::from_u32(packet.read_long()?).ok_or(anyhow::anyhow!("Invalid auth protocol"))?,
            steam2_encryption_enabled: packet.read_word()?,
            gameserver_steamid: packet.read_longlong()?,
            vac_secured: packet.read_char()?,
            context_response: packet.read_string()?,
            host_version: packet.read_long()?,
            lobby_type: packet.read_string()?,
            password_required: packet.read_char()?,
            lobby_id: packet.read_longlong()?,
            friends_required: packet.read_char()?,
            valve_ds: packet.read_char()?,
            require_certificate: packet.read_char()?,
        })
    }
}

impl S2cChallenge
{
    // if true, the client should retry with the given cookie value
    pub fn should_retry(&self) -> bool
    {
        self.context_response == "connect-retry"
    }
}

#[derive(FromPrimitive, ToPrimitive, Debug)]
pub enum CrossplayPlatform
{
    Unknown,
    Pc,
    X360,
    Ps3
}

#[derive(Debug)]
pub struct SteamAuthInfo
{
    pub steamid: u64,
    pub auth_ticket: Vec<u8>,
}

#[derive(Debug)]
pub struct C2sConnect
{
    pub host_version: u32,
    pub auth_protocol: AuthProtocolType,
    pub challenge_num: u32,
    pub player_name: String,
    pub server_password: String,
    pub num_players: u8,
    pub split_player_connect: Vec<CCLCMsg_SplitPlayerConnect>,
    pub low_violence: bool,
    pub lobby_cookie: u64,
    pub crossplay_platform: CrossplayPlatform,
    pub encryption_key_index: u32,
    pub auth_info: SteamAuthInfo,
}

impl ConnectionlessPacketTrait for C2sConnect
{
    fn serialize_values(&self, target: &mut BitBufWriterType) -> Result<()>
    {
        // write fields
        target.write_long(self.host_version)?;
        target.write_long(ToPrimitive::to_u32(&self.auth_protocol).ok_or(anyhow::anyhow!("Invalid auth protocol"))?)?;
        target.write_long(self.challenge_num)?;
        target.write_string(&self.player_name)?;
        target.write_string(&self.server_password)?;
        target.write_char(self.num_players)?;

        for player_num in 0..self.num_players
        {
            // netmessage number, not used
            target.write_int32_var(0)?;

            let encoded = self.split_player_connect[player_num as usize].write_to_bytes()?;
            target.write_int32_var(encoded.len() as u32)?;
            target.write_bytes(&encoded)?;
        }

        // more fields
        target.write_bit(self.low_violence)?;
        target.write_longlong(self.lobby_cookie)?;
        target.write_char(ToPrimitive::to_u8(&self.crossplay_platform).ok_or(anyhow::anyhow!("Invalid crossplay platform"))?)?;
        target.write_long(self.encryption_key_index)?;

        // auth info fields
        target.write_word((self.auth_info.auth_ticket.len() as u16)+8)?;
        target.write_longlong(self.auth_info.steamid)?;
        target.write_bytes(&self.auth_info.auth_ticket)?;

        // what genius though "oh, let's use a single bit to represent
        // low_violence and just leave this entire thing unaligned to a single byte...
        for _i in 0..7 {
            target.write_bit(false)?;
        }
        Ok(())
    }
}