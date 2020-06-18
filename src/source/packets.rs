use super::packetbase::ConnectionlessPacketTrait;
use anyhow::Result;
use super::channel::ByteWriter;
use super::channel::ByteReader;

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

#[derive(Debug)]
pub struct A2sInfo {}
impl ConnectionlessPacketTrait for A2sInfo
{
    fn serialize_values(&self, target: &mut dyn ByteWriter) -> Result<()>
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

impl S2aInfoSrc
{
    pub fn read_values(mut packet: &[u8]) -> Result<S2aInfoSrc>
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