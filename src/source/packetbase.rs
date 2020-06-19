use super::channel::*;
use anyhow::Result;
use super::packets::*;

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum ConnectionlessPacketType
{
    Invalid = 0 as u8,
    A2A_ACK = 106 as u8,
    A2A_PING = 105 as u8,
    A2S_INFO = 84 as u8,
    S2A_INFO_SRC = 73 as u8,
    A2S_GETCHALLENGE = 113 as u8,
    S2C_CHALLENGE = 65 as u8
}

impl From<u8> for ConnectionlessPacketType
{
    fn from(x: u8) -> ConnectionlessPacketType
    {
        match x
        {
            106 => ConnectionlessPacketType::A2A_ACK,
            105 => ConnectionlessPacketType::A2A_PING,
            84 => ConnectionlessPacketType::A2S_INFO,
            73 => ConnectionlessPacketType::S2A_INFO_SRC,
            113 => ConnectionlessPacketType::A2S_GETCHALLENGE,
            65 => ConnectionlessPacketType::S2C_CHALLENGE,
            _ => ConnectionlessPacketType::Invalid
        }
    }
}


#[allow(non_camel_case_types)]
#[enum_dispatch]
#[derive(Debug)]
pub enum ConnectionlessPacket
{
    A2aAck,
    A2aPing,
    A2sInfo,
    S2aInfoSrc,
    A2sGetChallenge,
    S2aChallenge
}

impl ConnectionlessPacket
{
    // get the type enum from a packet
    pub fn get_type(&self) -> ConnectionlessPacketType
    {
        match self
        {
            ConnectionlessPacket::A2aAck(_) => ConnectionlessPacketType::A2A_ACK,
            ConnectionlessPacket::A2aPing(_) => ConnectionlessPacketType::A2A_PING,
            ConnectionlessPacket::A2sInfo(_) => ConnectionlessPacketType::A2S_INFO,
            ConnectionlessPacket::S2aInfoSrc(_) => ConnectionlessPacketType::S2A_INFO_SRC,
            ConnectionlessPacket::A2sGetChallenge(_) => ConnectionlessPacketType::A2S_GETCHALLENGE,
            ConnectionlessPacket::S2aChallenge(_) => ConnectionlessPacketType::S2C_CHALLENGE,
        }
    }

    // serialize the packet to a byte array
    fn serialize_header(&self, target: &mut dyn ByteWriter) -> Result<()>
    {
        // SE determines netchannel vs. connectionless by the header
        target.write_long(CONNECTIONLESS_HEADER)?;

        // next is the id of the connectionless packet
        target.write_char(self.get_type() as u8)?;

        Ok(())
    }

    // serialize the packet to a channel
    pub fn serialize_to_channel(&self, target: &mut BufUdp) -> Result<()>
    {
        {
            // scratch space to serialize packet
            let scratch = target.get_scratch_mut();

            // reset length ptr
            scratch.clear();

            // serialize to scratch space
            self.serialize_header(scratch)?;
            self.serialize_values(scratch)?;
        }

        // send over channel
        target.send_raw(&target.get_scratch()[..])?;

        Ok(())
    }
}

pub const CONNECTIONLESS_HEADER: u32 = 0xFFFFFFFF;

#[enum_dispatch(ConnectionlessPacket)]
pub trait ConnectionlessPacketTrait
{
    // serialize extra packet information
    fn serialize_values(&self, _target: &mut dyn ByteWriter) -> Result<()>
    {
        // to be overridden
        Ok(())
    }
}

// A packet we are allowed to receive from the network
pub trait ConnectionlessPacketReceive: Sized
{
    fn get_type() -> ConnectionlessPacketType;

    // serialize extra packet information
    fn read_values(mut _packet: &[u8]) -> Result<Self>
    {
        // to be overridden
        Err(anyhow::anyhow!("read_values unimplemented"))
    }
}
