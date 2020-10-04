use steamworks::Manager;
use crate::protoutil;
use crate::source::BufUdp;
use crate::source::bitbuf::{BitBufWriterType, WireWriter};
use anyhow::*;
use bitstream_io::{BitWriter, LittleEndian};
use smallvec::{smallvec, SmallVec};

// a netmessage packet, either to be sent or received from the network
pub struct NetMessage<M>
    where M: ::protobuf::Message
{
    // the netmessage enum identifier for this message
    id: u32,

    // the size of this encoded message
    size: u32,

    // the internal protobuf message for this netmessage
    message: M,

    // internal encoding buffer
    buf: Vec<u8>
}

impl<M> NetMessage<M>
    where M: ::protobuf::Message
{
    // get the inner proto message
    pub fn inner(&self) -> &M
    {
        return &self.message;
    }

    // get the netmessage enum id
    pub fn get_id(&self) -> u32
    {
        return self.id;
    }

    // get the size of the encoded message
    pub fn get_size(&self) -> u32
    {
        return self.size;
    }

    // get the maximum size of the encoded message with the header
    pub fn get_max_size(&self) -> usize
    {
        return (self.size + 8) as usize;
    }

    // write the netmessage (with header) to a vector, clears the vector beforehand
    pub fn encode_to_buffer(&mut self, buf: &mut Vec<u8>) -> anyhow::Result<()>
    {
        // TODO: Encode message directly to buf

        // create a stack/heap allocated buffer hopefully to optimize small netmessage encodings
        let mut encode_buf: SmallVec<[u8; 2048]> = SmallVec::with_capacity(self.size as usize);

        let mut cursor = std::io::Cursor::new(buf);
        let mut writer = BitWriter::endian(cursor, LittleEndian);

        // encode the proto message
        self.message.write_to_writer(&mut encode_buf)?;

        // write the netmessage header and proto message
        writer.write_int32_var(self.id)?;
        writer.write_int32_var(self.size)?;
        writer.write_bytes(&encode_buf)?;

        Ok(())
    }

    // create a message to send from a proto message and the id of the message
    pub fn from_message(message: M, id: u32) -> Self {
        NetMessage{
            id,
            size: message.compute_size(),
            message,
            buf: Vec::with_capacity(4096)
        }
    }

    // create a message from a network buffer
    pub fn from_buffer(message: &[u8], id: u32) -> anyhow::Result<Self> {
        let msg: M = protoutil::deserialize(message)?;

        Ok(NetMessage{
            id,
            size: msg.get_cached_size(),
            message: msg,
            buf: Vec::with_capacity(4096)
        })
    }
}