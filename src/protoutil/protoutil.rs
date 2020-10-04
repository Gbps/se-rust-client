use std::io::Write;

/// Deserialize a protobuf message from its bytes representation
pub fn deserialize<M>(bytes: &[u8]) -> anyhow::Result<M>
    where M: protobuf::Message
{
    let res = protobuf::parse_from_bytes::<M>(&bytes)?;
    return Ok(res);
}

/// Serialize a protobuf message into its bytes representation
pub fn serialize<M>(proto_msg: M) -> anyhow::Result<Vec<u8>>
    where M: protobuf::Message
{
    // establish some vector space
    let mut vec = Vec::with_capacity(proto_msg.get_cached_size() as usize);

    // write the message to the vector
    proto_msg.write_to_vec(&mut vec)?;

    return Ok(vec);
}

/// Clears the buffer and writes a protobuf message to it
pub fn serialize_to_buffer<M>(proto_msg: &M, buf: &mut Vec<u8>) -> anyhow::Result<()>
    where M: protobuf::Message
{
    // clear space for message
    buf.clear();

    // compute size and resize buffer capacity to fit
    let len = proto_msg.compute_size() as usize;
    if buf.capacity() < len {
        buf.reserve(len - buf.len());
    }

    // write the message to the buf
    proto_msg.write_to_vec(buf)?;

    return Ok(())
}