
/// Deserialize a protobuf message from its bytes representation
/// Removes the 8 byte GC header
pub fn deserialize<M>(bytes: &[u8]) -> anyhow::Result<M>
    where M: protobuf::Message
{
    let res = protobuf::parse_from_bytes::<M>(&bytes[8..])?;
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