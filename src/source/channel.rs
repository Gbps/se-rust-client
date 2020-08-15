use std::net::UdpSocket;
use anyhow::{Result, Context};
use super::packetbase::*;
use super::bitbuf::*;

// implements a buffered udp reader
pub struct BufUdp
{
    // mutable vector that we will read messages from the udp socket to
    inner_vec: Vec<u8>,

    // socket to read from
    socket: UdpSocket
}

// the maximum UDP payload that will ever be sent, or should ever be received
const NET_MAXPAYLOAD: usize = 262192;

impl BufUdp
{
    fn new(socket: UdpSocket) -> BufUdp
    {
        BufUdp
        {
            // preallocate space for the largest possible payload
            inner_vec: vec![0; NET_MAXPAYLOAD],
            socket
        }
    }

    // read in a message into the internal buffer
    // does not return the message, use get_message() to get
    // the message from the internal buffer
    fn recv_message(&mut self) -> Result<&[u8]>
    {
        // we always know that inner_vec has at least NET_MAXPAYLOAD
        // because we allocated it and no one else can touch it
        // we have to do this because .recv() expects a vector not just
        // of enough *capacity* but also *length* (because of the conversion to &[u8])
        unsafe
        {
            self.inner_vec.set_len(NET_MAXPAYLOAD)
        }

        // receive the message from the socket
        let res = self.socket
            .recv(self.inner_vec.as_mut())
            .context("recv_message failed to read from socket")?;
        // return the part of the vector that contains the message
        Ok(&self.inner_vec[0..res])
    }

    // get packet serialization scratch space as a mutable pointer
    pub fn get_scratch_mut(&mut self) -> &mut Vec<u8>
    {
        return &mut self.inner_vec;
    }

    // get packet serialization scratch space as an immutable pointer
    pub fn get_scratch(&self) -> &Vec<u8>
    {
        return &self.inner_vec;
    }

    // send raw data over the channel
    pub fn send_raw(&self, raw: &[u8]) -> Result<()>
    {
        self.socket.send(raw)?;

        Ok(())
    }
}

// send and receive connectionless source engine packets
pub struct ConnectionlessChannel
{
    // buffered udp socket
    wrapper: BufUdp,
}

impl ConnectionlessChannel
{
    // wrap a udp socket
    pub fn new(socket: UdpSocket) -> Result<ConnectionlessChannel>
    {
        Ok(ConnectionlessChannel
        {
            wrapper: BufUdp::new(socket)
        })
    }

    // send a connectionless packet to the socket
    pub fn send_packet(&mut self, pkt: ConnectionlessPacket) -> Result<()>
    {
        pkt.serialize_to_channel(&mut self.wrapper)
    }

    // read the header from the stream, returns the type of packet and the new position of the
    // message slice
    fn recv_header(&mut self) -> Result<(ConnectionlessPacketType, BitBufReaderType)>
    {
        // read the message
        let msg = self.wrapper.recv_message()?;

        // wrap in a bit buffer
        let mut reader: BitBufReaderType = BitReader::endian(std::io::Cursor::new(msg), LittleEndian);

        // first ensure we have a proper connectionless header
        let header = reader.read_long()?;
        if header != CONNECTIONLESS_HEADER
        {
            return Err(anyhow::anyhow!("Invalid connectionless header"))
        }

        // read the type number and convert it to a packet type enum
        Ok((ConnectionlessPacketType::from(reader.read_char()?), reader))
    }

    // read a specific connectionless packet from the socket
    pub fn recv_packet_type<T>(&mut self) -> Result<T>
        where T: ConnectionlessPacketReceive
    {
        // read the type number and convert it to a packet type enum
        let (packet_type, mut target) = self.recv_header()?;

        if packet_type != T::get_type()
        {
            return Err(anyhow::anyhow!(format!("Expected packet {:?}, got {:?}", T::get_type(), packet_type)))
        }

        // read the packet from the wire
        Ok(T::read_values(&mut target)?)
    }
}

