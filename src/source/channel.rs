use std::net::UdpSocket;
use std::io::{BufRead, Write};
use anyhow::{Result, Context};
use super::packetbase::*;

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
    fn recv_header(&mut self) -> Result<(ConnectionlessPacketType, &[u8])>
    {
        // read the message
        let mut target = self.wrapper.recv_message()?;

        // first ensure we have a proper connectionless header
        let header = target.read_long()?;
        if header != CONNECTIONLESS_HEADER
        {
            return Err(anyhow::anyhow!("Invalid connectionless header"))
        }

        // read the type number and convert it to a packet type enum
        Ok((ConnectionlessPacketType::from(target.read_char()?), target))
    }
/*
    // read any generic connectionless packet from the socket
    pub fn recv_packet(&mut self) -> Result<ConnectionlessPacket>
    {
        // read the type number and convert it to a packet type enum
        let (packet_type, target) = self.recv_header()?;

        // construct a packet object based on the packet type
        match packet_type
        {
            ConnectionlessPacketType::S2A_INFO_SRC => Ok(S2aInfoSrc::read_values(target)?.into()),
            ConnectionlessPacketType::S2A_CHALLENGE => Ok(S2aChallenge::read_values(target)?.into()),
            _ => panic!(format!("no read_values() match implemented for packet {}", packet_type as u8))
        }
    }
*/
    // read a specific connectionless packet from the socket
    pub fn recv_packet_type<T>(&mut self) -> Result<T>
        where T: ConnectionlessPacketReceive
    {
        // read the type number and convert it to a packet type enum
        let (packet_type, target) = self.recv_header()?;

        if packet_type != T::get_type()
        {
            return Err(anyhow::anyhow!(format!("Expected packet {:?}, got {:?}", T::get_type(), packet_type)))
        }

        // read the packet from the wire
        Ok(T::read_values(target)?)
    }
}

// wrapper to write network data as source engine expects on the wire
pub trait ByteWriter
{
    fn write_long(&mut self, num: u32) -> Result<()>;
    fn write_char(&mut self, num: u8) -> Result<()>;
    fn write_string(&mut self, s: &str) -> Result<()>;
}

impl<T> ByteWriter for T
    where T: Write
{
    // write little endian long
    #[inline]
    fn write_long(&mut self, num: u32) -> Result<()>
    {
        self.write(&num.to_le_bytes())?;

        Ok(())
    }

    // write char
    #[inline]
    fn write_char(&mut self, num: u8) -> Result<()>
    {
        self.write(&num.to_le_bytes())?;

        Ok(())
    }

    // write a string with a null terminator
    #[inline]
    fn write_string(&mut self, s: &str) -> Result<()>
    {
        // write string and null terminator
        self.write_all(s.as_bytes())?;

        // write a null byte
        self.write(&[0])?;

        Ok(())
    }
}

// wrapper to read objects from a stream
pub trait ByteReader
{
    fn read_long(&mut self) -> Result<u32>;
    fn read_longlong(&mut self) -> Result<u64>;
    fn read_word(&mut self) -> Result<u16>;
    fn read_char(&mut self) -> Result<u8>;
    fn read_string(&mut self) -> Result<String>;
}

impl<T> ByteReader for T
    where T: BufRead
{
    // read a little endian long from the stream
    #[inline]
    fn read_long(&mut self) -> Result<u32>
    {
        // 4 byte buffer space
        let mut buf:[u8; 4] = [0; 4];

        // read exactly 4 bytes from stream
        self.read_exact(&mut buf)?;

        // convert to little endian long
        Ok(u32::from_le_bytes(buf))
    }

    // read a little endian longlong from the stream
    #[inline]
    fn read_longlong(&mut self) -> Result<u64>
    {
        // 4 byte buffer space
        let mut buf:[u8; 8] = [0; 8];

        // read exactly 4 bytes from stream
        self.read_exact(&mut buf)?;

        // convert to little endian long
        Ok(u64::from_le_bytes(buf))
    }

    // read a little endian long from the stream
    #[inline]
    fn read_word(&mut self) -> Result<u16>
    {
        // 4 byte buffer space
        let mut buf:[u8; 2] = [0; 2];

        // read exactly 4 bytes from stream
        self.read_exact(&mut buf)?;

        // convert to little endian long
        Ok(u16::from_le_bytes(buf))
    }

    // read a single byte from the stream
    #[inline]
    fn read_char(&mut self) -> Result<u8>
    {
        let mut buf: [u8; 1] = [0; 1];

        self.read_exact(&mut buf)?;

        Ok(u8::from_le_bytes(buf))
    }

    // read an arbitrarily sized null terminated string
    fn read_string(&mut self) -> Result<String>
    {
        // some reasonable space for small strings
        let mut buf: Vec<u8> = Vec::with_capacity(128);

        // read until null byte
        let size = self.read_until(b'\0', &mut buf)?;

        // convert to utf-8 string (it's probably just ascii but rust wants us to use utf-8)
        let out_str = std::str::from_utf8(&buf[0..size-1])?;

        Ok(out_str.to_string())
    }
}