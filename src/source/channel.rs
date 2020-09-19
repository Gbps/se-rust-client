use std::net::UdpSocket;
use anyhow::{Result, Context};
use super::packetbase::*;
use super::bitbuf::*;
use pretty_hex::PrettyHex;
use crate::source::ice::IceEncryption;
use bitstream_io::BigEndian;
use std::cell::{RefCell, RefMut, Ref};
use std::rc::Rc;
use std::borrow::{BorrowMut, Borrow};
use crc32fast::Hasher;
use std::io::Seek;
use std::io::Cursor;

// implements a buffered udp reader
pub struct BufUdp
{
    // mutable vector that we will read messages from the udp socket to
    inner_vec: Vec<u8>,

    // socket to read from
    socket: UdpSocket,

    // size of the message in the buffer
    message_len: usize,
}

/// the maximum UDP payload that will ever be sent, or should ever be received
const NET_MAXPAYLOAD: usize = 262192;
const PACKET_CHOKED: u8 = 1 << 4;
const PACKET_RELIABLE: u8 = 1<<0;

/// Specifies that a datagram packet is a split packet
const NET_HEADER_FLAG_SPLITPACKET: u32 = 0xFFFFFFFE;
const NET_HEADER_FLAG_COMPRESSEDPACKET: u32 = 0xFFFFFFFD;
const CONNECTIONLESS_HEADER: u32 = 0xFFFFFFFF;


impl BufUdp
{
    fn new(socket: UdpSocket) -> BufUdp
    {
        BufUdp
        {
            // preallocate space for the largest possible payload
            inner_vec: vec![0; NET_MAXPAYLOAD],
            socket,
            message_len: 0,
        }
    }

    // read in a message into the internal buffer
    // does not return the message, use get_message() to get
    // the message from the internal buffer
    fn recv_message(&mut self) -> Result<&mut [u8]>
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
        self.message_len = self.socket
            .recv(self.inner_vec.as_mut())
            .context("recv_message failed to read from socket")?;
        // return the part of the vector that contains the message
        Ok(&mut self.inner_vec[0..self.message_len])
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

    // get the message that was last received with recv_message
    pub fn get_message(&self) -> &[u8]
    {
        return &self.inner_vec[0..self.message_len];
    }

    // get the message that was last received with recv_message
    pub fn get_message_mut(&mut self) -> &mut [u8]
    {
        return &mut self.inner_vec[0..self.message_len];
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
    pub fn new(socket: UdpSocket) -> Result<Self>
    {
        Ok(Self
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

/// A NetChannel is a fully established connection with a server which can send source engine
/// netmessage packets between it
pub struct NetChannel
{
    /// buffered udp socket
    wrapper: RefCell<BufUdp>,

    /// ICE network encryption key
    crypt: IceEncryption,

    /// current input sequence number
    in_sequence: u32,

    /// current out sequence number
    out_sequence: u32,

    /// current acknowledged output sequence number
    out_sequence_ack: u32,

    /// number of choked packets
    choked_num: u8,

    /// buffer to encrypt packets to
    encrypt_buffer: RefCell<Vec<u8>>,
}

/// Header read out of a basic netchannel packet
#[derive(Debug)]
struct NetChannelPacketHeader {
    sequence_in: u32,
    sequence_ack: u32,
    flags: u8,
    checksum: u16,
    reliable_state: u8,
    choked: u8,
}

impl NetChannel {
    // get the default channel encryption key
    fn get_encryption_key(host_version: u32) -> [u8; 16]
    {
        return [
            'C' as u8,
            'S' as u8,
            'G' as u8,
            'O' as u8,
            (host_version >> 0) as u8,
            (host_version >> 8) as u8,
            (host_version >> 16) as u8,
            (host_version >> 24) as u8,
            (host_version >> 2) as u8,
            (host_version >> 10) as u8,
            (host_version >> 18) as u8,
            (host_version >> 26) as u8,
            (host_version >> 4) as u8,
            (host_version >> 12) as u8,
            (host_version >> 20) as u8,
            (host_version >> 28) as u8,
        ]
    }

    // upgrade a connectionless channel into a netchannel after authentication is complete
    pub fn upgrade(socket: ConnectionlessChannel, host_version: u32) -> Result<Self>
    {
        let encryption_key = NetChannel::get_encryption_key(host_version);

        // apply the ice key to prepare for encryption/decryption
        let crypt= IceEncryption::new(2, &encryption_key);

        Ok(Self
        {
            crypt,
            wrapper: RefCell::new(socket.wrapper),
            in_sequence: 0,
            out_sequence_ack: 0,
            out_sequence: 0,
            choked_num: 0,
            encrypt_buffer: RefCell::new(Vec::with_capacity(4096)),
        })
    }

    // read all of the incoming data from a packet
    pub fn read_data(&mut self) -> Result<()>
    {
        {
            let mut borrow = self.wrapper.borrow_mut();
            // receive the datagram over the network
            borrow.recv_message()?;
        }

        {
            let borrow = self.wrapper.borrow();
            let datagram = borrow.get_message();

            // wrap the datagram in a bitbuffer
            let mut reader = BitReader::endian(std::io::Cursor::new(datagram), LittleEndian);

            // check the packet header for a split packet
            // also hope that ICE doesn't encrypt the first 4 bytes to these values!?
            // what the hell are they thinking??
            let header = reader.read_long()?;
            if header == NET_HEADER_FLAG_SPLITPACKET {
                panic!("Split packets not supported yet!");
            } else if header == CONNECTIONLESS_HEADER {
                panic!("Unexpected connectionless packet!");
            }
        }

        let mut borrow = self.wrapper.borrow_mut();
        let datagram = borrow.get_message_mut();

        if (datagram.len() % 8) != 0 {
            return Err(anyhow::anyhow!("Unexpected packet alignment"));
        }

        // decrypt packet contents with our ICE key
        let packet_data = self.decrypt_packet(datagram)?;

        // if we're here, we have successfully decrypted the contents of the packet
        println!("Packet: \n{:?}", packet_data.hex_dump());

        // process header data, sequence numbers, subchannel data, etc.
        let (mut remaining_data, header) = self.read_packet_header(&packet_data)?;

        // update current sequence number info for this packet
        self.in_sequence = header.sequence_in;
        self.out_sequence_ack = header.sequence_ack;

        dbg!(&header);

        // if there is still data, there must be messages for us to process
        let message_number = remaining_data.read_int32_var();
        if message_number.is_err() {
            // no netmessages remain
            println!("No more net messages");
            return Ok(())
        }
        println!("Message number: {}", message_number?);

        Ok(())
    }

    fn decrypt_packet<'a>(&self, datagram: &'a mut [u8]) -> Result<&'a [u8]>
    {
        // decrypt the buffer
        self.crypt.decrypt_buffer_inplace(datagram);

        // the first byte is the number of garbage bytes added to the packet
        let garbage = datagram[0] as usize;
        if garbage >= 0x80 || garbage+1 >= datagram.len() {
            return Err(anyhow::anyhow!("Invalid garbage bytes in packet"));
        }

        // prune the garbage bytes off of our payload
        let packet = &datagram[garbage+1..];

        // read the 4-byte network byte order size field of the packet
        let mut reader = BitReader::endian(Cursor::new(packet), BigEndian);
        let size_on_wire: i32 = reader.read_signed(32)?;
        let size_on_wire = size_on_wire as usize;

        // expect the packet to not lie about its size
        if size_on_wire > (packet.len()-4) {
            return Err(anyhow::anyhow!("Invalid wire size"));
        }

        // prune off the size_on_wire field
        let packet_data = &packet[4..(size_on_wire+4)];

        return Ok(packet_data);
    }

    // LE -> BE byteswap
    fn bswap(le_in: u32) -> u32 {
        let mut out: u32 = 0;
        out |= ((le_in >> 24) as u8) as u32;
        out |= (((le_in >> 16) as u8) as u32) << 8;
        out |= (((le_in >> 8) as u8) as u32) << 16;
        out |= ((le_in as u8) as u32) << 24;
        return out;
    }

    // encrypt the datagram and return a reference to the encrypted result
    fn encrypt_packet(&self, datagram: &mut [u8]) -> Result<Ref<Vec<u8>>>
    {
        {
            // get a reference to the temp buffer
            let mut out_buffer = self.encrypt_buffer.borrow_mut();

            // we must pad the full message to 8 bytes for ICE
            let num_pad_bytes = 8 - ((datagram.len() as u32) + 5) % 8;

            // size on wire we're writing (garbage len byte + 4 bytes for wire size)
            let effective_len = datagram.len() + (num_pad_bytes as usize) + 5;

            // ensure there's enough space there
            if effective_len > out_buffer.capacity() {
                let len = out_buffer.len();
                out_buffer.reserve(effective_len - len);
            }

            // use whatever garbage was already there then overwrite it
            unsafe {
                out_buffer.set_len(effective_len);
            }

            let mut writer = BitWriter::endian(Cursor::new(out_buffer.as_mut_slice()), LittleEndian);

            // number of padding bytes
            writer.write_char(num_pad_bytes as u8)?;

            // write the padding bytes
            for _i in 0..num_pad_bytes {
                writer.write_char(0)?;
            }

            // write the size on the wire
            writer.write_long(NetChannel::bswap(datagram.len() as u32))?;

            // and the actual payload
            writer.write_bytes(datagram)?;

            println!("{:?}", out_buffer.hex_dump());

            // encrypt the buffer
            self.crypt.encrypt_buffer_inplace( out_buffer.as_mut_slice());
        }

        Ok(self.encrypt_buffer.borrow())
    }

    // calculate the CRC32 checksum of the current packet in the scratch buffer and update
    // the checksum field
    fn calc_scratch_checksum(&self) -> Result<()>
    {
        let shortened_checksum: u16;
        {
            // now take the message AFTER the checksum field and checksum it
            let wrapper = self.wrapper.borrow();
            let immut_scratch = wrapper.get_scratch();

            // 4 + 4 + 1 + 2
            let sum_area = &immut_scratch[11..];

            // CRC32 on the buffer
            let mut hasher = Hasher::new();
            hasher.update(sum_area);
            let checksum = hasher.finalize();

            // XOR the high and low parts together to make the shortened sum
            // I doubt this is actually a good way to checksum... but it's how the engine does it
            shortened_checksum = (checksum as u16) ^ ((checksum >> 16) as u16);
        }

        // update the packet now
        self.update_scratch_checksum(shortened_checksum)?;

        Ok(())
    }

    // update the checksum field of the current pending internal scratch buffer packet
    fn update_scratch_checksum(&self, checksum: u16) -> Result<()> {
        // create a cursor on the internal scratch buffer
        let mut wrapper = self.wrapper.borrow_mut();
        let scratch = wrapper.get_scratch_mut();
        let mut cursor = std::io::Cursor::new(scratch);

        // skip to the checksum position
        cursor.set_position(9);

        // write the checksum there
        let mut writer = BitWriter::endian(cursor, LittleEndian);
        writer.write_word(checksum)?;

        Ok(())
    }

    // write the header of the netchannel datagram
    pub fn write_datagram(&self, send_buffer: &[u8]) -> Result<()>
    {
        {
            // use our packet scratch buffer to form the packet
            let mut wrapper = self.wrapper.borrow_mut();
            let scratch = wrapper.get_scratch_mut();

            // reset the packet before we start writing
            unsafe {
                scratch.set_len(0);
            }

            // create a bit writer wraper on top
            let mut writer = BitWriter::endian(std::io::Cursor::new(scratch), LittleEndian);

            // outgoing sequence number for this packet
            writer.write_long(self.out_sequence)?;

            // the input sequence number we are acknowledging
            writer.write_long(self.in_sequence)?;

            // packet flags (choked, reliable data)
            let mut flags: u8 = 0;

            // are there any choked packets?
            if self.choked_num > 0 {
                flags |= PACKET_CHOKED;
            }

            // write packet flags
            writer.write_char(flags)?;

            // write packet checksum as 0, we will checksum later then restore here
            writer.write_signed(16, 0)?;

            // if we have choked packets, write them here
            if self.choked_num > 0 {
                // acknowledge choked packets
                writer.write_char(self.choked_num)?;
            }

            // TODO: create reliable fragments
            // TODO: reliable state flags
            writer.write_char(0)?;

            // TODO: Padding?

            // write the contents of the message
            writer.write_bytes(send_buffer)?;
        }

        // calculate and fix the checksum
        self.calc_scratch_checksum()?;

        // encrypt the packet with the ICE key
        let encrypted = self.encrypt_packet(self.wrapper.borrow_mut().get_scratch_mut())?;
        println!("{:?}", encrypted.hex_dump());

        // send the datagram
        self.wrapper.borrow().send_raw(encrypted.as_slice());

        Ok(())
    }

    fn read_packet_header<'a>(&self, packet_data: &'a [u8]) -> Result<(BitBufReaderType<'a>, NetChannelPacketHeader)>
    {
        let mut reader = BitReader::endian(std::io::Cursor::new(packet_data), LittleEndian);

        // incoming sequence number
        let sequence_in = reader.read_long()?;

        if sequence_in == NET_HEADER_FLAG_COMPRESSEDPACKET {
            panic!("Compressed packets not supported yet!");
        }
        if sequence_in == CONNECTIONLESS_HEADER {
            panic!("Connectionless headers over netchannels not supported yet!");
        }

        // acknowledgement of the last sequence number
        let sequence_ack = reader.read_long()?;

        // flag states
        let flags = reader.read_char()?;

        // checksum of the packet
        let checksum: i16 = reader.read_signed(16)?;

        // reliable state of each of the 8 subchannels
        let reliable_state = reader.read_char()?;

        // was the packet choked by the sender?
        let choked;
        if (flags & PACKET_CHOKED) != 0 {
            choked = reader.read_char()?;
        } else {
            choked = 0;
        }

        // check for packet lag, network duplication
        if sequence_in <= self.in_sequence {
            println!("Sequence number mismatch (in={}, current={})", sequence_in, self.in_sequence);
            return Err(anyhow::anyhow!("Sequence number mismatch"))
        }

        // TODO: Subchannel bits

        // is there subchannel info?
        if (flags & PACKET_RELIABLE) != 0
        {
            let _bits: i8 = reader.read_signed(3)?;
            for _subchan_i in 0..8 {
                let updated = reader.read_bit()?;
                if updated {
                    // TODO: Read subchannel data
                    panic!("Subchannel data not implemented.");
                }
            }

            // TODO: Update reliable state.
            // TODO: Process subchannel data.
        }

        // is there still data left?

        Ok((reader, NetChannelPacketHeader{
            sequence_ack,
            sequence_in,
            flags,
            checksum: checksum as u16,
            reliable_state,
            choked
        }))
    }
}