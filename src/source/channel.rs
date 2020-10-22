use std::net::UdpSocket;
use anyhow::{Result, Context};
use super::packetbase::*;
use super::bitbuf::*;
use pretty_hex::PrettyHex;
use crate::source::ice::IceEncryption;
use bitstream_io::BigEndian;
use std::cell::{RefCell, Ref, Cell};
use crc32fast::Hasher;
use std::io::Cursor;
use crate::source::netmessages::NetMessage;
use crate::source::subchannel::{SubChannel, TransferBuffer, SubchannelStreamType};
use log::{trace, warn};
use crate::source::lzss::Lzss;
use smallvec::SmallVec;

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

    /// buffer to encode protobuf packets into
    encode_buffer: Vec<u8>,

    /// all of the subchannels for this netchannel
    subchannels: RefCell<[SubChannel; 2]>,

    /// current reliable state of all subchannels
    reliable_state: Cell<u8>,
}

/// Header read out of a basic netchannel packet
#[derive(Debug)]
pub struct NetChannelPacketHeader {
    sequence_in: u32,
    sequence_ack: u32,
    flags: u8,
    checksum: u16,
    reliable_state: u8,
    choked: u8,
}

/// A single datagram read off the network
pub struct NetDatagram {
    /// The decoded packet header for the datagram
    pub header: NetChannelPacketHeader,

    /// If this packet contained any netmessages (other than NET_Nop)
    /// then they will be decoded and put here. Otherwise, None.
    messages: Option<Vec<NetMessage>>,
}

impl NetDatagram {
    /// create a new datagram
    fn new(
               sequence_ack: u32,
               sequence_in: u32,
               flags: u8,
               checksum: u16,
               reliable_state: u8,
               choked:u8
            ) -> Self
    {
        return Self {
            header: NetChannelPacketHeader {
                sequence_in,
                sequence_ack,
                flags,
                checksum,
                reliable_state,
                choked,
            },
            messages: None,
        }
    }

    /// adds a netmessage to this datagram
    fn add_message(&mut self, message: NetMessage)
    {
        // allocate some space if this is our first message
        if self.messages.is_none() {
            self.messages = Some(Vec::with_capacity(16))
        }

        // add message
        self.messages.as_mut().unwrap().push(message);
    }

    /// get all netmessages encoded in this packet
    /// if there are no messages, returns None
    pub fn get_messages(&self) -> Option<&Vec<NetMessage>>
    {
        return self.messages.as_ref();
    }

    /// add a set of messages to this datagram
    fn add_messages(&mut self, messages: Vec<NetMessage>)
    {
        if messages.len() == 0 {
            return;
        }

        // allocate some space if this is our first message
        if self.messages.is_none() {
            self.messages = Some(Vec::with_capacity(16))
        }

        self.messages.as_mut().unwrap().extend(messages)
    }
}

impl NetChannel {
    /// get the default channel encryption key
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

    /// upgrade a connectionless channel into a netchannel after authentication is complete
    pub fn upgrade(socket: ConnectionlessChannel, host_version: u32) -> Result<Self>
    {
        let encryption_key = NetChannel::get_encryption_key(host_version);

        // apply the ice key to prepare for encryption/decryption
        let crypt= IceEncryption::new(2, &encryption_key);

        let subchannels: [SubChannel; 2] = [
            SubChannel::new(),
            SubChannel::new(),
        ];

        Ok(Self
        {
            crypt,
            wrapper: RefCell::new(socket.wrapper),
            in_sequence: 0,
            out_sequence_ack: 0,
            out_sequence: 1,
            choked_num: 0,
            encrypt_buffer: RefCell::new(Vec::with_capacity(4096)),
            encode_buffer: Vec::with_capacity(4096),
            subchannels: RefCell::new(subchannels),
            reliable_state: Cell::new(0),
        })
    }

    /// read all of the incoming data from a packet
    pub fn read_data(&mut self) -> Result<NetDatagram>
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
        trace!("[RECV DATAGRAM]: \n{:?}", packet_data.hex_dump());

        // process header data, sequence numbers, subchannel data, etc.
        let datagram = self.parse_datagram(&packet_data)?;

        // update current sequence number info for this packet
        self.in_sequence = datagram.header.sequence_in;
        self.out_sequence_ack = datagram.header.sequence_ack;

        trace!("Finished parsing datagram [seq={}, seq_ack={}]", self.in_sequence, self.out_sequence_ack);
        Ok(datagram)
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

    /// LE -> BE byteswap
    fn bswap(le_in: u32) -> u32 {
        let mut out: u32 = 0;
        out |= ((le_in >> 24) as u8) as u32;
        out |= (((le_in >> 16) as u8) as u32) << 8;
        out |= (((le_in >> 8) as u8) as u32) << 16;
        out |= ((le_in as u8) as u32) << 24;
        return out;
    }

    /// encrypt the datagram and return a reference to the encrypted result
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

            // encrypt the buffer
            self.crypt.encrypt_buffer_inplace( out_buffer.as_mut_slice());
        }

        Ok(self.encrypt_buffer.borrow())
    }

    /// calculate the CRC32 checksum of the current packet in the scratch buffer and update
    /// the checksum field
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

    /// update the checksum field of the current pending internal scratch buffer packet
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

    /// send a netmessage to the server
    pub fn write_netmessage(&mut self, mut message: NetMessage) -> anyhow::Result<()>
    {
        // clear to prepare for a new
        self.encode_buffer.clear();

        // ensure there is enough space in the encode buffer
        let max_size = message.get_max_size();
        if self.encode_buffer.capacity() < max_size {
            self.encode_buffer.reserve(message.get_max_size() - max_size);
        }

        // encode the protobuf message to the local encoding buffer
        message.encode_to_buffer(&mut self.encode_buffer)?;

        // write to the network
        self.write_datagram(&self.encode_buffer)?;

        // continue processing next sequence
        self.out_sequence += 1;

        Ok(())
    }

    /// write a nop packet (no net messages encoded)
    pub fn write_nop(&mut self) -> anyhow::Result<()>
    {
        // write to the network
        self.write_datagram(&[])?;

        // continue processing next sequence
        self.out_sequence += 1;

        Ok(())
    }

    /// write the header of the netchannel datagram
    pub fn write_datagram(&self, send_buffer: &[u8]) -> Result<()>
    {
        {
            // use our packet scratch buffer to form the packet
            let mut wrapper = self.wrapper.borrow_mut();
            let scratch = wrapper.get_scratch_mut();

            // reset the packet before we start writing
            scratch.clear();

            // create a bit writer wrapper on top
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

            // TODO: create send-side reliable fragments

            // write the reliable state (established in read_data)
            writer.write_char(self.reliable_state.get())?;

            // if we have choked packets, write them here
            if self.choked_num > 0 {
                // acknowledge choked packets
                writer.write_char(self.choked_num)?;
            }

            // TODO: Padding?

            // write the contents of the message
            writer.write_bytes(send_buffer)?;
        }

        // calculate and fix the checksum
        self.calc_scratch_checksum()?;

        {
            trace!("[SEND DATAGRAM]\n {:?}", self.wrapper.borrow().get_scratch().hex_dump());
        }

        // encrypt the packet with the ICE key
        let encrypted = self.encrypt_packet(self.wrapper.borrow_mut().get_scratch_mut())?;

        // send the datagram
        self.wrapper.borrow().send_raw(encrypted.as_slice())?;

        Ok(())
    }

    /// reads a set of netmessages from a payload
    fn read_messages<T>(&self, reader: &mut BitReader<T, LittleEndian>) -> anyhow::Result<Vec<NetMessage>>
        where T: std::io::Read
    {
        let mut decode_buf: SmallVec<[u8; 0x1000*2]> = SmallVec::new();

        let mut out_messages: Vec<NetMessage> = Vec::with_capacity(32);

        trace!("--- read_messages() begin ---");
        loop {
            // if there is still data, there must be messages for us to process
            let message_number_e = reader.read_int32_var();
            let message_id: u32;

            // when we reach EOF, we stop netmessage parsing
            if message_number_e.is_err() {
                break;
            } else {
                // the message index number, maps to the netmessage enum
                message_id = message_number_e?;
            }

            if message_id == 0 {
                // NOP packet, just ignore
                continue;
            }

            // total size of the message
            let message_size = reader.read_int32_var()? as usize;

            trace!("MESSAGE [id={}, size={}]:", message_id, message_size);

            // allocate either stack or heap data depending on size
            if message_size > decode_buf.capacity()
            {
                decode_buf.reserve(message_size - decode_buf.len());
            }

            // use unallocated space, don't clear contents
            unsafe {
                decode_buf.set_len(message_size);
            }

            // read the message's data
            reader.read_bytes(decode_buf.as_mut_slice())?;

            // decode the protobuf message
            let message = NetMessage::bind(message_id as i32, decode_buf.as_slice());
            if message.is_err() {
                warn!("Failed decoding netmessage [id={}]: {}", message_id, message.err().unwrap());
                continue;
            }

            let message = message.unwrap();

            trace!("Successfully decoded \"{}\" (id={}, size={}) message", message.get_type_name(), message_id, message_size);

            // return this message
            out_messages.push(message);
        }

        // no more netmessages in this packet
        trace!("--- read_messages() end [{} messages read] ---", out_messages.len());
        return Ok(out_messages);
    }

    /// when a payload is received over a subchannel stream, process its data here
    fn process_subchannel_payload(&self, transfer: TransferBuffer, stream_index: SubchannelStreamType, out_datagram: &mut NetDatagram) -> anyhow::Result<()>
    {
        // unwrap the full subchannel payload
        let payload = transfer.unwrap_payload();

        // convert it to a bit reader
        let mut reader = BitReader::endian(std::io::Cursor::new(payload), LittleEndian);

        // read the message/file inside
        match stream_index {
            // the message stream sends payloads that contain large, reliably sent groups of netmessages
            SubchannelStreamType::Message => out_datagram.add_messages(self.read_messages(&mut reader)?),
            SubchannelStreamType::File => panic!("File transfers not implemented yet!"),
            _ => ()
        }

        Ok(())
    }

    /// parses datagram header and body values
    /// parses netmessages from the packet and returns it in the NetDatagram packet
    fn parse_datagram(&self, packet_data: &[u8]) -> anyhow::Result<NetDatagram>
    {
        let mut reader = BitReader::endian(std::io::Cursor::new(packet_data), LittleEndian);

        // incoming sequence number
        let mut sequence_in = reader.read_long()?;
        let decompressed: Vec<u8>;

        if sequence_in == NET_HEADER_FLAG_COMPRESSEDPACKET {
            trace!("Compressed datagram, {} uncompressed", packet_data.len());

            // decompress the LZSS payload
            decompressed = Lzss::decode(&packet_data[4..])?;

            // retry this, but this time with the decompressed packet
            reader = BitReader::endian(std::io::Cursor::new(decompressed.as_slice()), LittleEndian);

            // re-read the first value of the packet now that it's decompressed
            sequence_in = reader.read_long()?;

            trace!("Decompressed {} bytes from datagram", decompressed.len());
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

        // TODO: Checksum the packet

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
            warn!("Sequence number mismatch (in={}, current={})", sequence_in, self.in_sequence);
            return Err(anyhow::anyhow!("Sequence number mismatch"))
        }

        // create the datagram struct to return to caller
        let mut out_datagram = NetDatagram::new(
            sequence_ack,
            sequence_in,
            flags,
            checksum as u16,
            reliable_state,
            choked,
        );

        // TODO: Subchannel bits

        // is there subchannel info?
        if (flags & PACKET_RELIABLE) != 0
        {
            // which subchannel is currently sending data?
            let subchan_i = reader.read::<u8>(3)?;
            trace!("subchannel[{}] is marked as updated", subchan_i);

            // for each stream in the subchannel,
            for stream_i in 0..2 {
                // grab the subchannel object
                let subchan = &mut (self.subchannels.borrow_mut())[stream_i as usize];

                // check to see if this stream is updated
                let updated = reader.read_bit()?;
                trace!("subchannel[{}][stream={}] updated={}", subchan_i, stream_i, updated);

                if updated {
                    // read all incoming subchannel data
                    let buf = subchan.read_subchannel_data(&mut reader)?;

                    // has a subchannel transfer completed?
                    if buf.is_some()
                    {
                        // we received a full payload, processes it depending on what subchannel stream we're
                        // receiving from
                        self.process_subchannel_payload(buf.unwrap(), SubchannelStreamType::from(stream_i), &mut out_datagram)?;
                    }
                }
            }

            // mark this subchannel as being read from by flipping the bit in reliable state
            let new_state = self.reliable_state.get() ^ (1 << subchan_i);
            self.reliable_state.set(new_state);
        }

        // is there still data left in the packet? if so, netmessages will be parsed here here
        let messages = self.read_messages(&mut reader)?;

        // add any parsed messages to the datagram object
        out_datagram.add_messages(messages);

        Ok(out_datagram)
    }
}