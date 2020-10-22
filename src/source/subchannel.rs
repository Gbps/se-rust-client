use bitstream_io::{BitReader, LittleEndian};
use crate::source::bitbuf::WireReader;
use log::{warn, trace};
use crate::source::lzss::Lzss;
use pretty_hex::PrettyHex;

const MAX_FILE_SIZE: usize = (1<<26) - 1;
const FRAGMENT_SIZE: usize = 1<<8;

pub enum SubchannelStreamType
{
    // reliable messages
    Message = 0,

    // file transfers
    File = 1,

    // invalid subchannel type
    Invalid = 2,
}

impl From<u8> for SubchannelStreamType
{
    fn from(num: u8) -> Self
    {
        match num {
            0 => SubchannelStreamType::Message,
            1 => SubchannelStreamType::File,
            _ => SubchannelStreamType::Invalid,
        }
    }
}

// compressed fragment information, if compressed
struct CompressedFragments {
    // size of payload when uncompressed, if it is compressed
    uncompressed_size: usize
}

// a file payload being sent
struct FileFragments {
    // filename for the incoming file
    filename: String,

    // transfer id of this file
    transfer_id: u32,
}

// a current in-progress transfer
pub struct TransferBuffer {
    // the buffer holding current transfer data
    buffer: Vec<u8>,

    // the number of fragments in this transfer
    num_fragments: usize,

    // number of acknowledged fragments
    num_fragments_ack: usize,
}

pub struct SubChannel
{
    // file information if the payload is a file
    file: Option<FileFragments>,

    // compression information if the payload is compressed
    compressed: Option<CompressedFragments>,

    // if this payload is a replay?
    is_replay: bool,

    // the size of total bytes being sent over the network
    payload_size: usize,

    // current in-progress transfer
    transfer: Option<TransferBuffer>,

    // contains the reliable state for this SubChannel
    // reliable state is a bit which flips back and forth acknowledging
    // transfers as they are received, shifted by the SubChannel index
    in_reliable_state: bool,
}

impl TransferBuffer {
    // create a new transfer buffer to receive incoming data
    fn new(transfer_size: usize) -> Self {

        // calculate the number of fragments that payload actually is
        // convert from bytes to fragments
        let num_fragments: usize = (transfer_size+FRAGMENT_SIZE-1)/(FRAGMENT_SIZE);
        trace!("Transfer size = {}, therefore allocating for {} fragments @ {} bytes per fragment", transfer_size, num_fragments, FRAGMENT_SIZE);

        //
        // allocate space for the entire payload
        let buffer = vec![0; transfer_size];
        return TransferBuffer{
            buffer,
            num_fragments,
            num_fragments_ack: 0,
        }
    }

    // read a given number of fragments over the network
    // return Ok(true) when the transfer is complete
    fn read_fragments<T>(&mut self, start_frag: usize, num_fragments: usize, reader: &mut BitReader<T, LittleEndian>) -> anyhow::Result<bool>
        where T: std::io::Read
    {
        // total number of bytes to receive off of the network
        let mut total_recv_length: usize = num_fragments * FRAGMENT_SIZE;
        let last_recv_fragment = start_frag+num_fragments;
        let total_fragments_in_payload = self.num_fragments;
        let mut transfer_complete = false;

        trace!("[read_fragments] start_frag: {}, num_fragments: {}", start_frag, num_fragments);
        trace!("[read_fragments] total_recv_length: {}, total_fragments_in_payload: {}", total_recv_length, total_fragments_in_payload);

        // is this the last fragment?
        if last_recv_fragment == total_fragments_in_payload
        {
            // this is the last fragment, adjust the receiving length so that we only receive
            // the bytes of the final fragment that we want to finish this off
            let final_part = FRAGMENT_SIZE - ( self.buffer.len() % FRAGMENT_SIZE );
            if final_part < FRAGMENT_SIZE
            {
                total_recv_length -= final_part;
            }

            transfer_complete = true;
            trace!("[read_fragments] Completing transfer! (final_part={})", final_part);
        }
        else if last_recv_fragment > total_fragments_in_payload
        {
            warn!("[read_fragments] Out of bounds fragment chunk!");

            // does this fragment exceed the total size of the payload?
            return Err(anyhow::anyhow!("Fragment chunk received out of bounds"))
        }

        // start bytes for where to read in the buffer
        let start = start_frag * FRAGMENT_SIZE;

        trace!("[read_fragments] buffer[start..end] = buffer[{}..{}]", start, start+total_recv_length);

        // receive the bytes on the network
        reader.read_bytes(&mut self.buffer[start..(start+total_recv_length)])?;

        // acknowledge these packets
        self.num_fragments_ack += num_fragments;

        trace!("[read_fragments] Transfer status: [{}/{}]", self.num_fragments_ack, self.num_fragments);

        // have we finished this transfer entirely?
        if transfer_complete
        {
            trace!("Transfer complete.");
            return Ok(true)
        }

        // transfer not complete yet
        return Ok(false)
    }

    // decompress an LZSS payload and replace the buffer with the decompressed one on success
    fn decompress_payload(&mut self, expected_length: usize) -> anyhow::Result<()>
    {
        trace!("Payload BEFORE decompress (len={}):\n{:?}", self.buffer.len(), self.buffer.hex_dump());

        // decompress the result
        let decompressed = Lzss::decode(&self.buffer[..])?;

        trace!("Payload AFTER decompress (len={}):\n{:?}", decompressed.len(), decompressed.hex_dump());

        // check that the expected length matches (despite there also being a separate length
        // in the lzss header)
        if decompressed.len() != expected_length
        {
            return Err(anyhow::anyhow!("Decompressed data length mismatch from fragment transfer"));
        }

        // reassign the buffer with our new output
        self.buffer = decompressed;

        Ok(())
    }

    // get the final payload once the transfer is complete
    pub fn unwrap_payload(self) -> Vec<u8>
    {
        assert_eq!(self.num_fragments, self.num_fragments_ack);

        return self.buffer;
    }
}

impl SubChannel {
    // create a new SubChannel
    pub fn new() -> Self {
        Self {
            file: None,
            compressed: None,
            is_replay: false,
            payload_size: 0,
            transfer: None,
            in_reliable_state: false,
        }
    }

    // read information about a file fragment
    fn read_file_info<T>(&mut self, reader: &mut BitReader<T, LittleEndian>) -> anyhow::Result<()>
        where T: std::io::Read
    {
        // check if it's a file
        let is_file = reader.read_bit()?;

        trace!("is_file: {}", is_file);

        if is_file {
            let transfer_id = reader.read::<u32>(32)?;
            let filename = reader.read_string()?;

            trace!("[FILE] filename: {}", &filename);
            // this is file fragments
            self.file = Some(FileFragments{
                // read the transfer id for the file
                transfer_id,

                // read the filename
                filename,
            });

            // read if it's a replay demo
            let is_replay = reader.read_bit()?;
            if is_replay {
                self.is_replay = true;
            }

            trace!("[FILE] transfer_id: {}, is_replay: {}", transfer_id, is_replay);
        }

        Ok(())
    }

    // read compression header info
    fn read_compress_info<T>(&mut self, reader: &mut BitReader<T, LittleEndian>) -> anyhow::Result<()>
        where T: std::io::Read
    {
        // is it a compressed single block?
        let compressed = reader.read_bit()?;

        trace!("compressed: {}", compressed);

        if compressed {
            let uncompressed_size = reader.read::<u32>(26)? as usize;

            // mark it as compressed and read its uncompressed size
            self.compressed = Some(CompressedFragments {
                uncompressed_size
            });

            trace!("uncompressed_size: {}", uncompressed_size);
        }

        Ok(())
    }

    // called when a full payload has been received and needs to be processed before returning
    fn complete_transfer(&mut self) -> anyhow::Result<TransferBuffer>
    {
        if let Some(data) = &self.compressed {
            trace!("Fragments were LZSS compressed, decompressing... (uncompressed_size={})", data.uncompressed_size);

            // if this is a compressed payload, decompress it here
            self.transfer.as_mut().unwrap().decompress_payload(data.uncompressed_size)?;

            trace!("Fragments successfully decompressed");
        }

        let transfer_out = self.transfer.take().unwrap();

        // return the completed transfer
        return Ok(transfer_out);
    }
    // read all of the SubChannel data for this SubChannel from the network
    // when the transfer is complete, returns Some(TransferBuffer) which contains the completed payload
    pub fn read_subchannel_data<T>(&mut self, reader: &mut BitReader<T, LittleEndian>) -> anyhow::Result<Option<TransferBuffer>>
        where T: std::io::Read
    {
        trace!("Begin read_subchannel_data");

        // position in the overall fragment buffer we're writing to
        let mut start_frag: usize = 0;

        // number of fragments contained in this packet
        let mut num_frags: usize = 0;

        // is it a single chunk of data?
        let single = !(reader.read_bit()?);

        // is it not a single block of data? if so, we need to start buffering the payload
        if !single
        {
            // the current offset fragment
            start_frag = reader.read::<u32>(18)? as usize;

            // the number of fragments in this packet
            num_frags = reader.read::<u32>(3)? as usize;

            trace!("Multi-fragment receive: (start_frag={}, num_frags={})", start_frag, num_frags);
        }

        // are we reading from the first packet?
        if start_frag == 0 {
            // if it is a single block
            if single {
                trace!("Starting new transfer (single block)");

                // read if it's compressed
                self.read_compress_info(reader)?;

                // read the total amount of data being sent
                self.payload_size = reader.read::<u32>(18)? as usize;
            } else {
                trace!("Starting new transfer (multi-block)");

                // read if it's file fragments
                self.read_file_info(reader)?;

                // read if it's compressed
                self.read_compress_info(reader)?;

                // read the total amount of data being sent
                self.payload_size = reader.read::<u32>(26)? as usize;
            }

            trace!("payload_size: {}", self.payload_size);

            // check for a file that's too large
            if self.payload_size > MAX_FILE_SIZE
            {
                return Err(anyhow::anyhow!("Exceeded max file transfer size!"));
            }

            // check for an invalid fragment
            if self.payload_size == 0 {
                return Err(anyhow::anyhow!("Invalid 0 length subfragment received!"));
            }

            // check for too large compressed file
            if let Some(x) = &self.compressed {
                if x.uncompressed_size > MAX_FILE_SIZE {
                    return Err(anyhow::anyhow!("Exceeded max compressed file transfer size!"));
                }
            }

            // check for reinitialization, if so drop the old data
            if let Some(_x) = &self.transfer {
                warn!("Reinitializing transfer buffer due to fragment abort...");
            }

            self.transfer = Some(TransferBuffer::new(self.payload_size));
        } else {
            trace!("Continuing existing transfer...");
        }

        let mut complete: bool = false;

        // check for no transfer, but we're somehow receiving transfer data
        if let None = &self.transfer {
            return Err(anyhow::anyhow!("Received fragment but no transfer pending"));
        }else if let Some(transfer) = &mut self.transfer {
            // read the actual bytes off the network
            complete = transfer.read_fragments(start_frag, num_frags, reader)?;

            // if we're still here, we received this chunk, flip the reliable state bit to ack
            // on the other end
            self.in_reliable_state = !self.in_reliable_state;
        }

        // has the full payload been received? if so, return the payload up.
        if complete {
            return Ok(Some(self.complete_transfer()?));
        }

        Ok(None)
    }
}