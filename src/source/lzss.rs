use anyhow::Result;
use std::fmt;
use byteorder::{ReadBytesExt, LittleEndian};

#[derive(Debug)]
pub enum LzssError
{
    InvalidHeader,
    BadData,
    SizeMismatch,
    IoError(std::io::Error),
}

impl From<std::io::Error> for LzssError
{
    fn from(error: std::io::Error) -> LzssError
    {
        LzssError::IoError(error)
    }
}

impl fmt::Display for LzssError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self
        {
            LzssError::InvalidHeader => write!(f, "Invalid header in LZSS compressed data"),
            LzssError::BadData => write!(f, "Invalid compressed data"),
            LzssError::SizeMismatch => write!(f, "Compressed data was not of expected size"),
            LzssError::IoError(_) => write!(f, "Reached EOF early"),
        }
    }
}

impl std::error::Error for LzssError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub struct Lzss
{

}

const LZSS_HEADER: u32 = (('S' as u32)<<24) | (('S' as u32)<<16) | (('Z' as u32)<<8) | ('L' as u32);

impl Lzss
{
    pub fn decode(mut input: &[u8]) -> Result<Vec<u8>, LzssError>
    {
        // ensure proper LZSS header
        let header: u32 = input.read_u32::<LittleEndian>()?;
        if header != LZSS_HEADER {
            return Err(LzssError::InvalidHeader);
        }

        // get the supposed "actual size" to verify at the end
        let actual_size: usize = input.read_u32::<LittleEndian>()? as usize;

        // pre-allocate the actual size (errors if we go over this)
        let mut output: Vec<u8> = Vec::with_capacity(actual_size);

        // keep track of beginning and end of the vector as pointers for raw ptr writes
        let mut out_ptr = output.as_mut_ptr();
        let out_ptr_end: *mut u8;
        unsafe {
            out_ptr_end = out_ptr.add(output.capacity())
        }

        let mut get_cmd_byte: u8 = 0;
        let mut cmd_byte: u8 = 0;
        loop {
            // is it time to read a new command byte?
            if get_cmd_byte == 0 {
                cmd_byte = input.read_u8()?;
            }

            // read a command byte every 8 bytes
            get_cmd_byte = (get_cmd_byte + 1) & 0x07;

            // if this is a command byte?
            if (cmd_byte & 1) != 0 {
                let pos_byte: usize = input.read_u8()? as usize;

                // the position of the reference
                let mut position = pos_byte << 4;

                // the size of the reference
                let count_byte: usize = input.read_u8()? as usize;

                position |= count_byte >> 4;

                let count = (count_byte & 0xF) + 1;

                // count == 0 is the end
                if count == 1
                {
                    break;
                }

                // calculate range of the copy from the previously uncompressed data
                let target_index = (output.len() - 1) - position;
                let target_index_end = target_index + count;

                // copy the reference into output, bytewise since we can't assume
                // a full memcpy due to overlap
                for idx in target_index..target_index_end
                {
                    // check for bad access
                    if idx >= output.len(){
                        return Err(LzssError::BadData);
                    }

                    output.push(output[idx]);

                    // keep incrementing output pointer for new item
                    unsafe {
                        out_ptr = out_ptr.add(1);
                    }
                }
            } else {
                // otherwise, this is not a command byte but a regular byte of data
                // copy it to output

                // check for writing past bounds
                if out_ptr == out_ptr_end
                {
                    break;
                }

                // hot path for copying non-compressed bytes to output
                // instead of using output.push. We do raw pointer read/write
                // which increases perf of this loop by up to 4x due to
                // lack of bounds checking and error handling
                unsafe {
                    // read input byte and shift input slice
                    let byt = input.as_ptr().read();
                    input = &input[1..];

                    // write byte to output
                    std::ptr::write(out_ptr, byt);

                    // increment output pointer for next write
                    out_ptr = out_ptr.add(1);

                    // increase length of vector by 1 more item
                    output.set_len(output.len() + 1);
                }
            }

            cmd_byte >>= 1;
        }

        // ensure it's the size we expected
        if output.len() != actual_size
        {
            return Err(LzssError::SizeMismatch);
        }

        // all good, return the output
        Ok(output)
    }
}