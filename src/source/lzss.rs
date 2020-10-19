use anyhow::Result;
use bitstream_io::{BitReader, LittleEndian};
use std::io::{Cursor};
use std::fmt;

#[derive(Debug)]
pub enum LzssError
{
    None,
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
            LzssError::None => write!(f, "LzssError::None"),
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
    pub fn decode(input: &[u8]) -> Result<Vec<u8>, LzssError>
    {
        let mut reader = BitReader::endian(Cursor::new(input), LittleEndian);

        // ensure proper LZSS header
        let header: u32 = reader.read(32)?;
        if header != LZSS_HEADER {
            return Err(LzssError::InvalidHeader);
        }

        // get the supposed "actual size"
        let actual_size: usize = reader.read::<u32>(32)? as usize;
        let mut output: Vec<u8> = Vec::with_capacity(actual_size);

        let mut get_cmd_byte: u8 = 0;
        let mut cmd_byte: u8 = 0;

        loop {
            if get_cmd_byte == 0 {
                cmd_byte = reader.read::<u8>(8)?;
            }

            get_cmd_byte = (get_cmd_byte + 1) & 0x07;

            if (cmd_byte & 1) != 0 {
                let pos_byte = reader.read::<u8>(8)?;

                // the position of the reference
                let mut position = pos_byte << 4;

                // the size of the reference
                let count_byte = reader.read::<u8>(8)?;

                position |= count_byte >> 4;

                let count = (count_byte & 0xF) + 1;

                // count == 0 is the end
                if count == 1
                {
                    break;
                }

                // verify slice targets
                let target_index = (output.len() - 1) - (position as usize);
                let target_index_end = target_index + (count as usize);

                // check if we're referencing too far back or too far forward
                if target_index > output.len() || target_index_end > actual_size
                {
                    return Err(LzssError::BadData);
                }

                // copy the reference into output, bytewise since we can't assume
                // a full memcpy due to overlap
                for idx in target_index..target_index_end
                {
                    output.push(output[idx]);
                }
            } else {
                // copy a single byte
                output.push(reader.read::<u8>(8)?);
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