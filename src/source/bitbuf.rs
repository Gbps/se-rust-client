pub use bitstream_io::{LittleEndian, BitReader, BitWriter};
use anyhow::{Result};

// A bit buffer reader which reads bits in little endian
// Used for reading messages from a stream since some netmessages are bit-based
pub type BitBufReaderType<'a> = BitReader<std::io::Cursor<&'a [u8]>, LittleEndian>;

// A bit buffer writer type which writes bits in little endian
// Used for writing messages to a stream
pub type BitBufWriterType<'a> = BitWriter<std::io::Cursor<&'a mut Vec<u8>>, LittleEndian>;

// read useful types from a bit buffer
pub trait WireReader
{
    fn read_long(&mut self) -> Result<u32>;
    fn read_longlong(&mut self) -> Result<u64>;
    fn read_word(&mut self) -> Result<u16>;
    fn read_char(&mut self) -> Result<u8>;
    fn read_string(&mut self) -> Result<String>;
    fn read_int32_var(&mut self) -> Result<u32>;
}

// reads values from a buffer
impl<T> WireReader for BitReader<T, LittleEndian>
    where T: std::io::Read
{
    // read a little endian long from the stream
    fn read_long(&mut self) -> Result<u32>
    {
        Ok(self.read::<u32>(32)?)
    }

    // read a little endian longlong from the stream
    fn read_longlong(&mut self) -> Result<u64>
    {
        Ok(self.read::<u64>(64)?)
    }

    // read a little endian long from the stream
    fn read_word(&mut self) -> Result<u16>
    {
        Ok(self.read::<u16>(16)?)
    }

    // read a single byte from the stream
    fn read_char(&mut self) -> Result<u8>
    {
        Ok(self.read::<u8>(8)?)
    }

    // read an arbitrarily sized null terminated string
    fn read_string(&mut self) -> Result<String>
    {
        // some reasonable space for small strings
        let mut buf: Vec<u8> = Vec::with_capacity(128);

        // not great performance here... I wish there was a better
        // way but we'll continue doing the "easy" method until perf
        // says it's too poor to use this
        loop {
            // read single byte, if null exit loop
            let byte = self.read_char()?;
            if byte == 0
            {
                break
            }

            // otherwise append byte and continue
            buf.push(byte);
        }

        // convert to utf-8 string (it's probably just ascii but rust wants us to use utf-8)
        let out_str = std::str::from_utf8(&buf[..])?;

        Ok(out_str.to_string())
    }

    /// source engine variable length 32-bit int encoding
    fn read_int32_var(&mut self) -> Result<u32>
    {
        let mut data: u8;
        let mut res: u32 = 0;
        let mut count: u32 = 0;

        loop
        {
            // maximum encoded bytes
            if count == 5 {
                return Err(anyhow::anyhow!("Invalid varint32 encoding!"));
            }

            data = self.read_char()?;
            res |= ((data & 0x7F) as u32) << (7 * count);
            count += 1;
            if (data & 0x80) == 0 {
                break;
            }
        }

        Ok(res)
    }
}

// wrapper to write network data as source engine expects on the wire
pub trait WireWriter
{
    fn write_long(&mut self, num: u32) -> Result<()>;
    fn write_longlong(&mut self, num: u64) -> Result<()>;
    fn write_word(&mut self, num: u16) -> Result<()>;
    fn write_char(&mut self, num: u8) -> Result<()>;
    fn write_string(&mut self, s: &str) -> Result<()>;
    fn write_bit(&mut self, bit: bool) -> Result<()>;
    fn write_int32_var(&mut self, num: u32) -> Result<()>;
}

impl<T> WireWriter for BitWriter<T, LittleEndian>
    where T: std::io::Write
{
    // write little endian long
    #[inline]
    fn write_long(&mut self, num: u32) -> Result<()>
    {
        self.write(32, num)?;

        Ok(())
    }

    // write little endian 64-bit longlong
    #[inline]
    fn write_longlong(&mut self, num: u64) -> Result<()>
    {
        self.write(64, num)?;

        Ok(())
    }

    #[inline]
    fn write_word(&mut self, num: u16) -> Result<()>
    {
        self.write(16, num)?;

        Ok(())
    }


    // write char
    #[inline]
    fn write_char(&mut self, num: u8) -> Result<()>
    {
        self.write(8, num)?;

        Ok(())
    }

    // write a string with a null terminator
    #[inline]
    fn write_string(&mut self, s: &str) -> Result<()>
    {
        if s.len() > 0
        {
            // write string and null terminator
            self.write_bytes(s.as_bytes())?;
        }

        // write a null byte
        self.write(8, 0)?;

        Ok(())
    }


    #[inline]
    fn write_bit(&mut self, bit: bool) -> Result<()>
    {
        Ok(self.write_bit(bit)?)
    }

    // source engine variable length 32-bit int encoding
    #[inline]
    fn write_int32_var(&mut self, mut data: u32) -> Result<()>
    {
        while data > 0x7F
        {
            self.write(8,  (data & 0x7F) | 0x80)?;
            data >>= 7;
        }
        self.write(8, data & 0x7F)?;
        Ok(())
    }
}

