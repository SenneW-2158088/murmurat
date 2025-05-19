use crate::protocol::*;
use bytes::{Buf, BufMut};

#[derive(Debug)]
pub enum CodingError {
    BufferTooSmall,
    EndOfBuffer,
}

pub type Result<T> = std::result::Result<T, CodingError>;

pub trait Encode {
    fn encode<T: BufMut>(&self, buffer: &mut T) -> Result<()>;
}

pub trait Decode: Sized {
    fn decode<T: Buf>(buffer: &mut T) -> Result<Self>;
}

impl<const N: usize> Encode for [u8; N] {
    fn encode<T: BufMut>(&self, buffer: &mut T) -> Result<()> {
        if buffer.remaining_mut() < self.len() {
            return Err(CodingError::BufferTooSmall);
        }
        buffer.put_slice(self);
        Ok(())
    }
}

impl<const N: usize> Decode for [u8; N] {
    fn decode<T: Buf>(buffer: &mut T) -> Result<Self> {
        if buffer.remaining() < 255 {
            return Err(CodingError::EndOfBuffer);
        }

        let mut key = [0u8; N];
        buffer.copy_to_slice(&mut key);
        Ok(key)
    }
}

impl Encode for u32 {
    fn encode<T: BufMut>(&self, buffer: &mut T) -> Result<()> {
        if buffer.remaining_mut() < 4 {
            return Err(CodingError::BufferTooSmall);
        }
        buffer.put_u32(*self);
        Ok(())
    }
}

impl Decode for u32 {
    fn decode<T: Buf>(buffer: &mut T) -> Result<Self> {
        if buffer.remaining() < 4 {
            return Err(CodingError::EndOfBuffer);
        }
        Ok(buffer.get_u32())
    }
}

impl Encode for u8 {
    fn encode<T: BufMut>(&self, buffer: &mut T) -> Result<()> {
        if buffer.remaining_mut() < 1 {
            return Err(CodingError::BufferTooSmall);
        }
        buffer.put_u8(*self);
        Ok(())
    }
}

impl Decode for u8 {
    fn decode<T: Buf>(buffer: &mut T) -> Result<Self> {
        if buffer.remaining() < 1 {
            return Err(CodingError::EndOfBuffer);
        }
        Ok(buffer.get_u8())
    }
}

impl Encode for u16 {
    fn encode<T: BufMut>(&self, buffer: &mut T) -> Result<()> {
        if buffer.remaining_mut() < 2 {
            return Err(CodingError::BufferTooSmall);
        }
        buffer.put_u16(*self);
        Ok(())
    }
}

impl Decode for u16 {
    fn decode<T: Buf>(buffer: &mut T) -> Result<Self> {
        if buffer.remaining() < 2 {
            return Err(CodingError::EndOfBuffer);
        }
        Ok(buffer.get_u16())
    }
}
