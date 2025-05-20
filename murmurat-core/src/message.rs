use crate::{
    coding::{CodingError, Decode, Encode},
    protocol,
};

/// Message used for key exchange
#[derive(Debug)]
pub struct DHMessage {
    pub dh_public: protocol::DhPublicKey,
}

impl Encode for DHMessage {
    fn encode<T: bytes::BufMut>(&self, buffer: &mut T) -> crate::coding::Result<()> {
        buffer.put_slice(&self.dh_public);
        Ok(())
    }
}

impl Decode for DHMessage {
    fn decode<T: bytes::Buf>(buffer: &mut T) -> crate::coding::Result<Self> {
        let mut public_key_buffer = [0u8; 256];
        buffer.copy_to_slice(&mut public_key_buffer);

        let public_key = protocol::DhPublicKey::try_from(public_key_buffer.as_slice())
            .map_err(|_| CodingError::InvalidValue)?;

        Ok(Self {
            dh_public: public_key,
        })
    }
}

/// Message used for authentication
#[derive(Debug)]
pub struct HelloMessage {
    pub pubkey_id: protocol::RsaPublicKeyId,
    pub rsa_public: protocol::RsaPublic,
}

impl Encode for HelloMessage {
    fn encode<T: bytes::BufMut>(&self, buffer: &mut T) -> crate::coding::Result<()> {
        buffer.put_slice(&self.pubkey_id.to_be_bytes());
        buffer.put_slice(&self.rsa_public);
        Ok(())
    }
}

impl Decode for HelloMessage {
    fn decode<T: bytes::Buf>(buffer: &mut T) -> crate::coding::Result<Self> {
        let session_size = std::mem::size_of::<protocol::RsaPublicKeyId>();
        if buffer.remaining() < session_size {
            return Err(CodingError::BufferTooSmall);
        }

        let pubkey_id = buffer.get_u32();

        let mut signature_bytes = [0u8; 512];
        buffer.copy_to_slice(&mut signature_bytes);

        let signature = protocol::RsaPublic::try_from(signature_bytes.as_slice())
            .map_err(|_| CodingError::InvalidValue)?;

        Ok(Self {
            pubkey_id,
            rsa_public: signature,
        })
    }
}

/// Message used for
#[derive(Debug)]
pub struct DataMessage {
    pub length: protocol::DataLength,
    pub nonce: protocol::Nonce,
    pub timestamp: protocol::Timestamp,
    pub data: protocol::Data,
    pub public_key_id: protocol::RsaPublicKeyId,
    pub signature: protocol::RsaPublic,
}

impl Encode for DataMessage {
    fn encode<T: bytes::BufMut>(&self, buffer: &mut T) -> crate::coding::Result<()> {
        let total_size = self.length + 521;
        buffer.put_u16(total_size);
        buffer.put_u8(self.nonce);
        buffer.put_u32(self.timestamp);
        buffer.put_slice(&self.data);
        buffer.put_u32(self.public_key_id);
        buffer.put_slice(&self.signature);
        Ok(())
    }
}
impl Decode for DataMessage {
    fn decode<T: bytes::Buf>(buffer: &mut T) -> crate::coding::Result<Self> {
        // Read length
        let total_size = buffer.get_u16();
        println!("total size: {}", total_size);

        let length = total_size - 1 - 4 - 4 - 512;

        // Read nonce
        let nonce = buffer.get_u8();

        // Read timestamp
        let timestamp = buffer.get_u32();

        // Read data
        let mut data = vec![0; length as usize];
        buffer.copy_to_slice(&mut data);

        // Read public key
        let public_key_id = buffer.get_u32();

        // Read signature
        let mut signature = [0u8; 512];
        buffer.copy_to_slice(&mut signature);

        Ok(Self {
            length,
            nonce,
            timestamp,
            data,
            public_key_id,
            signature,
        })
    }
}

#[derive(Debug)]
pub enum MurmuratMessage {
    DH(DHMessage),
    Hello(HelloMessage),
    Data(DataMessage),
}

struct MessageHeader {
    message_type: u8,
}

impl Encode for MessageHeader {
    fn encode<T: bytes::BufMut>(&self, buffer: &mut T) -> crate::coding::Result<()> {
        buffer.put_u8(self.message_type);
        Ok(())
    }
}

impl Decode for MessageHeader {
    fn decode<T: bytes::Buf>(buffer: &mut T) -> crate::coding::Result<Self> {
        Ok(Self {
            message_type: buffer.get_u8(),
        })
    }
}

impl Encode for MurmuratMessage {
    fn encode<T: bytes::BufMut>(&self, buffer: &mut T) -> crate::coding::Result<()> {
        match self {
            MurmuratMessage::DH(message) => {
                buffer.put_u8(0);
                message.encode(buffer)?;
            }
            MurmuratMessage::Hello(message) => {
                buffer.put_u8(1);
                message.encode(buffer)?;
            }
            MurmuratMessage::Data(message) => {
                buffer.put_u8(2);
                message.encode(buffer)?;
            }
        }

        Ok(())
    }
}

impl Decode for MurmuratMessage {
    fn decode<T: bytes::Buf>(buffer: &mut T) -> crate::coding::Result<Self> {
        let kind = buffer.get_u8();
        let message = match kind {
            0 => {
                let dh_message = DHMessage::decode(buffer)?;
                MurmuratMessage::DH(dh_message)
            }
            1 => {
                let hello_message = HelloMessage::decode(buffer)?;
                MurmuratMessage::Hello(hello_message)
            }
            2 => {
                let data_message = DataMessage::decode(buffer)?;
                MurmuratMessage::Data(data_message)
            }
            _ => return Err(CodingError::InvalidValue),
        };

        Ok(message)
    }
}
