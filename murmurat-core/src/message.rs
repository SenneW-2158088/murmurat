use crate::{encryption, protocol};

/// Message used for key exchange
pub struct DHMessage {
    pub dh_public: protocol::DhPublicKey,
}

impl DHMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.dh_public);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Self {
        let public_key = protocol::DhPublicKey::try_from(bytes).unwrap();
        DHMessage { dh_public: public_key }
    }
}

/// Message used for authentication
pub struct HelloMessage {
    pub pubkey_id: protocol::RsaPublicKeyId,
    pub rsa_public: protocol::RsaPublic,
}

impl HelloMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.pubkey_id.to_be_bytes());
        bytes.extend(self.rsa_public);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Self {
        let session_size = std::mem::size_of::<protocol::RsaPublicKeyId>();
        let (pub_id_bytes, signature_bytes) = bytes.split_at(session_size);
        let pubkey_id = protocol::RsaPublicKeyId::from_be_bytes(pub_id_bytes.try_into().unwrap());
        let signature = protocol::RsaPublic::try_from(signature_bytes).unwrap();
        HelloMessage { pubkey_id, rsa_public: signature }
    }
}

/// Message used for
pub struct DataMessage {
    length: protocol::DataLength,
    nonce: protocol::Nonce,
    timestamp: protocol::Timestamp,
    data: protocol::Data,
    public_key: protocol::DhPublicKey,
    signature: protocol::RsaPublic,
}

impl DataMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&self.length.to_be_bytes());
        bytes.extend(&self.nonce.to_be_bytes());
        bytes.extend(&self.timestamp.to_be_bytes());
        bytes.extend(&self.data);
        bytes.extend(self.public_key);
        bytes.extend(self.signature);
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Self {
        let public_key_size = std::mem::size_of::<protocol::DhPublicKey>();
        let signature_size = std::mem::size_of::<protocol::RsaPublic>();

        let (rest, signature_bytes) = bytes.split_at(bytes.len() - signature_size);
        let (rest, public_key_bytes) = rest.split_at(rest.len() - public_key_size);

        let length_size = std::mem::size_of::<protocol::DataLength>();
        let nonce_size = std::mem::size_of::<protocol::Nonce>();
        let timestamp_size = std::mem::size_of::<protocol::Timestamp>();

        let (length_bytes, rest) = rest.split_at(length_size);
        let (nonce_bytes, rest) = rest.split_at(nonce_size);
        let (timestamp_bytes, data_bytes) = rest.split_at(timestamp_size);

        let length = protocol::DataLength::from_be_bytes(length_bytes.try_into().unwrap());
        let nonce = protocol::Nonce::from_be_bytes(nonce_bytes.try_into().unwrap());
        let timestamp = protocol::Timestamp::from_be_bytes(timestamp_bytes.try_into().unwrap());

        let data = protocol::Data::from(data_bytes);
        let public_key = protocol::DhPublicKey::try_from(public_key_bytes).unwrap();
        let signature = protocol::RsaPublic::try_from(signature_bytes).unwrap();

        DataMessage {
            length,
            nonce,
            timestamp,
            data,
            public_key,
            signature,
        }
    }
}

pub enum MurmuratMessage {
    DH(DHMessage),
    Hello(HelloMessage),
    Data(DataMessage),
}

struct MessageHeader {
    message_type: u8,
}

impl MessageHeader {
    pub fn encode(&self) -> Vec<u8> {
        vec![self.message_type]
    }

    pub fn decode(bytes: &[u8]) -> Self {
        if bytes.len() != 1 {
            panic!("Invalid header length");
        }
        MessageHeader {
            message_type: bytes[0],
        }
    }
}

impl MurmuratMessage {
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let header = match self {
            MurmuratMessage::DH(_) => MessageHeader { message_type: 0 },
            MurmuratMessage::Hello(_) => MessageHeader { message_type: 1 },
            MurmuratMessage::Data(_) => MessageHeader { message_type: 2 },
        };
        bytes.extend(header.encode());
        bytes.extend(match self {
            MurmuratMessage::DH(message) => message.encode(),
            MurmuratMessage::Hello(message) => message.encode(),
            MurmuratMessage::Data(message) => message.encode(),
        });
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Self {
        let header = MessageHeader::decode(&bytes[0..1]);
        let body = &bytes[1..];
        match header.message_type {
            0 => MurmuratMessage::DH(DHMessage::decode(body)),
            1 => MurmuratMessage::Hello(HelloMessage::decode(body)),
            2 => MurmuratMessage::Data(DataMessage::decode(body)),
            _ => panic!("Unknown message type"),
        }
    }
}
