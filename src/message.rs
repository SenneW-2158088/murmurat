use crate::protocol;

/// Message used for key exchange
pub struct DHMessage {
    public_key: protocol::Key,
}

/// Message used for authenticaton
pub struct HelloMessage {
    session: protocol::Session,
    signature: protocol::Signature,
}

/// Message used for
pub struct DataMessage {
    length: protocol::DataLength,
    nonce: protocol::Nonce,
    timestamp: protocol::Timestamp,
    data: protocol::Data,
    public_key: protocol::Key,
    signature: protocol::Signature,
}

pub enum MurmuratMessage {
    DH(DHMessage),
    Hello(HelloMessage),
    Data(DataMessage),
}
