/// Representing the public key used for the DH message
pub type Key = [u8; 255];

/// Id of the public key
pub type Session = [u8; 16];

/// The rsa public signature
pub type Signature = [u8; 512];

pub type Timestamp = u32;

pub type Nonce = u8;

pub type DataLength = u16;

pub type Data = Vec<u8>;
