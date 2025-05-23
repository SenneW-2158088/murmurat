use std::str::FromStr;

use num_bigint::BigUint;
use num_traits::{FromPrimitive, One, Zero};
use rand::Rng;

use aes::{
    Aes128,
    cipher::{KeyIvInit, StreamCipher},
};

use crate::protocol::{self, DhPublicKey, Nonce};

pub const HOLY_PRIME: [u8; 256] = [
    0x01, 0x89, 0x45, 0x53, 0x31, 0x45, 0x96, 0x77, 0x15, 0x61, 0x19, 0x68, 0x71, 0x36, 0x30, 0x69,
    0x09, 0x05, 0x41, 0x06, 0x67, 0x62, 0x94, 0x87, 0x01, 0x57, 0x45, 0x67, 0x16, 0x40, 0x20, 0x10,
    0x92, 0x67, 0x13, 0x66, 0x79, 0x65, 0x83, 0x70, 0x48, 0x69, 0x43, 0x74, 0x39, 0x75, 0x83, 0x78,
    0x75, 0x55, 0x19, 0x99, 0x72, 0x41, 0x25, 0x67, 0x54, 0x79, 0x71, 0x39, 0x26, 0x61, 0x00, 0x11,
    0x15, 0x79, 0x78, 0x94, 0x34, 0x80, 0x74, 0x85, 0x21, 0x00, 0x64, 0x30, 0x55, 0x31, 0x87, 0x43,
    0x65, 0x63, 0x79, 0x30, 0x40, 0x13, 0x58, 0x59, 0x14, 0x73, 0x14, 0x20, 0x00, 0x60, 0x83, 0x40,
    0x37, 0x47, 0x67, 0x21, 0x05, 0x46, 0x87, 0x02, 0x03, 0x32, 0x55, 0x45, 0x21, 0x48, 0x29, 0x53,
    0x30, 0x79, 0x33, 0x27, 0x93, 0x32, 0x56, 0x92, 0x46, 0x54, 0x02, 0x22, 0x64, 0x48, 0x99, 0x05,
    0x20, 0x19, 0x73, 0x44, 0x02, 0x57, 0x81, 0x32, 0x14, 0x77, 0x90, 0x32, 0x18, 0x19, 0x67, 0x30,
    0x41, 0x69, 0x71, 0x83, 0x48, 0x55, 0x77, 0x75, 0x15, 0x56, 0x67, 0x18, 0x66, 0x08, 0x77, 0x60,
    0x11, 0x27, 0x58, 0x06, 0x91, 0x12, 0x21, 0x53, 0x18, 0x62, 0x34, 0x91, 0x42, 0x29, 0x73, 0x74,
    0x31, 0x09, 0x95, 0x94, 0x08, 0x98, 0x91, 0x19, 0x85, 0x39, 0x25, 0x06, 0x12, 0x21, 0x42, 0x49,
    0x14, 0x96, 0x95, 0x92, 0x11, 0x99, 0x64, 0x09, 0x27, 0x90, 0x96, 0x66, 0x27, 0x07, 0x81, 0x88,
    0x06, 0x17, 0x04, 0x83, 0x83, 0x61, 0x16, 0x80, 0x99, 0x80, 0x82, 0x41, 0x70, 0x63, 0x47, 0x07,
    0x13, 0x34, 0x60, 0x17, 0x34, 0x71, 0x86, 0x83, 0x91, 0x21, 0x03, 0x88, 0x37, 0x92, 0x71, 0x37,
    0x33, 0x49, 0x91, 0x06, 0x50, 0x09, 0x67, 0x97, 0x12, 0x47, 0x31, 0x29, 0x46, 0x33, 0x56, 0x7F,
];

pub const HOLY_PRIME_STR: &'static str = "
+21894553314596771561196871363069090541066762948
70157456716402010926713667965837048694374397583
78755519997241256754797139266100111579789434807
48521006430553187436563793040135859147314200060
83403747672105468702033255452148295330793327933
25692465402226448990520197344025781321477903218
19673041697183485577751556671866087760112758069
11221531862349142297374310995940898911985392506
12214249149695921199640927909666270781880617048
38361168099808241706347071334601734718683912103
88379271373349910650096797124731294633567866611
79887344268188974672850054280518419721295182781
36019917483333422790215788404956414952116894714
913327
";

pub const AUTH_BITS_SMALL: usize = 2048;
pub const AUTH_BITS_LARGE: usize = 4096;
pub const AUTH_EXPONENT: u32 = 65537;

pub fn get_exponent() -> rsa::BigUint {
    rsa::BigUint::from_u32(AUTH_EXPONENT).unwrap()
}

pub fn get_g() -> BigUint {
    BigUint::from_u8(2).unwrap()
}

pub fn get_holy_prime() -> BigUint {
    let cleaned: String = HOLY_PRIME_STR.chars().filter(|c| c.is_digit(10)).collect();
    BigUint::from_str(&cleaned).expect("failed to parse holy prime")
}

/// TODO: Change later to custom key type
pub struct Keypair {
    pub public: BigUint,
    pub private: BigUint,
}

impl Keypair {
    pub fn generate_random() -> Self {
        let mut rng = rand::thread_rng();
        let mut secret = [0u8; 256];
        rng.fill(&mut secret);
        let private = BigUint::from_bytes_be(&secret);
        let public = Self::generate_public_key(&private);

        Self { public, private }
    }

    pub fn from_secret(secret: BigUint) -> Self {
        let public = Self::generate_public_key(&secret);

        Self {
            public,
            private: secret,
        }
    }

    fn generate_public_key(secret: &BigUint) -> BigUint {
        let prime = get_holy_prime();
        let g = get_g();
        g.modpow(secret, &prime)
    }

    pub fn session(&self, public: &BigUint) -> Session {
        let prime = get_holy_prime();
        let session_key = public.modpow(&self.private, &prime).to_bytes_be();
        let mut session = [0u8; 16];
        session.copy_from_slice(&session_key[0..16]);

        Session(session)
    }

    pub fn public(&self) -> DhPublicKey {
        let mut dh_public_array = [0u8; 256];
        dh_public_array.copy_from_slice(&self.public.to_bytes_be());
        dh_public_array
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Session(pub protocol::Session);

impl From<protocol::Session> for Session {
    fn from(value: protocol::Session) -> Self {
        Self(value)
    }
}

pub struct Authentication {}

pub struct EncryptedData {
    pub data: Vec<u8>,
    pub nonce: [u8; 16],
}

pub type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

impl EncryptedData {
    pub fn new(data: Vec<u8>, nonce: Nonce) -> Self {
        let mut nonce_array = [0u8; 16];
        nonce_array[0] = nonce;
        Self {
            data,
            nonce: nonce_array,
        }
    }

    // TODO: Should nonce be random?
    fn rand_nonce() -> [u8; 16] {
        let mut nonce = [0u8; 16];
        nonce.fill(0);
        nonce[0] = rand::random();
        nonce
    }

    pub fn encrypt(data: &str, session: &Session) -> Self {
        let data: Vec<u8> = data.bytes().collect();
        let nonce = EncryptedData::rand_nonce(); // This should not be random, it should be incremented each message
        let mut cipher = Aes128Ctr64LE::new(&session.0.into(), &nonce.into());
        let mut data = data.to_vec();
        cipher.apply_keystream(&mut data);
        Self { nonce, data }
    }

    pub fn decrypt(self, session: &Session) -> String {
        let mut cipher = Aes128Ctr64LE::new(&session.0.into(), &self.nonce.into());
        let mut decrypted_data = self.data.clone();
        cipher.apply_keystream(&mut decrypted_data);
        String::from_utf8(decrypted_data).expect("Failed to decode UTF-8")
    }
}
