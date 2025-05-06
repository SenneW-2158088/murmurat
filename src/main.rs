use std::str::FromStr;

use aes::{cipher::{KeyIvInit, StreamCipher}, Aes128};
use encryption::{get_exponent, Keypair, Session, AUTH_BITS_LARGE};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::FromPrimitive;
use rand::{Rng, RngCore, rngs::OsRng};
use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};

mod coding;
mod encryption;
mod message;
mod protocol;

fn diffie_hellman() {
    let client = Keypair::generate_random();

    let server = Keypair::generate_random();

    let client_session = client.session(&server.public);
    let server_session = server.session(&client.public);

    println!("Client Session: {:?}", client_session);
    println!("Server Session: {:?}", server_session);
    assert_eq!(client_session, server_session)
}

#[derive(Debug)]
pub struct Authentication {
    pub id: u32,
    pub key: [u8; 512],
}

impl Authentication {
    pub fn generate_random() -> Self {
        let mut rng = rand::thread_rng();

        let exponent = get_exponent();
        let bits = AUTH_BITS_LARGE;
        let rsa = RsaPrivateKey::new_with_exp(&mut rng, bits, &exponent)
            .expect("Failed to generate a key");
        let modulus = rsa.n().to_bytes_be();

        let mut key = [0u8; 512];

        if modulus.len() <= 512 {
            key.copy_from_slice(&modulus);
        } else {
            key.copy_from_slice(&modulus[..512]);
        }

        let id: u32 = rand::random();

        Self { id, key }
    }
}

struct EncryptedMessage {
    data: Vec<u8>,
    nonce: [u8; 16]
}

type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

impl EncryptedMessage {
    // TODO: Should nonce be random?
    fn rand_nonce()-> [u8; 16] {
        let mut rng = OsRng;
        let mut nonce = [0u8; 16];
        rng.fill_bytes(&mut nonce);
        nonce
    }

    pub fn encrypt(data: &str, session: Session) -> Self {
        let data: Vec<u8> = data.bytes().collect();
        let nonce = EncryptedMessage::rand_nonce();
        let mut cipher = Aes128Ctr64LE::new(&session.0.into(), &nonce.into());
        let mut data = data.to_vec();
        cipher.apply_keystream(&mut data);
        Self {
            nonce,
            data
        }
    }

    pub fn decrypt(self, session: Session) -> String {
        let mut cipher = Aes128Ctr64LE::new(&session.0.into(), &self.nonce.into());
        let mut decrypted_data = self.data.clone();
        cipher.apply_keystream(&mut decrypted_data);
        String::from_utf8(decrypted_data).expect("Failed to decode UTF-8")
    }
}

fn main() {
    let client = Keypair::generate_random();
    let server = Keypair::generate_random();

    let client_session = client.session(&server.public);
    let server_session = server.session(&client.public);

    let client_auth = Authentication::generate_random();
    let server_auth = Authentication::generate_random();

    // Data to encrypt
    let data = "Hello, this is a test message.";

    let encrypted = EncryptedMessage::encrypt(data, client_session);
    println!("Encrypted data: {:?}", encrypted.data);

    let decrypted = encrypted.decrypt(server_session);
    // Output the decrypted data
    println!("Decrypted data: {:?}", decrypted);
}
