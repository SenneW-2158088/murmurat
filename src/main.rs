use std::str::FromStr;

use encryption::{AUTH_BITS_LARGE, Keypair, get_exponent};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::FromPrimitive;
use protocol::Key;
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

fn main() {
    let auth = Authentication::generate_random();
    println!("Auth: {:?}", auth);
}
