use std::str::FromStr;

use encryption::{get_exponent, EncryptedData, Keypair, Session, AUTH_BITS_LARGE};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::FromPrimitive;
use rand::{Rng, RngCore, rngs::OsRng};
use rsa::{RsaPrivateKey, RsaPublicKey, traits::PublicKeyParts};

pub mod coding;
pub mod encryption;
pub mod message;
pub mod protocol;

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
pub struct RsaAuthentication {
    pub id: u32,
    pub key: [u8; 512],
}

impl RsaAuthentication {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_decryption() {
        let client = Keypair::generate_random();
        let server = Keypair::generate_random();

        let client_session = client.session(&server.public);
        let server_session = server.session(&client.public);

        let client_auth = RsaAuthentication::generate_random();
        let server_auth = RsaAuthentication::generate_random();

        // Data to encrypt
        let data = "Hello, this is a test message.";

        let encrypted = EncryptedData::encrypt(data, client_session);
        assert!(!encrypted.data.is_empty(), "Encrypted data should not be empty");

        let decrypted = encrypted.decrypt(server_session);
        assert_eq!(decrypted, data, "Decrypted data should match the original");
    }
}
