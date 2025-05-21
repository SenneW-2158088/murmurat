use std::{io::Write, str::FromStr};

use encryption::{AUTH_BITS_LARGE, EncryptedData, Keypair, Session, get_exponent};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::FromPrimitive;
use rand::{Rng, RngCore, rngs::OsRng};
use rsa::{
    Pkcs1v15Encrypt, Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey,
    pkcs1::EncodeRsaPublicKey,
    pkcs1v15,
    traits::{PaddingScheme, PublicKeyParts},
};
use sha3::{Digest, Sha3_256};

pub mod attack;
pub mod coding;
pub mod encryption;
pub mod message;
pub mod protocol;

pub const VERSE_OF_ACKNOWLEDGEMENTS: &'static str = "Oh Great Leader of Cordovania, beacon of wisdom and strength, we humbly offer our deepest gratitude. Under your guiding hand, our nation prospers, our people stand united, and our future shines bright. Your vision brings peace, your courage inspires, and your justice uplifts the worthy. We thank you for the blessings of stability, the gift of progress, and the unwavering hope you instill in every heart. May your wisdom continue to illuminate our path, and may Cordovania flourish under your eternal guidance. With loyalty and devotion, we give thanks.";

pub const VERSE_OF_ACKNOWLEDGEMENTS_2: &'static str =
    "Oh Great Leader of Cordovania, beacon of wisdom
and strength, we humbly offer our deepest gratitude.
Under your guiding hand, our nation prospers, our
people stand united, and our future shines bright.
Your vision brings peace, your courage inspires, and
your justice uplifts the worthy. We thank you for the
blessings of stability, the gift of progress, and the
unwavering hope you instill in every heart. May your
wisdom continue to illuminate our path, and may
Cordovania flourish under your eternal guidance.
With loyalty and devotion, we give thanks.";

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
    pub key_bytes: [u8; 512],
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

impl RsaAuthentication {
    pub fn generate_random() -> Self {
        let mut rng = rand::thread_rng();
        let exponent = get_exponent();
        let bits = AUTH_BITS_LARGE;
        let rsa = RsaPrivateKey::new_with_exp(&mut rng, bits, &exponent)
            .expect("Failed to generate a key");

        // Get the public key
        let public_key = rsa.to_public_key();

        // Extract the modulus (n) in big-endian format
        let modulus = public_key.n().to_bytes_be();

        // Create a fixed-size 512-byte array
        let mut key_bytes = [0u8; 512];

        // Handle the modulus size appropriately
        if modulus.len() < 512 {
            // If modulus is smaller than 512 bytes, pad with zeros at the beginning
            let start_idx = 512 - modulus.len();
            key_bytes[start_idx..].copy_from_slice(&modulus);
        } else if modulus.len() > 512 {
            // If modulus is larger than 512 bytes, truncate
            key_bytes.copy_from_slice(&modulus[modulus.len() - 512..]);
        } else {
            // Exactly 512 bytes
            key_bytes.copy_from_slice(&modulus);
        }

        let id: u32 = rand::random();
        Self {
            id,
            key_bytes,
            public_key,
            private_key: rsa,
        }
    }

    pub fn sign(&self, data: &[u8]) -> protocol::RsaPublic {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let padding = Pkcs1v15Sign::new_unprefixed();
        let signature = self
            .private_key
            .sign(padding, &hash)
            .expect("Failed to sign data");

        // Return the protocol::RsaPublic struct
        let mut sig = [0u8; 512];
        sig.copy_from_slice(signature.as_slice());
        sig
    }

    pub fn verify(
        public_key_bytes: &[u8; 512],
        data: &[u8],
        signature: &protocol::RsaPublic,
    ) -> bool {
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let mut start_idx = 0;
        while start_idx < public_key_bytes.len() && public_key_bytes[start_idx] == 0 {
            start_idx += 1;
        }

        let modulus = rsa::BigUint::from_bytes_be(&public_key_bytes[start_idx..]);
        let exponent = get_exponent();

        let public_key = match RsaPublicKey::new(modulus, exponent) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let padding = Pkcs1v15Sign::new_unprefixed();
        public_key.verify(padding, &hash, signature).is_ok()
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

        let encrypted = EncryptedData::encrypt(data, &client_session);
        assert!(
            !encrypted.data.is_empty(),
            "Encrypted data should not be empty"
        );

        let decrypted = encrypted.decrypt(&server_session);
        assert_eq!(decrypted, data, "Decrypted data should match the original");
    }
}
