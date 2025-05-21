use std::collections::HashMap;

use aes::cipher::{KeyIvInit, StreamCipher};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::encryption::{Aes128Ctr64LE, EncryptedData, Session, get_g, get_holy_prime};

pub struct SessionAttacker {
    // Prime from the protocol
    holy_prime: BigUint,
    // The generator g=2
    generator: BigUint,
    // Small subgroups of the prime for the attack
    small_subgroups: Vec<(u32, BigUint)>, // (order, generator)
}

impl SessionAttacker {
    pub fn new() -> Self {
        let holy_prime = get_holy_prime();
        let generator = get_g();

        // Find small subgroups that will help with our attack
        let small_subgroups = Self::find_small_subgroups(&holy_prime);

        println!("[ATTACK] Initialized session attacker");
        println!(
            "[ATTACK] Found {} small subgroups to use in attack",
            small_subgroups.len()
        );

        Self {
            holy_prime,
            generator,
            small_subgroups,
        }
    }

    fn find_small_subgroups(p: &BigUint) -> Vec<(u32, BigUint)> {
        let one: BigUint = One::one();
        let p_minus_1 = p - &one;

        // Small factors to check
        let small_factors = vec![
            2u32, 3u32, 5u32, 7u32, 11u32, 13u32, 17u32, 19u32, 23u32, 29u32,
        ];

        // Check which of these are actually factors of p-1
        let mut subgroups = Vec::new();
        for factor in small_factors {
            let factor_bigint = BigUint::from(factor);

            // Check if factor divides p-1 (remainder is zero)
            if (&p_minus_1 % &factor_bigint).is_zero() {
                // This is a factor, so g^((p-1)/factor) generates a subgroup
                let exponent = &p_minus_1 / &factor_bigint;
                let subgroup_generator =
                    Self::generator_pow_mod(&BigUint::from(2u32), &exponent, p);
                subgroups.push((factor, subgroup_generator));
                println!("[ATTACK] Found small subgroup of order {}", factor);
            }
        }

        subgroups
    }

    fn generator_pow_mod(g: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
        g.modpow(exp, modulus)
    }

    pub fn calculate_subgroup_generator(p: &BigUint, factor: &BigUint) -> BigUint {
        let one: BigUint = One::one();
        let p_minus_1 = p - &one;
        let exponent = &p_minus_1 / factor;

        let g = BigUint::from(2u32);
        g.modpow(&exponent, p)
    }

    // This is the main attack function - it forces the public key into a small subgroup
    pub fn confine_to_subgroup(&self, public_key: &[u8]) -> Vec<u8> {
        let pubkey = BigUint::from_bytes_be(public_key);

        // We'll use the first small subgroup for the attack
        // In a real attack, you might try several or find the optimal one
        if let Some(first_subgroup) = self.small_subgroups.first() {
            let modified_key = pubkey.modpow(&first_subgroup.1, &self.holy_prime);
            println!("[ATTACK] Confined public key to small subgroup");
            return modified_key.to_bytes_be();
        }

        // If no subgroups found, just return the original key
        public_key.to_vec()
    }

    // Attempt to recover the session key from observed traffic
    pub fn try_recover_session(
        &mut self,
        client_pubkey: &[u8],
        server_pubkey: &[u8],
        encrypted_data: &[u8],
        nonce: u8,
    ) -> Option<Session> {
        let client_pubkey_bigint = BigUint::from_bytes_be(client_pubkey);
        let server_pubkey_bigint = BigUint::from_bytes_be(server_pubkey);

        // For each small subgroup we found
        for (order, subgroup_gen) in &self.small_subgroups {
            println!("[ATTACK] Trying subgroup of order {}", order);

            // Force both keys into this subgroup to limit the possible shared secrets
            let client_confined = client_pubkey_bigint.modpow(subgroup_gen, &self.holy_prime);
            let server_confined = server_pubkey_bigint.modpow(subgroup_gen, &self.holy_prime);

            // Now try all possible values in this subgroup
            let mut current = BigUint::one();

            for i in 0..*order {
                // Calculate possible session key
                let possible_shared_secret = current.to_bytes_be();

                // Take first 16 bytes as the protocol does
                let mut session_bytes = [0u8; 16];
                if possible_shared_secret.len() >= 16 {
                    session_bytes.copy_from_slice(&possible_shared_secret[0..16]);
                } else {
                    // Handle case where shared secret is shorter than 16 bytes
                    let offset = 16 - possible_shared_secret.len();
                    session_bytes[offset..].copy_from_slice(&possible_shared_secret);
                }

                // Create nonce array as the protocol does
                let mut nonce_array = [0u8; 16];
                nonce_array[0] = nonce;

                // Try to decrypt with this candidate key

                let session = Session(session_bytes);
                let encrypted = EncryptedData::new(encrypted_data.to_vec(), nonce);
                let mut cipher = Aes128Ctr64LE::new(&session.0.into(), &nonce_array.into());

                let mut decrypted_data = encrypted_data.to_vec();
                cipher.apply_keystream(&mut decrypted_data);

                if let Ok(decrypted) = String::from_utf8(decrypted_data.to_vec()) {
                    println!("[ATTACK] Found potentially valid decryption: {}", decrypted);
                }

                // Move to next element in subgroup
                current = (&current * subgroup_gen) % &self.holy_prime;
            }
        }

        None
    }
}
