use std::str::FromStr;

use encryption::Keypair;
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::FromPrimitive;
use protocol::Key;
use rand::fill;

mod coding;
mod encryption;
mod message;
mod protocol;

fn session_derivation(key: BigUint) {}

fn key_derivation() {
    let g: BigUint = BigUint::from_u8(2).unwrap();
    let holy_prime = encryption::get_holy_prime();

    let mut secret = [0u8; 256];
    fill(&mut secret);
    let secret = BigUint::from_bytes_be(&secret);

    println!("G: {}", g);
    println!("Prime: {}", holy_prime);
    println!("Secret: {}", secret);

    let public_key = g.modpow(&secret, &holy_prime);
    println!("Public key: {}", public_key)
}

fn main() {
    let client = Keypair::generate_random();

    let server = Keypair::generate_random();

    let client_session = client.session(&server.public);
    let server_session = server.session(&client.public);

    println!("Client Session: {:?}", client_session);
    println!("Server Session: {:?}", server_session);
    assert_eq!(client_session, server_session)
}
