use murmurat_core::{
    RsaAuthentication,
    attack::*,
    encryption::{EncryptedData, Keypair},
};

fn main() {
    let mut attacker = SessionAttacker::new();

    let server_keypair = Keypair::generate_random();
    let client_keypair = Keypair::generate_random();
    let rsa = RsaAuthentication::generate_random();

    let session = client_keypair.session(&server_keypair.public);

    let message = "Hello world!";
    let nonce = 0u8;
    let encrypted = EncryptedData::encrypt(&message, &session);

    let recoverd = attacker.try_recover_session(
        &client_keypair.public(),
        &server_keypair.public(),
        &encrypted.data,
        nonce,
    );

    if let Some(session) = recoverd {
        println!("Recovered session: {:?}", session);
    } else {
        println!("Failed to recover session");
    }
}
