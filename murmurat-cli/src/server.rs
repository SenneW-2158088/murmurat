use num_bigint::BigUint;
use tokio::net::UdpSocket;
use murmurat_core::{encryption::Keypair, message::MurmuratMessage, protocol, RsaAuthentication};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Clone)]
struct ServerSession {
    session:  Option<protocol::Session>,
    // public keys by id
    rsa_public_keys: std::collections::HashMap<protocol::RsaPublicKeyId, protocol::RsaPublic>
}

pub struct MurmuratServer {
    socket: Arc<UdpSocket>,
    dh_keypair: Keypair,
    rsa: RsaAuthentication,
    session: Arc<Mutex<ServerSession>>
}

impl MurmuratServer {
    pub async fn new(addr: &str, keypair: Keypair, rsa: RsaAuthentication) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            dh_keypair: keypair,
            rsa,
            session: Arc::new(Mutex::new(ServerSession {
                session: None,
                rsa_public_keys: std::collections::HashMap::new()
            }))
        })
    }

    pub async fn listen(mut self) -> std::io::Result<()> {
        let socket = self.socket.clone();
        let session = self.session.clone();
        let (tx, mut rx) = mpsc::channel(100);

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, _)) => {
                        let message = MurmuratMessage::decode(&buf[..size]);
                        let _ = tx.send(message).await;
                    }
                    Err(e) => {
                        eprintln!("Error receiving UDP packet: {}", e);
                    }
                }
            }
        });

        while let Some(message) = rx.recv().await {
            self.handle_message(message);
        }

        Ok(())
    }

    fn handle_message(&mut self, message: MurmuratMessage) {
        match message {
            MurmuratMessage::DH(dhmessage) => {
                let mut session_guard = self.session.lock().unwrap();
                let pubkey = BigUint::from_bytes_be(&dhmessage.dh_public);
                let session = self.dh_keypair.session(&pubkey);
                session_guard.session = Some(session)
            },
            MurmuratMessage::Hello(hello_message) => {
                let mut session_guard = self.session.lock().unwrap();
                session_guard.rsa_public_keys
                    .insert(hello_message.pubkey_id, hello_message.rsa_public);
            },
            MurmuratMessage::Data(data_message) => {
            },
        }
    }
}
