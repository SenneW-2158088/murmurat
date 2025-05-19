use num_bigint::BigUint;
use tokio::net::UdpSocket;
use murmurat_core::{encryption::Keypair, message::MurmuratMessage, protocol, RsaAuthentication};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Clone)]
struct ClientSession {
    session:  Option<protocol::Session>,
    client_rsa_public: std::collections::HashMap<protocol::RsaPublicKeyId, protocol::RsaPublic>
}

pub struct MurmuratClient {
    socket: Arc<UdpSocket>,
    dh_keypair: Keypair,
    rsa: RsaAuthentication,
    session: Arc<Mutex<ClientSession>>
}

impl MurmuratClient {
    pub async fn new(addr: &str, keypair: Keypair, rsa: RsaAuthentication) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            dh_keypair: keypair,
            rsa,
            session: Arc::new(Mutex::new(ClientSession {
                session: None,
                client_rsa_public: std::collections::HashMap::new()
            }))
        })
    }

    pub async fn listen(&self) -> std::io::Result<()> {
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
            let mut session_guard = session.lock().unwrap();
        }

        Ok(())
    }

    pub async fn connect(&self, addr: &str) -> std::io::Result<()> {
        let socket = self.socket.clone();
        let session = self.session.clone();

        // Create a "DH" message to initiate the connection
        let mut dh_public_array = [0u8; 255];
        dh_public_array.copy_from_slice(&self.dh_keypair.public.to_bytes_be());
        let dh_message = MurmuratMessage::DH(murmurat_core::message::DHMessage {
            dh_public: dh_public_array,
        });

        // Encode the DH message
        let encoded_dh_message = dh_message.encode();

        // Send the DH message to the specified address
        socket.send_to(&encoded_dh_message, addr).await?;

        // Wait for a response
        let mut buf = vec![0u8; 65535];
        match socket.recv_from(&mut buf).await {
            Ok((size, _)) => {
                let response_message = MurmuratMessage::decode(&buf[..size]);

                // Handle the response message
                match response_message {
                    MurmuratMessage::Hello(hello_message) => {
                        let mut session_guard = session.lock().unwrap();
                        session_guard.client_rsa_public
                            .insert(hello_message.pubkey_id, hello_message.rsa_public);
                    }
                    _ => {
                        eprintln!("Unexpected message type received during connection.");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving response during connection: {}", e);
            }
        }

        // Create a "Hello" message after DH exchange
        let hello_message = MurmuratMessage::Hello(murmurat_core::message::HelloMessage {
            pubkey_id: self.rsa.id,
            rsa_public: self.rsa.key,
        });

        // Encode the Hello message
        let encoded_hello_message = hello_message.encode();

        // Send the Hello message to the specified address
        socket.send_to(&encoded_hello_message, addr).await?;

        Ok(())
    }

    fn handle_message(&mut self, message: MurmuratMessage) {
        match message {
            MurmuratMessage::DH(dhmessage) => {
                let mut session_guard = self.session.lock().unwrap();
                let pubkey = BigUint::from_bytes_be(&dhmessage.dh_public);
                let session = self.dh_keypair.session(&pubkey);
                session_guard.session = Some(session.0)
            },
            MurmuratMessage::Hello(hello_message) => {
                let mut session_guard = self.session.lock().unwrap();
                session_guard.client_rsa_public
                    .insert(hello_message.pubkey_id, hello_message.rsa_public);
            },
            MurmuratMessage::Data(data_message) => {
            },
        }
    }
}
