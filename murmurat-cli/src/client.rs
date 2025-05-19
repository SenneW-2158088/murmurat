use num_bigint::BigUint;
use tokio::{net::UdpSocket, signal::unix::signal};
use murmurat_core::{encryption::{EncryptedData, Keypair}, message::MurmuratMessage, protocol, RsaAuthentication};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

#[derive(Clone)]
struct ClientSession {
    session:  Option<protocol::Session>,
    client_rsa_public: std::collections::HashMap<protocol::RsaPublicKeyId, protocol::RsaPublic>
}

pub struct MurmuratClient {
    socket: Arc<UdpSocket>,
    target_addr: String,
    dh_keypair: Keypair,
    rsa: RsaAuthentication,
    session: Arc<Mutex<ClientSession>>
}

impl MurmuratClient {
    pub async fn new(addr: &str, target_addr: &str, keypair: Keypair, rsa: RsaAuthentication) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            socket: Arc::new(socket),
            dh_keypair: keypair,
            target_addr: String::from(target_addr),
            rsa,
            session: Arc::new(Mutex::new(ClientSession {
                session: None,
                client_rsa_public: std::collections::HashMap::new()
            }))
        })
    }

    pub async fn connect(&self) -> std::io::Result<()> {
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
        socket.send_to(&encoded_dh_message, self.target_addr.as_str()).await?;

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
        socket.send_to(&encoded_hello_message, self.target_addr.as_str()).await?;

        Ok(())
    }

    pub async fn send(&self, message: &str) -> std::io::Result<()> {
        let socket = self.socket.clone();

        let session_guard = self.session.lock().unwrap();
        let session = session_guard.session.unwrap();

        let encrypted = EncryptedData::encrypt(message, session);

        let signature = self.rsa.sign_message(message);

        // Create a DataMessage from the input message
        let data_message = MurmuratMessage::Data(murmurat_core::message::DataMessage {
            length: message.len() as u16,
            nonce: encrypted.nonce[0],
            timestamp: protocol::Timestamp::default(),
            data: encrypted.data.clone(),
            pubkey_id: self.rsa.id,
            signature: {
                let mut signature_array = [0u8; 512];
                let signature_bytes = &signature[..std::cmp::min(signature.len(), 512)];
                signature_array[..signature_bytes.len()].copy_from_slice(signature_bytes);
                signature_array
            },
        });
        // Encode the DataMessage
        let encoded_message = data_message.encode();

        // Send the encoded DataMessage to the specified address
        socket.send_to(&encoded_message, self.target_addr.as_str()).await?;

        Ok(())
    }
}
