use bytes::{Bytes, BytesMut};
use murmurat_core::coding::{Decode, Encode};
use murmurat_core::encryption::{EncryptedData, Session};
use murmurat_core::{RsaAuthentication, encryption::Keypair, message::MurmuratMessage, protocol};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc;

#[derive(Clone)]
struct ServerSession {
    session: Session,
    client_rsa_public: std::collections::HashMap<protocol::RsaPublicKeyId, protocol::RsaPublic>,
}

pub struct MurmuratServer {
    /// Socket to bind on
    socket: UdpSocket,

    /// Keypair for dh exchange
    keypair: Keypair,

    /// Rsa authentication keys
    rsa: RsaAuthentication,

    /// Current sessions
    sessions: HashMap<SocketAddr, ServerSession>,
}

impl MurmuratServer {
    pub async fn new<T>(addr: T, keypair: Keypair, rsa: RsaAuthentication) -> std::io::Result<Self>
    where
        T: ToSocketAddrs,
    {
        let socket = UdpSocket::bind(&addr).await?;
        Ok(Self {
            socket,
            keypair,
            rsa,
            sessions: HashMap::default(),
        })
    }

    pub async fn listen(mut self) -> std::io::Result<()> {
        while let Ok((addr, message)) = self.recv_message().await {
            self.handle_message(addr, message).await?;
        }

        Ok(())
    }

    async fn handle_message(
        &mut self,
        addr: SocketAddr,
        message: MurmuratMessage,
    ) -> std::io::Result<()> {
        match message {
            MurmuratMessage::DH(dh_message) => {
                if self.sessions.contains_key(&addr) {
                    panic!("Should not get dh when session established");
                }

                let public = BigUint::from_bytes_be(&dh_message.dh_public);
                let session = self.keypair.session(&public);

                // Create a "DH" message to initiate the connection
                let dh_response = MurmuratMessage::DH(murmurat_core::message::DHMessage {
                    dh_public: self.keypair.public(),
                });

                self.send_message(&dh_response, &addr).await?;

                let session = ServerSession {
                    session,
                    client_rsa_public: HashMap::default(),
                };

                self.sessions.insert(addr, session);

                println!("[+] Client session created for {}", addr);
            }
            MurmuratMessage::Hello(hello_response) => {
                if let Some(session) = self.sessions.get_mut(&addr) {
                    session
                        .client_rsa_public
                        .insert(hello_response.pubkey_id, hello_response.rsa_public);
                } else {
                    panic!("Should have a session when performing hello")
                }

                // Create a "Hello" message after DH exchange
                let hello_message = MurmuratMessage::Hello(murmurat_core::message::HelloMessage {
                    pubkey_id: self.rsa.id,
                    rsa_public: self.rsa.key,
                });

                self.send_message(&hello_message, &addr).await?;
            }
            MurmuratMessage::Data(data_message) => {
                if let Some(session) = self.sessions.get(&addr) {
                    let encrypted = EncryptedData::new(data_message.data, data_message.nonce);
                    let decrypted = encrypted.decrypt(&session.session);
                    println!("[{}] => {}", addr, decrypted);
                } else {
                    panic!("Couldn't decrypt data...no session")
                }
            }
        }

        Ok(())
    }

    async fn recv_message(&self) -> std::io::Result<(SocketAddr, MurmuratMessage)> {
        let mut buf = [0u8; 2048];
        let (_, addr) = self.socket.recv_from(&mut buf).await?;
        let mut buf = Bytes::copy_from_slice(buf.as_slice());
        Ok((
            addr,
            MurmuratMessage::decode(&mut buf).expect("failed to decode message"),
        ))
    }

    async fn send_message<T, A>(&self, message: &T, addr: &A) -> std::io::Result<()>
    where
        T: Encode,
        A: ToSocketAddrs,
    {
        let mut buffer = Vec::new();
        message.encode(&mut buffer).unwrap();
        self.socket.send_to(&buffer, addr).await?;
        Ok(())
    }
}
