use bytes::{Bytes, BytesMut};
use murmurat_core::{
    RsaAuthentication,
    coding::{Decode, Encode},
    encryption::{EncryptedData, Keypair, Session},
    message::{DHMessage, MurmuratMessage},
    protocol,
};
use num_bigint::BigUint;
use std::{
    collections::HashMap,
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    time::SystemTime,
};
use tokio::net::{ToSocketAddrs, UdpSocket};

#[derive(Clone)]
struct ClientSession {
    session: Session,
    client_rsa_public: std::collections::HashMap<protocol::RsaPublicKeyId, protocol::RsaPublic>,
}

pub struct MurmuratClient {
    /// Client socket
    socket: UdpSocket,

    /// Generated keypair for encryption
    keypair: Keypair,

    /// Generated rsa authentication keys
    rsa: RsaAuthentication,

    /// Server addr
    target_addr: Option<SocketAddr>,

    /// Current session with target
    session: Option<ClientSession>,
}

impl MurmuratClient {
    pub async fn new<T>(addr: T, keypair: Keypair, rsa: RsaAuthentication) -> std::io::Result<Self>
    where
        T: ToSocketAddrs,
    {
        let socket = UdpSocket::bind(&addr).await?;

        Ok(Self {
            socket,
            keypair,
            rsa,
            session: None,
            target_addr: None,
        })
    }

    pub async fn connect(&mut self, addr: SocketAddr) -> std::io::Result<()> {
        // Create a "DH" message to initiate the connection
        let dh_message = MurmuratMessage::DH(murmurat_core::message::DHMessage {
            dh_public: self.keypair.public(),
        });

        self.send_message(&dh_message, &addr).await?;

        let MurmuratMessage::DH(dh_response) = self.recv_message().await? else {
            panic!("Invalid response from server");
        };

        let public = BigUint::from_bytes_be(&dh_response.dh_public);
        let session = self.keypair.session(&public);

        // Create a "Hello" message after DH exchange
        let hello_message = MurmuratMessage::Hello(murmurat_core::message::HelloMessage {
            pubkey_id: self.rsa.id,
            rsa_public: self.rsa.key_bytes,
        });

        self.send_message(&hello_message, &addr).await?;

        let MurmuratMessage::Hello(hello_response) = self.recv_message().await? else {
            panic!("Invalid response from server");
        };

        let public_keys = HashMap::from([(hello_response.pubkey_id, hello_response.rsa_public)]);

        // let session: Session = hello_response.
        self.session = Some(ClientSession {
            session,
            client_rsa_public: public_keys,
        });

        self.target_addr = Some(addr);

        Ok(())
    }

    pub async fn send(&self, message: &str) -> std::io::Result<()> {
        let Some(ref session) = self.session else {
            panic!("Should have a session before sending");
        };

        let encrypted = EncryptedData::encrypt(message, &session.session);
        let signature = self.rsa.sign(&encrypted.data);

        let timestamp: u32 = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        // Create a DataMessage from the input message
        let data_message = MurmuratMessage::Data(murmurat_core::message::DataMessage {
            length: message.len() as u16,
            nonce: encrypted.nonce[0],
            timestamp,
            data: encrypted.data.clone(),
            public_key_id: self.rsa.id,
            signature,
        });

        let Some(addr) = self.target_addr else {
            panic!("Should have a target addr before sending");
        };

        self.send_message(&data_message, &addr).await?;

        Ok(())
    }

    async fn recv_message(&self) -> std::io::Result<MurmuratMessage> {
        let mut buf = [0u8; 2048];
        let _ = self.socket.recv_from(&mut buf).await?;
        let mut buf = Bytes::copy_from_slice(buf.as_slice());
        Ok(MurmuratMessage::decode(&mut buf).expect("failed to decode message"))
    }

    async fn send_message<T, A>(&self, message: &T, addr: &A) -> std::io::Result<()>
    where
        T: Encode + Debug,
        A: ToSocketAddrs,
    {
        let mut buffer = Vec::new();
        message.encode(&mut buffer).unwrap();
        self.socket.send_to(&buffer, addr).await?;
        Ok(())
    }
}
