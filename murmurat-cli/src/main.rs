use std::{net::IpAddr, str::FromStr, thread::panicking};

use clap::Parser;
use client::MurmuratClient;
use murmurat_core::{RsaAuthentication, encryption::Keypair};
use server::MurmuratServer;

mod client;
mod server;

#[derive(Parser)]
struct Cli {
    #[clap(long, default_value = "127.0.0.1:1400")]
    host: std::net::SocketAddr,

    #[clap(long, default_value = "127.0.0.1:1401")]
    target: std::net::SocketAddr,

    #[clap(long)]
    server: bool,
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Use command-line arguments to retrieve parameters
    let args = Cli::parse();

    let keypair = Keypair::generate_random();
    let rsa = RsaAuthentication::generate_random();

    if args.server {
        println!("MurmuratServer listening on {}", args.host);
        let server = MurmuratServer::new(&args.target, keypair, rsa).await?;
        server.listen().await
    } else {
        println!("[i] MurmuratClient listening on {}", args.host);
        let mut client = MurmuratClient::new(&args.host, keypair, rsa).await?;

        println!("[i] MurmuratClient connecting to {}", args.target);
        client.connect(args.target).await?;
        println!("[+] MurmuratClient connected to {}", args.target);

        let input = std::io::stdin();

        loop {
            let mut message = String::default();
            input.read_line(&mut message)?;

            match message.as_str() {
                "exit" => break,
                _ => client.send(message.as_str()).await?,
            }
        }

        Ok(())
    }
}
