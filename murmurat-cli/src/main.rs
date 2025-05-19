use std::{net::IpAddr, str::FromStr, thread::panicking};

use clap::Parser;
use client::MurmuratClient;
use murmurat_core::{RsaAuthentication, encryption::Keypair};
use server::MurmuratServer;

mod client;
mod server;

#[derive(Parser)]
struct Cli {
    #[clap(long, default_value = "127.0.0.1:4000")]
    host: std::net::SocketAddr,

    #[clap(long, default_value = "127.0.0.1:4001")]
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
        println!("MurmuratClient listening on {}", args.host);
        let mut client = MurmuratClient::new(&args.host, keypair, rsa).await?;

        println!("MurmuratClient connecting to {}", args.target);
        client.connect(args.target).await?;

        client.send("hello world!").await?;

        Ok(())
    }
}
