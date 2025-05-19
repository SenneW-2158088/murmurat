use std::thread::panicking;

use client::MurmuratClient;
use server::MurmuratServer;
use murmurat_core::{encryption::Keypair, RsaAuthentication};
use clap::Parser;

mod client;
mod server;

#[derive(Parser)]
struct Cli {
    #[clap(long, default_value = "127.0.0.1")]
    host: String,
    #[clap(long)]
    port: Option<String>,
    #[clap(long)]
    connect_port: Option<String>,
    #[clap(long)]
    server: bool,
}
#[tokio::main]
async fn main() -> std::io::Result<()> {
    // Use command-line arguments to retrieve parameters
    let args = Cli::parse();

    let addr = match args.port {
        Some(port) => format!("{}:{}", args.host, port),
        None => format!("{}:8080", args.host),
    };

    let connect_addr = match args.connect_port {
        Some(connect_port) => Some(format!("{}:{}", args.host, connect_port)),
        None => None,
    };

    if args.server {
        let keypair = Keypair::generate_random();
        let rsa = RsaAuthentication::generate_random();
        let server = MurmuratServer::new(&addr, keypair, rsa).await?;
        println!("MurmuratServer listening on {}", addr);
        server.listen().await
    } else {
        if connect_addr.is_none() {
            panic!("Provide port for client");
        }
        let keypair = Keypair::generate_random();
        let rsa = RsaAuthentication::generate_random();
        println!("MurmuratClient listening on {}", addr);
        println!("MurmuratClient connecting to {:?}", connect_addr);
        let client = MurmuratClient::new(&addr, &connect_addr.unwrap(), keypair, rsa).await?;
        client.connect().await;
        client.send("hello world!");
        Ok(())
    }
}
