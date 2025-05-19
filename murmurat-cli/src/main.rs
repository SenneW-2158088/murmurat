use client::MurmuratClient;
use murmurat_core::{encryption::Keypair, RsaAuthentication};
use clap::Parser;

mod client;

#[derive(Parser)]
struct Cli {
    #[clap(long, default_value = "127.0.0.1")]
    host: String,
    #[clap(long)]
    port: Option<String>,
    #[clap(long)]
    connect_port: Option<String>,
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
        Some(connect_port) => format!("{}:{}", args.host, connect_port),
        None => format!("{}:9090", args.host),
    };

    let keypair = Keypair::generate_random();
    let rsa = RsaAuthentication::generate_random();
    // Initialize the MurmuratClient
    let client = MurmuratClient::new(&addr, keypair, rsa).await?;
    println!("MurmuratClient listening on {}", addr);
    println!("MurmuratClient connecting to {}", connect_addr);

    // Start listening for messages
    client.listen().await
}
