use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::SystemTime,
};

use bytes::Bytes;
use clap::Parser;
use murmurat_core::{
    coding::{Decode, Encode},
    message::MurmuratMessage,
};
use pcap_parser::{
    Block, EnhancedPacketBlock, PcapBlockOwned, PcapNGReader,
    traits::{PcapNGPacketBlock, PcapReaderIterator},
};
use socket2::{Domain, Protocol, Socket, Type};

fn relay(socket: &Socket, packets: &Vec<(Vec<u8>, MurmuratMessage)>) -> std::io::Result<()> {
    for (raw_packet, message) in packets {
        if let MurmuratMessage::Data(message_data) = message {
            let mut packet_data = raw_packet.clone();

            // Decode message, update timestamp, and re-encode
            let mut modified_message = message_data.clone();
            let timestamp: u32 = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32;
            modified_message.timestamp = timestamp;

            // Encode the modified message
            let mut payload = Vec::new();
            modified_message.encode(&mut payload).unwrap();

            // Replace payload in the original packet (starting at UDP data offset)
            // Assuming 20 bytes for IP header and 8 bytes for UDP header
            if payload.len() <= raw_packet.len() - 28 {
                packet_data[28..28 + payload.len()].copy_from_slice(&payload);

                // Update UDP length field (bytes 24-25)
                let udp_length = 8 + payload.len(); // UDP header (8) + payload
                packet_data[24] = ((udp_length >> 8) & 0xFF) as u8;
                packet_data[25] = (udp_length & 0xFF) as u8;

                // Update IP total length field (bytes 2-3)
                let total_length = 20 + udp_length; // IP header (20) + UDP length
                packet_data[2] = ((total_length >> 8) & 0xFF) as u8;
                packet_data[3] = (total_length & 0xFF) as u8;

                // Recalculate IP header checksum
                let ip_checksum = calculate_checksum(&packet_data[0..20]);
                packet_data[10] = ((ip_checksum >> 8) & 0xFF) as u8;
                packet_data[11] = (ip_checksum & 0xFF) as u8;

                // Recalculate UDP checksum
                let src_ip = Ipv4Addr::new(
                    packet_data[12],
                    packet_data[13],
                    packet_data[14],
                    packet_data[15],
                );
                let dst_ip = Ipv4Addr::new(
                    packet_data[16],
                    packet_data[17],
                    packet_data[18],
                    packet_data[19],
                );

                // Reset UDP checksum field to 0 before calculation
                packet_data[26] = 0;
                packet_data[27] = 0;

                // Calculate UDP checksum
                let udp_checksum =
                    calculate_udp_checksum(&packet_data[20..20 + udp_length], src_ip, dst_ip);
                packet_data[26] = ((udp_checksum >> 8) & 0xFF) as u8;
                packet_data[27] = (udp_checksum & 0xFF) as u8;

                // Get destination address from the packet
                let dest_ip = Ipv4Addr::new(
                    packet_data[16],
                    packet_data[17],
                    packet_data[18],
                    packet_data[19],
                );

                let dest_port = ((packet_data[22] as u16) << 8) | packet_data[23] as u16;
                let dest_addr = SocketAddr::new(IpAddr::V4(dest_ip), dest_port);

                // Send the modified packet
                socket.send_to(&packet_data, &dest_addr.into())?;
            } else {
                eprintln!("Warning: Modified payload larger than original - packet skipped");
            }
        }
    }
    Ok(())
}

fn process_packets(
    filename: &str,
    buffer: &mut Vec<(Vec<u8>, MurmuratMessage)>,
) -> std::io::Result<()> {
    let file = File::open(filename)?;
    let mut reader =
        PcapNGReader::new(1024 * 1024 * 100, file).expect("Failed to create PcapNGReader");

    while let Ok((size, block)) = reader.next() {
        match block {
            PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                if let Some(murmurat) = process_packet(&packet) {
                    buffer.push((packet.data.to_vec(), murmurat));
                }
            }
            _ => {}
        }

        reader.consume(size);
    }
    Ok(())
}

fn process_packet(epb: &EnhancedPacketBlock) -> Option<MurmuratMessage> {
    let packet_data = epb.packet_data();

    // internet, udp bla bla
    let data = &packet_data[28..];

    let mut buffer = Bytes::copy_from_slice(data);
    if let Ok(msg) = MurmuratMessage::decode(&mut buffer) {
        return Some(msg);
    } else {
        eprintln!("Failed to decode");
    }

    None
}

#[derive(Parser)]
struct Cli {
    #[clap(long)]
    file: String,

    #[clap(long, default_value = "127.0.0.1:4007")]
    addr: SocketAddr,

    #[clap(long, default_value = "127.0.0.1:4007")]
    target: SocketAddr,
}

fn main() -> std::io::Result<()> {
    let args = Cli::parse();

    // Process packets and keep both raw data and decoded messages
    let mut packets = Vec::new();
    process_packets(&args.file, &mut packets)?;
    println!("Found {} valid packets to relay", packets.len());

    // Create a raw socket
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::UDP))?;
    socket.set_header_included_v4(true)?;

    // Relay packets
    relay(&socket, &packets)?;

    println!("Finished relaying all packets");
    Ok(())
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Process 2 bytes at a time
    for i in 0..(data.len() / 2) {
        let word = ((data[i * 2] as u32) << 8) | (data[i * 2 + 1] as u32);
        sum += word;
    }

    // Handle odd-length data
    if data.len() % 2 == 1 {
        sum += (data[data.len() - 1] as u32) << 8;
    }

    // Add carry
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

fn calculate_udp_checksum(udp_data: &[u8], src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> u16 {
    let mut sum: u32 = 0;

    // Pseudoheader: source IP (4 bytes)
    let src_octets = src_ip.octets();
    sum += ((src_octets[0] as u32) << 8) | (src_octets[1] as u32);
    sum += ((src_octets[2] as u32) << 8) | (src_octets[3] as u32);

    // Pseudoheader: destination IP (4 bytes)
    let dst_octets = dst_ip.octets();
    sum += ((dst_octets[0] as u32) << 8) | (dst_octets[1] as u32);
    sum += ((dst_octets[2] as u32) << 8) | (dst_octets[3] as u32);

    // Pseudoheader: protocol (UDP = 17) and UDP length
    sum += 17;
    sum += udp_data.len() as u32;

    // Process UDP data 2 bytes at a time
    for i in 0..(udp_data.len() / 2) {
        let word = ((udp_data[i * 2] as u32) << 8) | (udp_data[i * 2 + 1] as u32);
        sum += word;
    }

    // Handle odd-length data
    if udp_data.len() % 2 == 1 {
        sum += (udp_data[udp_data.len() - 1] as u32) << 8;
    }

    // Add carry
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Optional for UDP: if the calculated checksum is 0, it should be set to 0xFFFF
    let result = !sum as u16;
    if result == 0 { 0xFFFF } else { result }
}
