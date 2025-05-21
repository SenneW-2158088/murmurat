use anyhow::{Context, Result};
use bytes::Bytes;
use etherparse::{PacketBuilder, SlicedPacket, TransportSlice};
use murmurat_core::{coding::Decode, message::MurmuratMessage};
use pcap::{Capture, Device};
use std::{net::Ipv4Addr, time::SystemTime};

fn main() -> Result<()> {
    // Find the loopback device
    let device = Device::list()?
        .into_iter()
        .find(|d| d.name.contains("lo"))
        .context("Failed to find loopback device")?;

    println!("Using device: {}", device.name);

    // Open the device for capturing
    let mut cap = Capture::from_device(device)?
        .immediate_mode(true)
        .promisc(true)
        .snaplen(65535)
        .open()?;

    cap.filter("udp", true)?;

    println!("Capturing packets on localhost...");

    loop {
        let packet: Option<Vec<u8>> = {
            if let Ok(p) = cap.next_packet() {
                match SlicedPacket::from_ethernet(&p.data) {
                    Ok(sliced) => process_packet(&sliced),
                    Err(_) => None,
                }
            } else {
                None
            }
        };

        if let Some(p) = packet {
            cap.sendpacket(p)?;
        }
    }
}

fn process_packet(packet: &SlicedPacket) -> Option<Vec<u8>> {
    // Since transport is None, we need to manually extract the UDP payload
    if let Some(link) = &packet.link {
        match link {
            etherparse::LinkSlice::Ethernet2(eth) => {
                let mut payload = Vec::new();

                if eth.ether_type() == 0x4011.into() {
                    let e_p = eth.payload().payload;
                    if e_p.len() > 512 {
                        let potential_murmurat_data = &payload[18..];
                        // hexdump(potential_murmurat_data, 1024);

                        let mut buffer = Bytes::from(potential_murmurat_data.to_vec());
                        match MurmuratMessage::decode(&mut buffer) {
                            Ok(_) => {
                                let timestamp: u32 = SystemTime::now()
                                    .duration_since(SystemTime::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs()
                                    as u32;

                                payload.copy_from_slice(eth.payload_slice());
                                payload[18 + 4..18 + 8].copy_from_slice(&timestamp.to_le_bytes());
                                return Some(payload);
                            }
                            Err(e) => println!("Failed to decode: {:?}", e),
                        }
                    }
                }
            }
            _ => println!("Not an Ethernet2 frame"),
        }
    }
    return None;
}

fn hexdump(bytes: &[u8], max_len: usize) {
    let len = std::cmp::min(bytes.len(), max_len);
    for (i, chunk) in bytes[..len].chunks(16).enumerate() {
        print!("{:04x}:  ", i * 16);
        for b in chunk {
            print!("{:02x} ", b);
        }
        println!();
    }
}
