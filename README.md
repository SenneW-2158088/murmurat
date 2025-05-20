# MURMURAT Protocol Analysis

## Overview

The MURMURAT protocol is a fictional military communication protocol designed for secure communication between the fictional nations of Rubea and the Autocratic Confederation of Cordovania (ACC). The protocol claims to be a "revolutionary cryptographic framework" with "unparalleled security" and "ultra-fast communication speeds."

## Technical Specifications

### Basic Parameters
- Operates on UDP port 1400
- Maximum datagram size: 1472 bytes
- Each datagram represents a single isolated message (no segmentation)
- Uses big-endian (network byte order) encoding for numerical fields

### Message Types
1. **DH Messages** (Type 0)
   - Used for Diffie-Hellman key exchange
   - Total size: 256 bytes
   - Contains the public DH value

2. **HELLO Messages** (Type 1)
   - Used for authentication of communicating parties
   - Total size: 516 bytes
   - Contains RSA public key and key identifier

3. **DATA Messages** (Type 2)
   - Used for encrypted communications
   - Variable size (2 + length bytes)
   - Contains encrypted payload and signature

### Cryptographic Components

#### Key Derivation
- Uses Diffie-Hellman key exchange algorithm
- Parameters:
  - Generator g = 2
  - A specific 2048-bit prime number (claimed to be "holy")
  - Each party generates a 2048-bit secret x
  - Public value: DHpub = g^x (mod p)
  - Session key (Ksession): First 16 bytes of the shared secret

#### Authentication
- Uses RSA for authentication (2048 or 4096-bit keys)
- Public exponent e is statically set to 65537
- RSA public keys are padded with zeros to 512 bytes
- Messages are signed using PKCS1v15 padding

#### Confidential Communications
- Encryption: AES-128 in Counter (CTR) mode
- 1-byte nonce for AES-CTR initialization
- 4-byte timestamp to prevent relay/delay attacks
  - Messages older than one minute are discarded
- DATA messages contain:
  - Length field (entire payload length)
  - Nonce value
  - Timestamp
  - Encrypted data
  - Public key identifier of transmitter
  - RSA signature over the data

### Special Features
- "Holiday Exception": Required transmission of the "Verse of Acknowledgement" on February 14th

## Communication Flow
1. **Key Exchange**:
   - A → DH → B
   - B → DH → A

2. **Authentication**:
   - A → HELLO → B
   - B → HELLO → A

3. **Messaging**:
   - A → DATA → B

## Observed Traffic
- Only two parties communicating:
  - Source: 77.102.50.25
  - Destination: 201.1.192.22


# Proof of concepts


```sh
# Run mitm client:
cargo run --bin murmurat-mitm --release -- --addr 127.0.0.1:4003 --server 127.0.0.1:4001
# Run server:
cargo run --bin murmurat-cli --release -- --server --target 127.0.0.1:4001
# Run client:
cargo run --bin murmurat-cli --release -- --host 127.0.0.1:4002 --target 127.0.0.1:4003
```
