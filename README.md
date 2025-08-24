# 👻 GhostComm

**Military-Grade Serverless P2P Messaging Over Bluetooth Mesh Networks**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![React Native](https://img.shields.io/badge/React%20Native-0.72+-green.svg)](https://reactnative.dev/)
[![Security](https://img.shields.io/badge/Security-Military%20Grade-red.svg)](https://github.com/Szyyi/ghostcomm)

GhostComm is a revolutionary, completely decentralised messaging system that operates entirely offline through Bluetooth Low Energy (BLE) mesh networks. Built with military-grade cryptography including the **Double Ratchet Algorithm** (Signal Protocol), **Perfect Forward Secrecy**, and **Post-Compromise Security**, GhostComm ensures your communications remain absolutely private with zero infrastructure requirements.

##  Revolutionary Features

###  **Military-Grade Security Architecture**

#### **Double Ratchet Protocol Implementation**
- **Perfect Forward Secrecy**: Each message uses unique ephemeral keys - compromise of long-term keys doesn't compromise past messages
- **Post-Compromise Security**: Automatic security recovery after key compromise through continuous ratcheting
- **X3DH-like Key Agreement**: Asynchronous key exchange using pre-generated key bundles
- **256-bit Security Level**: Full 256-bit fingerprints and key sizes throughout

#### **Multi-Layer Encryption**
```
Message → XChaCha20-Poly1305 (24-byte nonce) → Double Ratchet Session → BLE Transport
```
- **XChaCha20-Poly1305**: Extended nonce variant preventing nonce reuse
- **Ed25519 Signatures**: Every message and advertisement cryptographically signed
- **HKDF-SHA256**: Proper key derivation with unique salts per context
- **BLAKE3/SHA-256**: Fast, secure hashing for fingerprints and checksums

#### **Zero-Knowledge Architecture**
- **No Identity Requirements**: No phone numbers, emails, or accounts
- **No Metadata Collection**: Messages contain only encrypted payload
- **No Servers**: Complete peer-to-peer operation
- **No Internet**: 100% offline functionality

###  **Advanced Mesh Networking**

#### **Intelligent Routing**
- **Trust-Based Routing**: Routes prioritized by node trust scores (0-100)
- **Multi-Path Redundancy**: Messages can take multiple routes for reliability
- **Automatic Route Discovery**: Dynamic routing table updates
- **Priority-Based Forwarding**: Critical messages get network priority

#### **Anti-Tracking & Privacy**
- **Ephemeral ID Rotation**: Identifiers rotate every 15 minutes
- **Address Randomization**: BLE MAC addresses continuously change
- **Minimal Metadata Exposure**: Only essential routing information
- **Plausible Deniability**: No persistent identifiers

###  **Comprehensive Security Features**

#### **Authentication & Verification**
- **Multi-Method Verification**:
  - QR Code exchange for in-person verification
  - Numeric code comparison (SAS - Short Authentication String)
  - Fingerprint verification for remote validation
  - Web of Trust through peer verification
- **Device Attestation**: Secure boot verification
- **Channel Binding**: Cryptographic binding of sessions to BLE connections

#### **Attack Prevention**
- **Replay Protection**: Sliding window with sequence number tracking
- **Rate Limiting**: Prevents DoS attacks at multiple layers
- **Message Authentication**: All messages signed with Ed25519
- **Tamper Detection**: AEAD ensures message integrity

##  Enhanced Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         APPLICATION LAYER                        │
│                    React Native + TypeScript                     │
├─────────────────────────────────────────────────────────────────┤
│                      SECURITY MANAGER LAYER                      │
│          Double Ratchet Sessions + Key Management                │
├─────────────────────────────────────────────────────────────────┤
│                     BLE MESH NETWORK LAYER                       │
│     Secure Discovery + Authenticated Routing + Trust Scoring     │
├─────────────────────────────────────────────────────────────────┤
│                    MESSAGE ENCRYPTION LAYER                      │
│        XChaCha20-Poly1305 + Perfect Forward Secrecy             │
├─────────────────────────────────────────────────────────────────┤
│                   CRYPTOGRAPHIC FOUNDATION                       │
│    Ed25519 (Signing) + X25519 (ECDH) + HKDF + BLAKE3/SHA256    │
├─────────────────────────────────────────────────────────────────┤
│                    TRANSPORT SECURITY LAYER                      │
│      Signed Advertisements + Encrypted Connections               │
├─────────────────────────────────────────────────────────────────┤
│                      BLUETOOTH LOW ENERGY                        │
│                 Hardware Abstraction Layer                       │
└─────────────────────────────────────────────────────────────────┘
```

## 📂 Project Structure

```
ghostcomm/
├── 📁 core/                           # Security-hardened core library
│   ├── 📁 src/
│   │   ├── 📁 crypto/                 # Military-grade cryptography
│   │   │   ├── 📄 keypair.ts          # Enhanced key management with Double Ratchet
│   │   │   └── 📄 encryption.ts       # XChaCha20-Poly1305 + Perfect Forward Secrecy
│   │   ├── 📁 ble/                    # Secure BLE mesh implementation
│   │   │   ├── 📄 types.ts            # Security-enhanced type definitions
│   │   │   ├── 📄 advertiser.ts       # Signed advertisements with anti-tracking
│   │   │   ├── 📄 scanner.ts          # Verification-enabled discovery
│   │   │   ├── 📄 connection.ts       # Double Ratchet session management
│   │   │   ├── 📄 mesh.ts             # Trust-based mesh routing
│   │   │   └── 📄 manager.ts          # Orchestration with security enforcement
│   │   └── 📁 types/                  # Enhanced cryptographic types
│   │       └── 📄 crypto.ts           # Complete security type system
└── 📁 mobile/                         # React Native application
    └── 📁 src/ble/                    # Platform-specific BLE implementations
```

## Getting Started

### Prerequisites

- **Node.js** v20.9.0 or higher
- **npm** 10.1.0 or higher
- **React Native CLI** (for mobile development)
- **Android Studio** or **Xcode** (for mobile testing)

### Installation

```bash
# Clone the repository
git clone https://github.com/Szyyi/ghostcomm.git
cd ghostcomm

# Install all dependencies
npm install

# Build the security-enhanced core library
cd core
npx tsc

# Prepare mobile application
cd ../mobile
npm install
```

## 🔒 Cryptographic Specifications v2.0

### Key Management System

#### **Key Hierarchy**
```
Master Seed (Optional)
    ├── Identity Key Pair (Ed25519)
    │   ├── Public Key (32 bytes) - Node identification
    │   └── Private Key (32 bytes) - Message signing
    ├── Encryption Key Pair (X25519)
    │   ├── Public Key (32 bytes) - Key exchange
    │   └── Private Key (32 bytes) - ECDH operations
    └── Pre-Key Bundle (100 keys)
        ├── Signed Pre-Key - Long-term with signature
        └── One-Time Pre-Keys - Single use for PFS
```

#### **Key Features**
- **256-bit Fingerprints**: SHA-256/BLAKE3 full fingerprints
- **Deterministic Generation**: Optional seed phrase support (PBKDF2, 250k iterations)
- **Pre-Key Bundles**: 100 pre-generated keys for async key exchange
- **Automatic Rotation**: Keys rotate based on time and usage
- **Secure Storage**: Platform secure enclave where available

### Message Encryption System

#### **Encryption Pipeline**
1. **Session Establishment** (X3DH-like)
   - DH1: Identity ↔ Identity
   - DH2: Identity ↔ Pre-key (if available)
   - DH3: Ephemeral ↔ Identity
   - Combine secrets with HKDF-SHA512

2. **Double Ratchet Operation**
   ```
   Root Key → Chain Key → Message Key
      ↓          ↓           ↓
   Ratchet    Advance    Encrypt
   ```

3. **Message Encryption**
   - Algorithm: **XChaCha20-Poly1305**
   - Nonce: 24 bytes (extended nonce)
   - Key Size: 32 bytes per message
   - Auth Tag: 16 bytes (Poly1305)

#### **Security Properties**
- **Confidentiality**: XChaCha20 stream cipher
- **Integrity**: Poly1305 authenticator
- **Authentication**: Ed25519 signatures
- **Forward Secrecy**: New keys per message
- **Backward Secrecy**: Old keys unrecoverable
- **Deniability**: No long-term signatures on messages

### Broadcast Encryption

#### **Rotating Epoch System**
- **Epoch Duration**: 24 hours
- **Key Rotation**: Hourly within epoch
- **Sender Authentication**: Ed25519 signature on broadcast
- **No Shared Secrets**: Each sender uses unique ephemeral keys

## 🌐 BLE Mesh Networking v2.0

### Security-Enhanced Configuration

```typescript
const BLE_CONFIG = {
    // Service UUIDs
    SERVICE_UUID: '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
    
    // Timing (with randomization)
    ADVERTISEMENT_INTERVAL: 1000,        // ±500ms randomization
    SCAN_INTERVAL: 2000,
    ADDRESS_ROTATION_INTERVAL: 900000,   // 15 minutes
    
    // Security
    SESSION_LIFETIME: 86400000,          // 24 hours
    KEY_ROTATION_INTERVAL: 3600000,      // 1 hour
    REPLAY_WINDOW_SIZE: 1000,            // messages
    
    // Mesh Parameters  
    MAX_HOP_COUNT: 10,
    MESSAGE_TTL: 300000,                 // 5 minutes
    MAX_MESSAGE_SIZE: 65536,             // 64KB
    FRAGMENT_SIZE: 512                   // Per BLE packet
};
```

### Advertisement Security

#### **Signed Advertisement Packet Structure**
```
[Version|Flags|EphemeralID|IdentityHash|SeqNum|Timestamp|Signature|MeshInfo]
   1B     1B      16B          8B         4B      4B       64B       4B
```
Total: 108 bytes (fits in BLE 5.0 extended advertising)

#### **Anti-Tracking Features**
- **Ephemeral IDs**: Rotate every 15 minutes
- **No Static Identifiers**: All IDs are temporary
- **Timing Randomization**: ±500ms on all intervals
- **Address Rotation**: MAC addresses change regularly

### Trust-Based Mesh Routing

#### **Trust Score Calculation** (0-100 points)
- **Verification Status**: 40 points
  - Verified: +20
  - Trusted: +20
- **Signal Stability**: 20 points
  - Low variance: +20
- **Presence Duration**: 20 points  
  - >1 hour: +20
- **Message Reliability**: 20 points
  - Success rate: 0-20

#### **Routing Decision Matrix**
```
Trust Score | Routing Priority | Relay Willingness
----------- | --------------- | -----------------
80-100      | Preferred       | Always
60-79       | Normal          | Usually  
40-59       | Backup          | Sometimes
0-39        | Avoided         | Emergency only
```

## 🧪 Comprehensive Test Suite

### Test Coverage

```
✅ 46 Core Tests - 100% Pass Rate
✅ Security Tests - All cryptographic operations validated
✅ Network Tests - Mesh routing and discovery verified
✅ Integration Tests - End-to-end message flow confirmed
```

### Security Validation Tests

#### **Cryptographic Tests**
- ✅ 256-bit key generation
- ✅ Double Ratchet sessions
- ✅ Perfect forward secrecy
- ✅ Signature verification
- ✅ Key rotation
- ✅ Replay protection

#### **Network Security Tests**
- ✅ Advertisement signatures
- ✅ Trust score calculation
- ✅ Secure routing
- ✅ Anti-tracking measures
- ✅ Rate limiting
- ✅ DoS prevention

##  Mobile Application Features

### Security UI Components

#### **Trust Indicators**
- 🟢 **Verified**: Identity confirmed through verification method
- 🔵 **Encrypted**: Active Double Ratchet session
- 🟡 **Pending**: Authentication in progress
- 🔴 **Untrusted**: Unverified node

#### **Verification Interface**
- **QR Code Scanner**: In-person verification
- **Numeric Display**: 6-digit verification codes
- **Fingerprint Viewer**: Full 256-bit fingerprints
- **Trust Graph**: Visual web of trust

### Privacy Controls

- **Identity Management**: Multiple identities support
- **Message Expiry**: Auto-delete after time
- **Burn After Reading**: Single-view messages
- **Phantom Mode**: Invisible to discovery
- **Panic Button**: Emergency data wipe

##  Advanced Configuration

### Security Parameters

```typescript
const SECURITY_CONFIG = {
    // Cryptography
    FINGERPRINT_BITS: 256,
    SESSION_KEY_BITS: 256,
    NONCE_SIZE: 24,              // XChaCha20
    
    // Double Ratchet
    MAX_SKIP_KEYS: 1000,
    MESSAGE_KEY_LIFETIME: 604800000, // 7 days
    
    // Trust Management
    INITIAL_TRUST_SCORE: 0,
    VERIFICATION_BONUS: 40,
    AUTO_TRUST_THRESHOLD: 80,
    
    // Rate Limiting
    MAX_MESSAGES_PER_SECOND: 10,
    MAX_CONNECTIONS: 8,
    CONNECTION_COOLDOWN: 60000   // 1 minute
};
```

##  Security Considerations

### Threat Model

GhostComm protects against:
- ✅ **Passive Surveillance**: All traffic encrypted
- ✅ **Active MITM Attacks**: Mutual authentication required
- ✅ **Traffic Analysis**: Minimal metadata, rotating IDs
- ✅ **Device Compromise**: Forward secrecy limits damage
- ✅ **Replay Attacks**: Sequence numbers and timestamps
- ✅ **DoS Attacks**: Multi-layer rate limiting

### Limitations

- **Range**: Limited by BLE (~30-100 meters)
- **Throughput**: Constrained by BLE bandwidth
- **Battery**: Continuous BLE operations drain battery
- **Scalability**: Mesh efficiency decreases with size

##  License

MIT License - See [LICENSE](LICENSE) file for details.

##  Acknowledgments

- **Signal Protocol**: Inspiration for Double Ratchet implementation
- **@noble Cryptography**: Excellent pure JavaScript crypto libraries
- **React Native BLE PLX**: BLE platform abstraction

##  Disclaimer

GhostComm is experimental software. While we implement military-grade cryptography, this software has not been formally audited. Use at your own risk for sensitive communications.

---

*"In a world of surveillance, GhostComm ensures your words remain your own."*
