// core/src/types/crypto.ts
/**
 * GhostComm Core Cryptographic Type Definitions
 * 
 * This file contains all cryptographic type definitions for the GhostComm mesh network protocol.
 * It defines interfaces for key management, message encryption, peer authentication, and 
 * secure communication within the decentralized mesh network.
 * 
 * Key Features:
 * - Double Ratchet encryption for forward secrecy
 * - Ed25519/X25519 elliptic curve cryptography
 * - ChaCha20-Poly1305 authenticated encryption
 * - Pre-key bundles for asynchronous messaging
 * - Multi-layered message routing and priority system
 * 
 * @version 2.1
 * @author LCpl Szymon Procak
 */

// ===== CRYPTOGRAPHIC PRIMITIVES =====

/**
 * Supported cryptographic algorithms used throughout the GhostComm protocol.
 * 
 * The selection prioritizes:
 * - Security: State-of-the-art algorithms with proven security properties
 * - Performance: Efficient algorithms suitable for mobile/IoT devices
 * - Forward Compatibility: Support for future post-quantum algorithms
 * - Interoperability: Standard algorithms with wide library support
 */
export enum CryptoAlgorithm {
    // === Digital Signature Algorithms ===
    /**
     * Ed25519: Edwards Curve Digital Signature Algorithm
     * - Used for identity keys and message authentication
     * - 32-byte public keys, 32-byte private keys, 64-byte signatures
     * - Provides non-repudiation and identity verification
     */
    ED25519 = 'Ed25519',

    // === Key Exchange Algorithms ===
    /**
     * X25519: Elliptic Curve Diffie-Hellman key exchange
     * - Primary algorithm for ephemeral key exchanges
     * - Provides perfect forward secrecy through ephemeral keys
     * - 32-byte public/private keys, compatible with Ed25519
     */
    X25519 = 'X25519',
    
    /**
     * ECDH-P256: NIST P-256 curve for key exchange
     * - Alternative key exchange for hardware acceleration
     * - Future support for post-quantum hybrid schemes
     */
    ECDH_P256 = 'ECDH-P256',  // Future: for post-quantum hybrid

    // === Symmetric Encryption Algorithms ===
    /**
     * ChaCha20-Poly1305: Stream cipher with authenticated encryption
     * - Primary encryption algorithm for messages
     * - 32-byte keys, 12-byte nonces, 16-byte authentication tags
     * - Excellent performance on mobile ARM processors
     */
    CHACHA20_POLY1305 = 'ChaCha20-Poly1305',
    
    /**
     * XChaCha20-Poly1305: Extended nonce variant of ChaCha20-Poly1305
     * - Used when larger nonces are needed (24 bytes vs 12 bytes)
     * - Reduces nonce collision risk in high-volume scenarios
     */
    XCHACHA20_POLY1305 = 'XChaCha20-Poly1305',  // Extended nonce version
    
    /**
     * AES-256-GCM: Advanced Encryption Standard with Galois/Counter Mode
     * - Alternative encryption for hardware with AES acceleration
     * - Fallback option for platforms without ChaCha20 support
     */
    AES_256_GCM = 'AES-256-GCM',  // Alternative for hardware acceleration

    // === Key Derivation Functions ===
    /**
     * HKDF-SHA256: HMAC-based Key Derivation Function
     * - Used for deriving encryption keys from shared secrets
     * - Expands short secrets into cryptographically strong keys
     * - Essential for Double Ratchet implementation
     */
    HKDF_SHA256 = 'HKDF-SHA256',
    
    /**
     * Argon2id: Memory-hard password-based key derivation
     * - Used for deriving keys from user passwords
     * - Resistant to GPU/ASIC attacks through memory requirements
     */
    ARGON2ID = 'Argon2id',  // For password-based key derivation

    // === Cryptographic Hash Functions ===
    /**
     * SHA-256: Secure Hash Algorithm 256-bit
     * - Used for message integrity and fingerprint generation
     * - Foundation for HMAC and HKDF operations
     */
    SHA256 = 'SHA-256',
    
    /**
     * SHA-512: Secure Hash Algorithm 512-bit
     * - Used for high-security hash requirements
     * - Provides larger security margin for long-term storage
     */
    SHA512 = 'SHA-512',
    
    /**
     * BLAKE3: Fast, secure, and parallelizable hash function
     * - Future alternative with better performance characteristics
     * - Tree-based structure allows for parallel computation
     */
    BLAKE3 = 'BLAKE3'  // Future: faster alternative
}

// ===== KEY MANAGEMENT =====

/**
 * Enhanced key pair with metadata and versioning.
 * 
 * Represents a cryptographic key pair with associated metadata for tracking
 * key lifecycle, algorithm identification, and security auditing.
 * 
 * Usage Pattern:
 * - Identity keys: Long-term Ed25519 keys for node identification
 * - Encryption keys: X25519 keys for Diffie-Hellman key exchange
 * - Ephemeral keys: Short-lived keys for forward secrecy
 */
export interface KeyPair {
    /** Raw public key bytes (typically 32 bytes for Ed25519/X25519) */
    publicKey: Uint8Array;
    
    /** Raw private key bytes (typically 32 bytes for Ed25519/X25519) */
    privateKey: Uint8Array;
    
    /** Algorithm used for this key pair */
    algorithm: CryptoAlgorithm;
    
    /** Unix timestamp (ms) when the key was generated */
    createdAt: number;
    
    /** Optional unique identifier for key tracking and rotation */
    keyId?: string;
}

/**
 * Extended key pair with multiple key types for comprehensive identity.
 * 
 * This represents a complete cryptographic identity in the GhostComm network,
 * containing all keys necessary for secure communication. Each node has one
 * ExtendedKeyPair that serves as their persistent identity.
 * 
 * Key Hierarchy:
 * 1. Identity Key: Ed25519 for signing and node authentication
 * 2. Encryption Key: X25519 for Diffie-Hellman key exchange
 * 3. Pre-keys: Ephemeral X25519 keys for asynchronous messaging
 */
export interface ExtendedKeyPair {
    /** Ed25519 key pair for digital signatures and identity verification */
    identity: KeyPair;
    
    /** X25519 key pair for elliptic curve Diffie-Hellman key exchange */
    encryption: KeyPair;
    
    /** Array of pre-generated ephemeral keys for asynchronous messaging */
    preKeys?: PreKey[];
    
    /** 64-character hex string uniquely identifying this key bundle */
    fingerprint: string;
    
    /** Key format version for future compatibility and migration */
    version: number;
}

/**
 * Pre-generated ephemeral keys for asynchronous key exchange.
 * 
 * Pre-keys enable secure messaging even when the recipient is offline.
 * They are signed by the identity key to prevent tampering and ensure
 * authenticity. Each pre-key should only be used once to maintain
 * forward secrecy.
 * 
 * Lifecycle:
 * 1. Generated in batches and signed by identity key
 * 2. Published as part of key bundle
 * 3. Consumed by senders for initial key exchange
 * 4. Marked as used and eventually rotated
 */
export interface PreKey {
    /** Unique numeric identifier within the key bundle */
    keyId: number;
    
    /** X25519 public key for key exchange (32 bytes) */
    publicKey: Uint8Array;
    
    /** X25519 private key (32 bytes) - stored securely */
    privateKey: Uint8Array;
    
    /** Ed25519 signature by the identity key proving authenticity */
    signature: Uint8Array;
    
    /** Unix timestamp (ms) when the pre-key was generated */
    createdAt: number;
    
    /** Unix timestamp (ms) when the pre-key was first used (optional) */
    usedAt?: number;
}

/**
 * Session keys for Double Ratchet implementation.
 * 
 * The Double Ratchet algorithm provides forward secrecy and break-in recovery
 * for messaging sessions. These keys manage the cryptographic state for a
 * conversation between two parties.
 * 
 * Double Ratchet Components:
 * 1. Root Key: Master key for deriving chain keys
 * 2. Chain Keys: Used to derive message keys for encryption/decryption
 * 3. Message Numbers: Prevent replay attacks and ensure ordering
 * 
 * Security Properties:
 * - Forward Secrecy: Old messages cannot be decrypted if current keys are compromised
 * - Break-in Recovery: New key exchanges restore security after compromise
 * - Out-of-order Delivery: Messages can arrive in any order
 */
export interface SessionKeys {
    /** 32-byte root key for deriving new chain keys via HKDF */
    rootKey: Uint8Array;
    
    /** 32-byte chain key for deriving individual message keys */
    chainKey: Uint8Array;
    
    /** Current key for encrypting outgoing messages (derived from chain key) */
    sendingKey?: Uint8Array;
    
    /** Current key for decrypting incoming messages (derived from chain key) */
    receivingKey?: Uint8Array;
    
    /** Sequence number for message ordering and replay protection */
    messageNumber: number;
    
    /** Number of messages sent in the previous ratchet chain */
    previousChainLength: number;
}

// ===== MESSAGE TYPES =====

/**
 * Enhanced message types with priority levels.
 * 
 * Defines the different categories of messages in the GhostComm network,
 * each with specific routing, security, and handling requirements.
 * 
 * Message Type Hierarchy:
 * 1. Core Messages: Direct user communication
 * 2. Protocol Messages: Network operation and maintenance
 * 3. Control Messages: Session management and acknowledgments
 * 4. Security Messages: Cryptographic operations and key management
 */
export enum MessageType {
    // === Core Communication Messages ===
    /**
     * Direct person-to-person private message
     * - End-to-end encrypted using Double Ratchet
     * - Highest privacy guarantees
     * - Routed through mesh network if not directly connected
     */
    DIRECT = 'direct',
    
    /**
     * Public broadcast message visible to all nearby nodes
     * - Signed but not encrypted (public by design)
     * - Used for announcements, public chat, emergency broadcasts
     * - Propagated through mesh with TTL limits
     */
    BROADCAST = 'broadcast',
    
    /**
     * Group chat message for predefined participant set
     * - Encrypted with shared group key
     * - Requires group membership verification
     * - Supports key rotation and member management
     */
    GROUP = 'group',

    // === Protocol Operation Messages ===
    /**
     * Forwarded message in mesh network routing
     * - Carries another message through intermediate nodes
     * - Maintains end-to-end encryption while allowing routing
     * - Includes hop count and TTL for loop prevention
     */
    RELAY = 'relay',
    
    /**
     * Node discovery and initial handshake message
     * - Announces node presence and capabilities
     * - Exchanges public keys and protocol versions
     * - Establishes trust relationships
     */
    DISCOVERY = 'discovery',
    
    /**
     * Diffie-Hellman key exchange message
     * - Establishes shared secrets for encryption
     * - Includes ephemeral public keys and signatures
     * - Enables Perfect Forward Secrecy
     */
    KEY_EXCHANGE = 'key_exchange',

    // === Session Control Messages ===
    /**
     * Message acknowledgment confirming receipt
     * - Provides delivery confirmation to sender
     * - Includes message hash for verification
     * - Used for reliability and retry logic
     */
    ACK = 'ack',
    
    /**
     * Delivery receipt with optional read confirmation
     * - Indicates message was successfully delivered and/or read
     * - Supports privacy settings (disable read receipts)
     * - Helps with message queue management
     */
    RECEIPT = 'receipt',
    
    /**
     * Typing indicator for real-time chat feedback
     * - Shows when someone is composing a message
     * - Low priority, high frequency message type
     * - Short TTL to avoid outdated indicators
     */
    TYPING = 'typing',

    // === Security and Key Management ===
    /**
     * Key rotation notification message
     * - Informs contacts of new public keys
     * - Includes signatures proving authenticity
     * - Triggers key bundle updates
     */
    KEY_UPDATE = 'key_update',
    
    /**
     * Key revocation and compromise notification
     * - Immediately invalidates compromised keys
     * - Triggers emergency key rotation
     * - High priority distribution throughout network
     */
    REVOCATION = 'revocation'
}

/**
 * Message priority levels for mesh routing decisions.
 * 
 * Priority affects:
 * - Queue ordering at relay nodes
 * - Bandwidth allocation under congestion
 * - TTL and retry behavior
 * - Battery usage on mobile devices
 * 
 * Lower numeric values indicate higher priority.
 */
export enum MessagePriority {
    /** 
     * Emergency/SOS messages requiring immediate delivery
     * - Safety-critical communications
     * - Maximum network resources allocated
     * - Bypass normal rate limiting
     */
    CRITICAL = 0,
    
    /** 
     * Key exchanges, acknowledgments, and security messages
     * - Protocol-critical for maintaining security
     * - Higher priority than user messages
     * - Fast retransmission on failure
     */
    HIGH = 1,
    
    /** 
     * Regular user messages and group communications
     * - Standard message delivery priority
     * - Normal retry and timeout behavior
     * - Balanced resource usage
     */
    NORMAL = 2,
    
    /** 
     * Discovery messages, typing indicators, presence updates
     * - Non-critical informational messages
     * - Lower bandwidth allocation
     * - May be dropped under heavy load
     */
    LOW = 3
}

// ===== ENHANCED MESSAGE STRUCTURES =====

/**
 * Enhanced message header with comprehensive security and routing features.
 * 
 * The message header contains all metadata necessary for secure routing,
 * delivery, and authentication in the mesh network. It travels with every
 * message and is partially encrypted to protect privacy while enabling routing.
 * 
 * Security Considerations:
 * - Signature prevents tampering and provides non-repudiation
 * - Source/destination IDs use fingerprints to prevent spoofing
 * - Sequence numbers prevent replay attacks
 * - TTL prevents infinite loops in mesh routing
 */
export interface MessageHeader {
    // === Version and Identification ===
    /** Protocol version for forward/backward compatibility */
    version: number;
    
    /** Globally unique 256-bit message identifier (hex string) */
    messageId: string;

    // === Routing Information ===
    /** Sender's node fingerprint (64-char hex string) */
    sourceId: string;
    
    /** Recipient's node fingerprint (optional for broadcasts) */
    destinationId?: string;
    
    /** Group identifier for group messages (SHA-256 of group info) */
    groupId?: string;

    // === Timing and Ordering ===
    /** Unix timestamp in milliseconds when message was created */
    timestamp: number;
    
    /** Monotonic sequence number from sender for ordering and replay protection */
    sequenceNumber: number;

    // === Mesh Network Routing ===
    /** Time-to-live in hops to prevent infinite routing loops */
    ttl: number;
    
    /** Current hop count, incremented at each relay */
    hopCount: number;
    
    /** Message priority affecting routing decisions and resource allocation */
    priority: MessagePriority;
    
    /** Array of node IDs that have relayed this message */
    relayPath: string[];

    // === Security and Authentication ===
    /** Ed25519 signature of message content by sender's identity key */
    signature: Uint8Array;
    
    /** SHA-256 hash of previous message for chain integrity (optional) */
    previousMessageHash?: string;
}

/**
 * Enhanced plaintext message structure with rich metadata and features.
 * 
 * This represents a fully-formed message before encryption, containing all
 * user content and metadata. It supports modern messaging features like
 * replies, attachments, reactions, and ephemeral messages.
 * 
 * Privacy Features:
 * - Ephemeral expiry for disappearing messages
 * - Burn after reading for maximum privacy
 * - Optional delivery confirmations
 */
export interface PlaintextMessage {
    /** Message header with routing and security metadata */
    header: MessageHeader;

    // === Core Message Content ===
    /** Type of message determining handling and routing */
    type: MessageType;
    
    /** Actual text content of the message (UTF-8 string) */
    payload: string;

    // === Rich Messaging Features ===
    /** Message ID this message is replying to (threading support) */
    replyTo?: string;
    
    /** Array of file attachment metadata */
    attachments?: AttachmentMetadata[];
    
    /** Array of mentioned user fingerprints (@mentions) */
    mentions?: string[];
    
    /** Array of emoji reactions with user attribution */
    reactions?: MessageReaction[];

    // === Privacy and Security Features ===
    /** Unix timestamp when message should self-destruct (optional) */
    ephemeralExpiry?: number;
    
    /** Whether message should be deleted after first read */
    burnAfterReading?: boolean;
}

/**
 * Enhanced encrypted message with Double Ratchet support and mesh routing.
 * 
 * This is the wire format for messages transmitted over the network. The header
 * contains unencrypted routing information while the payload is encrypted using
 * the Double Ratchet algorithm for forward secrecy.
 * 
 * Encryption Process:
 * 1. Serialize PlaintextMessage to bytes
 * 2. Generate ephemeral X25519 key pair
 * 3. Perform ECDH with recipient's public key
 * 4. Derive encryption key using HKDF
 * 5. Encrypt with XChaCha20-Poly1305
 * 6. Include ephemeral public key for decryption
 */
export interface EncryptedMessage {
    // === Routing Envelope (Unencrypted) ===
    /**
     * Unencrypted header information needed for mesh routing.
     * Contains no sensitive information, only routing metadata.
     */
    header: {
        /** Unique message identifier */
        messageId: string;
        
        /** Sender's node fingerprint */
        sourceId: string;
        
        /** Recipient's node fingerprint (optional for broadcasts) */
        destinationId?: string;
        
        /** Group identifier for group messages */
        groupId?: string;
        
        /** Message creation timestamp */
        timestamp: number;
        
        /** Remaining hops before message expires */
        ttl: number;
        
        /** Number of hops message has taken */
        hopCount: number;
        
        /** Routing priority level */
        priority: MessagePriority;
    };

    // === Double Ratchet Cryptographic Fields ===
    /** Hex-encoded X25519 ephemeral public key for this message */
    ephemeralPublicKey: string;
    
    /** Number of messages in the previous ratchet chain */
    previousChainLength: number;
    
    /** Message number within current ratchet chain */
    messageNumber: number;

    // === Encrypted Payload ===
    /** 24-byte nonce for XChaCha20-Poly1305 encryption (hex-encoded) */
    nonce: string;
    
    /** Encrypted PlaintextMessage and header (hex-encoded) */
    ciphertext: string;
    
    /** 16-byte Poly1305 authentication tag (hex-encoded) */
    authTag: string;

    // === Group Message Extensions ===
    /** Group key version/identifier for group messages */
    groupKeyId?: string;
    
    /** Sender's ephemeral key share for group key derivation */
    senderKeyShare?: string;
}

/**
 * Protocol v2.1: Encrypted message with mandatory sender key for enhanced security.
 * 
 * Version 2.1 of the protocol requires the sender's identity key to be included
 * with every message to prevent certain classes of attacks and enable better
 * key management. This is backward compatible with v2.0 clients.
 * 
 * Security Improvements:
 * - Prevents key substitution attacks
 * - Enables immediate sender verification
 * - Supports key rotation detection
 * - Facilitates trust establishment
 */
export interface EncryptedMessageWithSenderKey extends EncryptedMessage {
    /** Hex-encoded Ed25519 identity public key (REQUIRED in v2.1) */
    senderIdentityKey: string;
    
    /** Hex-encoded X25519 encryption public key (optional, for key exchange) */
    senderEncryptionKey?: string;
}

// ===== ADDITIONAL MESSAGING TYPES =====

/**
 * File attachment metadata for rich media messaging.
 * 
 * Supports secure file transfer through the mesh network with optional
 * per-file encryption and chunked delivery for large files.
 * 
 * Security Features:
 * - SHA-256 hash for integrity verification
 * - Optional per-file encryption keys
 * - Chunked transfer for reliability
 */
export interface AttachmentMetadata {
    /** Unique identifier for this attachment */
    id: string;
    
    /** Original filename as provided by sender */
    filename: string;
    
    /** MIME type for proper rendering (e.g., 'image/jpeg', 'text/plain') */
    mimeType: string;
    
    /** File size in bytes for progress tracking and validation */
    size: number;
    
    /** SHA-256 hash of file content for integrity verification */
    hash: string;
    
    /** Optional AES-256 key for additional file encryption (hex-encoded) */
    encryptionKey?: string;
    
    /** Number of chunks for large file transfer (optional) */
    chunks?: number;
}

/**
 * Message reactions (emoji responses) with user attribution.
 * 
 * Enables users to react to messages with emoji, providing lightweight
 * feedback without sending full reply messages.
 */
export interface MessageReaction {
    /** Unicode emoji character or custom emoji identifier */
    emoji: string;
    
    /** Fingerprint of user who added this reaction */
    userId: string;
    
    /** Unix timestamp when reaction was added */
    timestamp: number;
}

/**
 * Enhanced mesh network node information with comprehensive capabilities.
 * 
 * Represents a peer node in the GhostComm mesh network with all information
 * necessary for secure communication, routing decisions, and trust management.
 * 
 * This structure serves multiple purposes:
 * 1. Identity Management: Cryptographic identity and verification
 * 2. Network Routing: Connectivity and performance metrics
 * 3. Trust System: Reputation and verification status
 * 4. Resource Management: Battery, bandwidth, and capabilities
 * 
 * Privacy Considerations:
 * - Location data is coarse (geohash) to preserve privacy
 * - Device information is optional and user-controlled
 * - Trust metrics are local to each node
 */
export interface MeshNode {
    // === Cryptographic Identity ===
    /** Unique 64-character hex fingerprint derived from identity key */
    nodeId: string;
    
    /** 
     * Public key bundle for secure communication
     * Contains all keys necessary for establishing encrypted sessions
     */
    publicKeys: {
        /** Ed25519 public key for digital signatures and identity verification */
        identity: Uint8Array;
        
        /** X25519 public key for elliptic curve Diffie-Hellman key exchange */
        encryption: Uint8Array;
        
        /** Array of pre-generated ephemeral keys for asynchronous messaging */
        preKeys?: PreKey[];
    };

    // === Network Connectivity Status ===
    /** Unix timestamp of most recent communication with this node */
    lastSeen: number;
    
    /** Unix timestamp when this node was first discovered */
    firstSeen: number;
    
    /** Whether node is currently reachable via direct or mesh connection */
    isOnline: boolean;

    // === Node Capabilities and Protocol Support ===
    /** Protocol version supported by this node for compatibility checks */
    protocolVersion: number;
    
    /** Array of cryptographic algorithms supported by this node */
    supportedAlgorithms: CryptoAlgorithm[];
    
    /** Array of protocol features and services provided by this node */
    capabilities: NodeCapability[];

    // === Physical Network Metrics ===
    /** Received Signal Strength Indicator in dBm (Bluetooth/WiFi) */
    signalStrength?: number;
    
    /** Battery level percentage (0-100) if shared by node */
    batteryLevel?: number;
    
    /** 
     * Message transmission statistics for performance monitoring
     * Used for routing decisions and network optimization
     */
    messageStats?: {
        /** Total messages sent by this node */
        sent: number;
        
        /** Total messages received from this node */
        received: number;
        
        /** Total messages relayed through this node */
        relayed: number;
        
        /** Total messages dropped due to errors or capacity */
        dropped: number;
    };

    // === Trust and Security Metrics ===
    /** 
     * Local trust score (0-100) based on behavior and verification
     * Higher scores indicate more trustworthy nodes
     */
    trustScore?: number;
    
    /** Current verification status of this node's identity */
    verificationStatus?: VerificationStatus;
    
    /** Array of node fingerprints that have verified this node's identity */
    verifiedBy?: string[];

    // === Optional Metadata (Privacy-Preserving) ===
    /** Human-readable device name (optional, user-controlled) */
    deviceName?: string;
    
    /** General device category for capability inference */
    deviceType?: DeviceType;
    
    /** Coarse location hash for proximity-based features (privacy-preserving) */
    location?: GeoHash;
}

/**
 * Node capabilities indicating supported features and services.
 * 
 * These capabilities determine what services a node can provide to the
 * mesh network and influence routing decisions and peer selection.
 */
export enum NodeCapability {
    /** Ability to relay messages for other nodes in the mesh network */
    RELAY = 'relay',
    
    /** Provides persistent storage for offline message delivery */
    STORAGE = 'storage',
    
    /** Acts as bridge between mesh network and internet/other networks */
    BRIDGE = 'bridge',
    
    /** Supports group chat functionality and group key management */
    GROUP_CHAT = 'group_chat',
    
    /** Supports file transfer and attachment handling */
    FILE_TRANSFER = 'file_transfer',
    
    /** Supports voice note recording and playback */
    VOICE_NOTES = 'voice_notes'
}

/**
 * Device types for capability inference and user interface adaptation.
 * 
 * Helps other nodes understand the capabilities and limitations of this device,
 * allowing for optimized communication patterns and feature availability.
 */
export enum DeviceType {
    /** Mobile phone with typical battery and performance constraints */
    PHONE = 'phone',
    
    /** Tablet device with larger screen and better battery life */
    TABLET = 'tablet',
    
    /** Laptop computer with AC power and high performance */
    LAPTOP = 'laptop',
    
    /** Internet of Things device with limited resources */
    IOT = 'iot',
    
    /** Dedicated relay device optimized for mesh networking */
    DEDICATED_RELAY = 'relay'
}

/**
 * Verification status levels for node identity trust.
 * 
 * Represents the level of trust and verification for a node's claimed identity.
 * Higher verification levels enable access to more sensitive features.
 */
export enum VerificationStatus {
    /** Identity has not been verified through any mechanism */
    UNVERIFIED = 'unverified',
    
    /** Identity verified through cryptographic proof or trusted introducer */
    VERIFIED = 'verified',
    
    /** High trust level through multiple verification methods */
    TRUSTED = 'trusted',
    
    /** Node has been identified as malicious and should be ignored */
    BLOCKED = 'blocked'
}

/**
 * Connection state machine for peer connections.
 * 
 * Tracks the current state of connection establishment and authentication
 * with another node in the mesh network.
 */
export enum ConnectionState {
    /** No connection established */
    DISCONNECTED = 'disconnected',
    
    /** Attempting to establish initial connection */
    CONNECTING = 'connecting',
    
    /** Physical connection established, starting authentication */
    CONNECTED = 'connected',
    
    /** Performing cryptographic authentication and key exchange */
    AUTHENTICATING = 'authenticating',
    
    /** Fully authenticated and ready for secure communication */
    AUTHENTICATED = 'authenticated',
    
    /** Gracefully closing connection */
    DISCONNECTING = 'disconnecting',
    
    /** Connection failed or authentication unsuccessful */
    FAILED = 'failed'
}

/**
 * Privacy-preserving coarse location representation using geohashing.
 * 
 * Enables proximity-based features while preserving user privacy by using
 * coarse location granularity. Higher precision values provide more accuracy
 * but less privacy.
 */
export interface GeoHash {
    /** 4-6 character geohash string representing approximate location */
    hash: string;
    
    /** Precision level (4-6) determining granularity vs privacy trade-off */
    precision: number;
}

// ===== ROUTING & MESH NETWORK =====

/**
 * Enhanced routing information for mesh network path optimization.
 * 
 * Maintains routing state for efficient message delivery through the mesh network.
 * Includes performance metrics, reliability statistics, and backup routes for
 * resilient communication even when primary paths fail.
 * 
 * Routing Algorithm Considerations:
 * - Shortest path vs most reliable path trade-offs
 * - Battery-aware routing for mobile devices
 * - Congestion avoidance and load balancing
 * - Geographic and signal strength factors
 */
export interface RouteInfo {
    /** Target node fingerprint for this route */
    destinationId: string;
    
    /** Next hop node fingerprint in the route to destination */
    nextHop: string;
    
    /** Number of hops required to reach destination */
    hopCount: number;
    
    /** Success rate (0.0-1.0) based on recent delivery attempts */
    reliability: number;
    
    /** Average round-trip latency in milliseconds (optional) */
    latency?: number;
    
    /** Estimated bandwidth capacity in bytes per second (optional) */
    bandwidth?: number;
    
    /** Unix timestamp when route information was last updated */
    lastUpdated: number;
    
    /** Alternative backup routes for failover scenarios */
    alternativeRoutes?: RouteInfo[];
}

/**
 * Message queue entry for store-and-forward delivery.
 * 
 * Enables offline messaging by storing messages until recipients come online.
 * Includes retry logic, expiration, and priority handling for reliable delivery
 * even in intermittently connected mesh networks.
 * 
 * Queue Management Strategy:
 * - Priority-based ordering with CRITICAL messages first
 * - Exponential backoff for retry attempts
 * - Automatic expiration to prevent queue bloat
 * - Size limits to prevent memory exhaustion
 */
export interface QueuedMessage {
    /** The encrypted message waiting for delivery */
    message: EncryptedMessage | EncryptedMessageWithSenderKey;
    
    /** Target recipient node fingerprint */
    destinationId: string;
    
    /** Number of delivery attempts made so far */
    attempts: number;
    
    /** Unix timestamp for next retry attempt */
    nextRetry: number;
    
    /** Maximum retry attempts before giving up */
    maxRetries: number;
    
    /** Message priority affecting queue position */
    priority: MessagePriority;
    
    /** Unix timestamp when message was first queued */
    createdAt: number;
    
    /** Unix timestamp when message expires and should be discarded */
    expiresAt: number;
}

// ===== SECURITY INTERFACES =====

/**
 * Enhanced cryptographic key pair interface with comprehensive security operations.
 * 
 * This interface defines all cryptographic operations required for secure
 * communication in the GhostComm mesh network. It provides a unified API
 * for key management, digital signatures, key exchange, and session management.
 * 
 * Security Features:
 * - Double Ratchet algorithm for forward secrecy
 * - Pre-key generation for asynchronous messaging
 * - Key rotation and lifecycle management
 * - Secure key export with optional password protection
 * 
 * Implementation Notes:
 * - All operations should use constant-time algorithms
 * - Private keys should be stored in secure hardware when available
 * - Memory containing private keys should be zeroed after use
 */
export interface IGhostKeyPair {
    // === Key Export and Persistence ===
    /**
     * Export all keys in a secure, portable format.
     * @param password Optional password for encrypting the exported keys
     * @returns Encrypted or plaintext key bundle depending on password presence
     */
    export(password?: string): ExportedKeys;
    
    // === Identity and Fingerprinting ===
    /**
     * Generate a unique 64-character hex fingerprint for this key pair.
     * The fingerprint is derived from the identity public key and serves
     * as the primary node identifier in the network.
     * @returns 256-bit fingerprint as hex string
     */
    getFingerprint(): string;
    
    /**
     * Generate a shortened version of the fingerprint for display purposes.
     * Typically the first 8-16 characters for user interfaces.
     * @returns Truncated fingerprint for human-readable display
     */
    getShortFingerprint(): string;
    
    /**
     * Get the Ed25519 identity public key for signature verification.
     * @returns 32-byte Ed25519 public key
     */
    getIdentityPublicKey(): Uint8Array;
    
    /**
     * Get the X25519 encryption public key for key exchange.
     * @returns 32-byte X25519 public key
     */
    getEncryptionPublicKey(): Uint8Array;
    
    /**
     * Get the X25519 encryption private key for key exchange.
     * WARNING: Handle with extreme care, never log or transmit.
     * @returns 32-byte X25519 private key
     */
    getEncryptionPrivateKey(): Uint8Array;

    // === Digital Signature Operations ===
    /**
     * Sign a message with the Ed25519 identity key.
     * Provides non-repudiation and authenticity guarantees.
     * @param message Message bytes or UTF-8 string to sign
     * @returns 64-byte Ed25519 signature
     */
    signMessage(message: Uint8Array | string): Uint8Array;
    
    /**
     * Verify an Ed25519 signature against a message and public key.
     * @param message Original message that was signed
     * @param signature 64-byte signature to verify
     * @param publicKey 32-byte Ed25519 public key of signer
     * @returns true if signature is valid, false otherwise
     */
    verifySignature(message: Uint8Array | string, signature: Uint8Array, publicKey: Uint8Array): boolean;
    
    /**
     * Perform X25519 Elliptic Curve Diffie-Hellman key exchange.
     * Generates a shared secret from our private key and their public key.
     * @param theirPublicKey 32-byte X25519 public key from other party
     * @param salt Optional salt for key derivation (recommended)
     * @returns 32-byte shared secret (should be used with HKDF)
     */
    performKeyExchange(theirPublicKey: Uint8Array, salt?: Uint8Array): Uint8Array;

    // === Double Ratchet Session Management ===
    /**
     * Initialize a new Double Ratchet session with another party.
     * Creates the initial root key and chain keys for secure messaging.
     * @param theirPublicKey Other party's X25519 public key
     * @returns Initial session state with root and chain keys
     */
    initializeSession(theirPublicKey: Uint8Array): SessionKeys;
    
    /**
     * Advance the Double Ratchet by one step.
     * Updates session keys to provide forward secrecy and break-in recovery.
     * @param session Current session state
     * @param theirEphemeralKey Optional new ephemeral key from other party
     * @returns Updated session state with new keys
     */
    ratchetSession(session: SessionKeys, theirEphemeralKey?: Uint8Array): SessionKeys;

    // === Key Rotation and Management ===
    /**
     * Generate a new X25519 encryption key pair while keeping identity key.
     * Used for periodic key rotation to limit key exposure time.
     * @returns New encryption key pair
     */
    rotateEncryptionKey(): KeyPair;
    
    /**
     * Generate a batch of pre-keys for asynchronous messaging.
     * Pre-keys enable secure communication when recipient is offline.
     * @param count Number of pre-keys to generate (typically 10-100)
     * @returns Array of signed pre-keys ready for publication
     */
    generatePreKeys(count: number): PreKey[];

    // === Import/Export Operations ===
    /**
     * Export all key material in a structured format.
     * Includes both public and private keys with metadata.
     * @returns Complete key bundle for backup or transfer
     */
    exportKeys(): ExportedKeys;
    
    /**
     * Export only public keys for sharing with other parties.
     * Safe to transmit over insecure channels.
     * @returns Public key bundle with fingerprint and signatures
     */
    exportPublicKeys(): ExportedPublicKeys;

    // === Metadata Access ===
    /**
     * Get the Unix timestamp when this key pair was created.
     * @returns Creation timestamp in milliseconds
     */
    getCreatedAt(): number;
    
    /**
     * Get the key format version for compatibility checking.
     * @returns Version number for forward/backward compatibility
     */
    getVersion(): number;
}

/**
 * Exported key format for secure key backup and transfer.
 * 
 * Provides a standardized format for exporting cryptographic keys with
 * optional password-based encryption. Includes all necessary metadata
 * for proper key reconstruction and compatibility checking.
 * 
 * Security Considerations:
 * - Private keys should be encrypted when password is provided
 * - Include version information for future migration support
 * - Validate integrity during import operations
 */
export interface ExportedKeys {
    /** Key format version for compatibility and migration */
    version: number;
    
    /** Hex-encoded Ed25519 private key (32 bytes) */
    identityPrivate: string;
    
    /** Hex-encoded Ed25519 public key (32 bytes) */
    identityPublic: string;
    
    /** Hex-encoded X25519 private key (32 bytes) */
    encryptionPrivate: string;
    
    /** Hex-encoded X25519 public key (32 bytes) */
    encryptionPublic: string;
    
    /** Legacy field for backward compatibility with older versions */
    publicKey?: string;
    
    /** 
     * Optional array of pre-keys with their key material
     * Each pre-key includes ID, public/private keys as hex strings
     */
    preKeys?: Array<{
        keyId: number;
        private: string;
        public: string;
    }>;
    
    /** Unix timestamp when keys were created */
    createdAt: number;
}

/**
 * Exported public keys for sharing with other parties.
 * 
 * Contains only public key information that is safe to share over
 * insecure channels. Used for initial key exchange and identity
 * establishment between mesh network nodes.
 */
export interface ExportedPublicKeys {
    /** Key format version for compatibility checking */
    version: number;
    
    /** Hex-encoded Ed25519 public identity key */
    identityPublic: string;
    
    /** Hex-encoded X25519 public encryption key */
    encryptionPublic: string;
    
    /** 64-character hex fingerprint derived from identity key */
    fingerprint: string;
    
    /** 
     * Optional array of available pre-keys for asynchronous messaging
     * Includes public keys and their signatures for verification
     */
    preKeys?: Array<{
        keyId: number;
        public: string;
        signature: string;
    }>;
}

/**
 * Enhanced message encryption interface providing comprehensive cryptographic operations.
 * 
 * This interface abstracts all message encryption, decryption, and session management
 * operations for the GhostComm mesh network. It supports multiple message types,
 * group communications, and maintains forward secrecy through Double Ratchet.
 * 
 * Key Features:
 * - End-to-end encryption for all message types
 * - Perfect forward secrecy through ephemeral keys
 * - Group messaging with shared key management
 * - Broadcast messages with signature verification
 * - Session-based encryption for performance
 * 
 * Security Guarantees:
 * - Confidentiality: Only intended recipients can read messages
 * - Authenticity: Recipients can verify sender identity
 * - Integrity: Message tampering is detectable
 * - Forward Secrecy: Past messages remain secure if keys are compromised
 * - Break-in Recovery: Security is restored after key compromise
 */
export interface IMessageEncryption {
    // === Direct Messaging (End-to-End Encryption) ===
    /**
     * Encrypt a message for a specific recipient using Double Ratchet.
     * Creates a new ephemeral key pair and advances the ratchet state.
     * @param message Plaintext message with headers and content
     * @param senderKeyPair Sender's cryptographic identity
     * @param recipientPublicKey Recipient's X25519 public key
     * @returns Encrypted message ready for transmission
     */
    encryptMessage(message: PlaintextMessage, senderKeyPair: IGhostKeyPair, recipientPublicKey: Uint8Array): Promise<EncryptedMessage | EncryptedMessageWithSenderKey>;
    
    /**
     * Decrypt a message received from another party.
     * Automatically handles ratchet advancement and key derivation.
     * @param encryptedMessage Encrypted message from network
     * @param recipientKeyPair Recipient's cryptographic identity
     * @returns Decrypted plaintext message with verification
     */
    decryptMessage(encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey, recipientKeyPair: IGhostKeyPair): Promise<PlaintextMessage>;

    // === Group Messaging (Shared Key Encryption) ===
    /**
     * Encrypt a message for a group using shared group key.
     * All group members must have the same group key for decryption.
     * @param message Plaintext group message
     * @param senderKeyPair Sender's identity for authentication
     * @param groupKey 32-byte shared symmetric key for the group
     * @returns Encrypted group message
     */
    encryptGroupMessage(message: PlaintextMessage, senderKeyPair: IGhostKeyPair, groupKey: Uint8Array): Promise<EncryptedMessage | EncryptedMessageWithSenderKey>;
    
    /**
     * Decrypt a group message using shared group key.
     * Verifies sender's signature and message integrity.
     * @param encryptedMessage Encrypted group message
     * @param groupKey 32-byte shared symmetric key for the group
     * @returns Decrypted group message with sender verification
     */
    decryptGroupMessage(encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey, groupKey: Uint8Array): Promise<PlaintextMessage>;

    // === Broadcast Messages (Public with Authentication) ===
    /**
     * Create a broadcast message signed but not encrypted.
     * Visible to all network participants but authenticated to sender.
     * @param message Plaintext broadcast message
     * @param senderKeyPair Sender's identity for signature
     * @returns Signed broadcast message (not encrypted)
     */
    createBroadcastMessage(message: PlaintextMessage, senderKeyPair: IGhostKeyPair): Promise<EncryptedMessage | EncryptedMessageWithSenderKey>;
    
    /**
     * Verify and decrypt a broadcast message.
     * Validates sender's signature for authenticity.
     * @param encryptedMessage Signed broadcast message
     * @param senderPublicKey Expected sender's Ed25519 public key
     * @returns Verified plaintext message
     */
    decryptBroadcastMessage(encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey, senderPublicKey: Uint8Array): Promise<PlaintextMessage>;

    // === Session-Based Encryption (Performance Optimization) ===
    /**
     * Establish a new Double Ratchet session for ongoing communication.
     * Creates shared secret and initializes ratchet state for efficiency.
     * @param senderKeyPair Sender's cryptographic identity
     * @param recipientPublicKey Recipient's long-term X25519 public key
     * @param recipientPreKey Optional pre-key for asynchronous messaging
     * @returns Initialized session keys for subsequent messages
     */
    establishSession(senderKeyPair: IGhostKeyPair, recipientPublicKey: Uint8Array, recipientPreKey?: PreKey): Promise<SessionKeys>;
    
    /**
     * Encrypt a message using an existing session.
     * More efficient than full key exchange for subsequent messages.
     * @param message Plaintext message to encrypt
     * @param session Current session state with keys
     * @returns Encrypted message using session keys
     */
    encryptWithSession(message: PlaintextMessage, session: SessionKeys): Promise<EncryptedMessage | EncryptedMessageWithSenderKey>;
    
    /**
     * Decrypt a message using an existing session.
     * Automatically advances session state for forward secrecy.
     * @param encryptedMessage Encrypted message using session
     * @param session Current session state with keys
     * @returns Decrypted message and updated session state
     */
    decryptWithSession(encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey, session: SessionKeys): Promise<PlaintextMessage>;

    // === Utility Functions ===
    /**
     * Generate a cryptographically secure unique message identifier.
     * Uses 256 bits of entropy for global uniqueness.
     * @returns 64-character hex string message ID
     */
    generateMessageId(): string;
    
    /**
     * Validate message structure and required fields.
     * Checks for required headers, valid timestamps, and proper format.
     * @param message Plaintext message to validate
     * @returns true if message structure is valid
     */
    validateMessage(message: PlaintextMessage): boolean;
    
    /**
     * Calculate SHA-256 hash of message for integrity checking.
     * Used for deduplication and chain integrity verification.
     * @param message Plaintext message to hash
     * @returns 64-character hex hash string
     */
    calculateMessageHash(message: PlaintextMessage): string;
}

// ===== STORAGE INTERFACES =====

/**
 * Enhanced message storage interface with indexing and advanced query capabilities.
 * 
 * Provides persistent storage for encrypted messages with efficient querying,
 * batch operations, and automatic maintenance. Supports both online and offline
 * message handling with store-and-forward capabilities.
 * 
 * Storage Strategy:
 * - Encrypted messages stored as-is for offline delivery
 * - Indexed by multiple fields for fast retrieval
 * - Automatic expiration and cleanup
 * - Compression and optimization for mobile devices
 * 
 * Performance Considerations:
 * - Use database indexes on frequently queried fields
 * - Implement write batching for high-volume scenarios
 * - Regular compaction to maintain performance
 * - Memory-mapped files for large message stores
 */
export interface IMessageStore {
    // === Basic Storage Operations ===
    /**
     * Store a single encrypted message persistently.
     * Message is indexed by ID, sender, recipient, and timestamp.
     * @param message Encrypted message to store
     */
    storeMessage(message: EncryptedMessage | EncryptedMessageWithSenderKey): Promise<void>;
    
    /**
     * Retrieve a specific message by its unique identifier.
     * @param messageId Unique message identifier
     * @returns Message if found, null otherwise
     */
    getMessage(messageId: string): Promise<(EncryptedMessage | EncryptedMessageWithSenderKey) | null>;
    
    /**
     * Retrieve all messages associated with a specific node.
     * Includes both sent and received messages for conversation view.
     * @param nodeId Node fingerprint to search for
     * @returns Array of messages involving the specified node
     */
    getMessagesForNode(nodeId: string): Promise<(EncryptedMessage | EncryptedMessageWithSenderKey)[]>;
    
    /**
     * Remove a specific message from storage.
     * Used for message deletion and cleanup operations.
     * @param messageId Unique message identifier to remove
     */
    removeMessage(messageId: string): Promise<void>;

    // === Batch Operations (Performance Optimization) ===
    /**
     * Store multiple messages in a single atomic operation.
     * More efficient than individual stores for bulk operations.
     * @param messages Array of encrypted messages to store
     */
    storeMessages(messages: (EncryptedMessage | EncryptedMessageWithSenderKey)[]): Promise<void>;
    
    /**
     * Remove multiple messages in a single atomic operation.
     * Used for bulk cleanup and conversation deletion.
     * @param messageIds Array of message identifiers to remove
     */
    removeMessages(messageIds: string[]): Promise<void>;

    // === Advanced Query Operations ===
    /**
     * Query messages using flexible filter criteria.
     * Supports pagination, time ranges, priority filtering, and more.
     * @param filter Query parameters defining search criteria
     * @returns Array of messages matching the filter
     */
    queryMessages(filter: MessageFilter): Promise<(EncryptedMessage | EncryptedMessageWithSenderKey)[]>;
    
    /**
     * Retrieve messages within a specific time range.
     * Useful for conversation history and time-based analysis.
     * @param start Start timestamp (Unix milliseconds)
     * @param end End timestamp (Unix milliseconds)
     * @returns Messages created within the time range
     */
    getMessagesByTimeRange(start: number, end: number): Promise<(EncryptedMessage | EncryptedMessageWithSenderKey)[]>;
    
    /**
     * Retrieve messages by priority level.
     * Used for priority-based processing and emergency message handling.
     * @param priority Message priority level to filter by
     * @returns Messages with the specified priority
     */
    getMessagesByPriority(priority: MessagePriority): Promise<(EncryptedMessage | EncryptedMessageWithSenderKey)[]>;

    // === Storage Maintenance ===
    /**
     * Remove expired messages based on TTL and retention policies.
     * Should be called periodically to prevent storage bloat.
     * @returns Number of messages removed
     */
    pruneExpiredMessages(): Promise<number>;
    
    /**
     * Optimize storage by defragmenting and reclaiming space.
     * Improves performance by reorganizing data for better access patterns.
     */
    compactStorage(): Promise<void>;

    // === Storage Analytics ===
    /**
     * Get comprehensive storage statistics and health metrics.
     * Used for monitoring storage usage and performance.
     * @returns Detailed storage statistics
     */
    getStorageStats(): Promise<StorageStats>;
    
    /**
     * Get message-specific statistics and counters.
     * Provides insights into messaging patterns and network activity.
     * @returns Message processing statistics
     */
    getMessageStats(): Promise<MessageStats>;
}

/**
 * Flexible message query filter for advanced searches.
 * 
 * Enables complex queries across multiple dimensions of message metadata.
 * All filter criteria are combined with AND logic for precise results.
 */
export interface MessageFilter {
    /** Filter by specific node (sender or recipient) */
    nodeId?: string;
    
    /** Filter by message type (direct, broadcast, group, etc.) */
    messageType?: MessageType;
    
    /** Filter by message priority level */
    priority?: MessagePriority;
    
    /** Filter by messages created after this timestamp */
    startTime?: number;
    
    /** Filter by messages created before this timestamp */
    endTime?: number;
    
    /** Maximum number of results to return (pagination) */
    limit?: number;
    
    /** Number of results to skip (pagination) */
    offset?: number;
}

/**
 * Comprehensive storage statistics for monitoring and optimization.
 * 
 * Provides detailed metrics about storage usage, message distribution,
 * and system health for capacity planning and performance tuning.
 */
export interface StorageStats {
    /** Total number of messages stored */
    totalMessages: number;
    
    /** Total storage space used in bytes */
    totalSize: number;
    
    /** Unix timestamp of oldest message in storage */
    oldestMessage: number;
    
    /** Unix timestamp of newest message in storage */
    newestMessage: number;
    
    /** Message count breakdown by type */
    byType: Record<MessageType, number>;
    
    /** Message count breakdown by priority */
    byPriority: Record<MessagePriority, number>;
}

/**
 * Message processing statistics for network analysis.
 * 
 * Tracks message flow and processing efficiency for network
 * performance monitoring and troubleshooting.
 */
export interface MessageStats {
    /** Total messages sent by this node */
    sent: number;
    
    /** Total messages received by this node */
    received: number;
    
    /** Total messages relayed through this node */
    relayed: number;
    
    /** Total messages dropped due to errors or capacity limits */
    dropped: number;
    
    /** Total messages expired before delivery */
    expired: number;
    
    /** Total messages successfully delivered to recipients */
    delivered: number;
    
    /** Total messages currently pending delivery */
    pending: number;
}

// ===== NETWORK STATISTICS =====

/**
 * Comprehensive network statistics for mesh network monitoring and optimization.
 * 
 * Provides detailed metrics about network health, performance, and connectivity
 * to help optimize routing, detect issues, and monitor overall system behavior.
 * These statistics are crucial for maintaining mesh network performance.
 * 
 * Use Cases:
 * - Network health monitoring and alerting
 * - Routing algorithm optimization
 * - Performance troubleshooting
 * - Capacity planning and scaling decisions
 * - User interface status displays
 */
export interface NetworkStats {
    /** Total number of active network connections (FIXED: now properly typed as number) */
    totalConnections: number;
    
    // === Node Population Metrics ===
    /** Total number of known nodes in the mesh network */
    totalNodes: number;
    
    /** Number of nodes currently online and reachable */
    activeNodes: number;
    
    /** Number of nodes marked as trusted through verification */
    trustedNodes: number;
    
    /** Number of nodes that have been blocked for malicious behavior */
    blockedNodes: number;

    // === Message Traffic Metrics ===
    /** Total messages sent by this node since startup */
    messagesSent: number;
    
    /** Total messages received by this node since startup */
    messagesReceived: number;
    
    /** Total messages relayed through this node for other parties */
    messagesRelayed: number;
    
    /** Total messages dropped due to errors, capacity, or TTL expiration */
    messagesDropped: number;

    // === Network Performance Metrics ===
    /** Average number of hops required to reach destinations */
    averageHopCount: number;
    
    /** Average round-trip latency in milliseconds for message delivery */
    averageLatency: number;
    
    /** Percentage of messages successfully delivered (0.0-1.0) */
    deliverySuccessRate: number;

    // === Network Topology Health ===
    /** Network density: average number of neighbors per node */
    networkDensity: number;
    
    /** Percentage of nodes reachable from this node (0.0-1.0) */
    networkReachability: number;

    // === Bandwidth and Data Transfer ===
    /** Total bytes transmitted by this node since startup */
    bytesTransmitted: number;
    
    /** Total bytes received by this node since startup */
    bytesReceived: number;
    
    /** Current average throughput in bytes per second */
    averageThroughput: number;

    // === System Health Metrics ===
    /** Total uptime of this node in milliseconds */
    uptime: number;
    
    /** Unix timestamp when these statistics were last updated */
    lastUpdated: number;
}

// ===== BLUETOOTH LOW ENERGY (BLE) SPECIFIC TYPES =====

/**
 * Enhanced BLE advertisement structure for mesh node discovery.
 * 
 * Bluetooth Low Energy advertisements are used for mesh node discovery
 * and capability announcement. The advertisement contains essential
 * information for establishing secure connections and determining
 * node capabilities before full connection establishment.
 * 
 * Advertisement Strategy:
 * - Broadcast essential information in limited space (31 bytes max)
 * - Include security proofs to prevent spoofing
 * - Rotate advertisements to prevent tracking
 * - Balance information density with battery efficiency
 * 
 * Security Considerations:
 * - Signature prevents advertisement spoofing
 * - Sequence numbers prevent replay attacks
 * - Public keys enable immediate encryption setup
 * - Capabilities help identify trustworthy nodes
 */
export interface BLEAdvertisement {
    // === Node Identity ===
    /** Unique node fingerprint (truncated for space efficiency) */
    nodeId: string;
    
    /** Hex-encoded X25519 public key for immediate key exchange */
    publicKey: string;

    // === BLE Service Information ===
    /** Primary service UUID for GhostComm protocol */
    serviceUUID: string;
    
    /** Array of characteristic UUIDs offered by this node */
    characteristicUUIDs: string[];

    // === Protocol and Capabilities ===
    /** Protocol version for compatibility checking */
    protocolVersion: number;
    
    /** Array of capabilities supported by this node */
    capabilities: NodeCapability[];
    
    /** Battery level percentage (0-100) if available and shared */
    batteryLevel?: number;

    // === Message Queue Status ===
    /** Number of pending messages in outbound queue */
    messageCount: number;
    
    /** Total size of message queue in bytes */
    queueSize: number;
    
    /** Number of high-priority messages awaiting delivery */
    highPriorityCount: number;

    // === Mesh Network Information ===
    /** Number of known neighbor nodes */
    neighborCount: number;
    
    /** Number of known routes to other nodes */
    routeCount: number;

    // === Anti-Replay Protection ===
    /** Unix timestamp when advertisement was created */
    timestamp: number;
    
    /** Monotonic sequence number for replay detection */
    sequenceNumber: number;

    // === Authentication ===
    /** Ed25519 signature of advertisement content for authenticity */
    signature: string;
}

/**
 * Detailed BLE connection information and performance metrics.
 * 
 * Tracks the state and performance of an active BLE connection with
 * another mesh node. Used for connection management, performance
 * optimization, and troubleshooting connectivity issues.
 * 
 * Connection Lifecycle:
 * 1. Discovery through advertisements
 * 2. Connection establishment
 * 3. Service and characteristic discovery
 * 4. Cryptographic authentication
 * 5. Ongoing message exchange
 * 6. Performance monitoring and optimization
 */
export interface ConnectionInfo {
    /** Connected peer's node fingerprint */
    peerId: string;
    
    /** Current connection state in the state machine */
    state: ConnectionState;
    
    /** Received Signal Strength Indicator in dBm */
    rssi: number;
    
    /** Maximum Transmission Unit for this connection in bytes */
    mtu: number;
    
    /** Estimated throughput in bytes per second */
    throughput: number;
    
    /** Average round-trip latency in milliseconds */
    latency: number;
    
    /** Total packets successfully transmitted */
    packetsTransmitted: number;
    
    /** Total packets successfully received */
    packetsReceived: number;
    
    /** Total transmission errors encountered */
    errors: number;
    
    /** Unix timestamp of last communication activity */
    lastActivity: number;
    
    /** Active session keys if authenticated connection established */
    sessionKeys?: SessionKeys;
}

// ===== ERROR TYPES =====

/**
 * Comprehensive cryptographic error enumeration for robust error handling.
 * 
 * These error types cover all possible cryptographic failures that can occur
 * during message processing, key management, and secure communication.
 * Proper error handling is essential for security and user experience.
 * 
 * Error Categories:
 * 1. Key Management Errors: Invalid or corrupted cryptographic keys
 * 2. Cryptographic Operation Errors: Encryption/decryption failures
 * 3. Protocol Errors: Version mismatches and format violations
 * 4. Security Errors: Replay attacks and integrity violations
 * 5. Session Errors: Double Ratchet state management issues
 * 
 * Error Handling Strategy:
 * - Log security-relevant errors for audit trails
 * - Provide user-friendly error messages for UI
 * - Implement automatic recovery where possible
 * - Fail securely when recovery is not possible
 */
export enum CryptoError {
    /** Cryptographic key is malformed, corrupted, or inappropriate for operation */
    INVALID_KEY = 'INVALID_KEY',
    
    /** Decryption operation failed due to wrong key, corrupted data, or tampering */
    DECRYPTION_FAILED = 'DECRYPTION_FAILED',
    
    /** Digital signature verification failed - message may be tampered or spoofed */
    SIGNATURE_VERIFICATION_FAILED = 'SIGNATURE_VERIFICATION_FAILED',
    
    /** Key exchange protocol failed - unable to establish shared secret */
    KEY_EXCHANGE_FAILED = 'KEY_EXCHANGE_FAILED',
    
    /** Message structure is invalid or missing required fields */
    INVALID_MESSAGE_FORMAT = 'INVALID_MESSAGE_FORMAT',
    
    /** Message has exceeded its time-to-live and should be discarded */
    MESSAGE_EXPIRED = 'MESSAGE_EXPIRED',
    
    /** Duplicate message detected - possible replay attack attempt */
    REPLAY_DETECTED = 'REPLAY_DETECTED',
    
    /** Required cryptographic session not found or expired */
    SESSION_NOT_FOUND = 'SESSION_NOT_FOUND',
    
    /** Message missing required sender key for protocol v2.1 compliance */
    NO_SENDER_KEY = 'NO_SENDER_KEY',
    
    /** Unsupported or incompatible protocol version */
    INVALID_PROTOCOL_VERSION = 'INVALID_PROTOCOL_VERSION',
    
    /** Double Ratchet message chain integrity compromised */
    MESSAGE_CHAIN_BROKEN = 'MESSAGE_CHAIN_BROKEN'
}

// ===== PROTOCOL VERSION =====

/**
 * Current protocol version constant.
 * 
 * Version 2.1 introduces mandatory sender keys for enhanced security
 * and improved key management. This version maintains backward
 * compatibility with version 2.0 clients while providing additional
 * security guarantees.
 * 
 * Version History:
 * - 2.0: Initial Double Ratchet implementation
 * - 2.1: Mandatory sender keys and enhanced verification
 * 
 * Compatibility Matrix:
 * - 2.1 clients can communicate with 2.0 clients (degraded security)
 * - 2.0 clients can receive from 2.1 clients (automatic upgrade)
 * - Future versions will maintain backward compatibility when possible
 */
export const PROTOCOL_VERSION = 2.1;

// ===== LEGACY TYPE EXPORTS =====

/**
 * Legacy type aliases for backward compatibility.
 * 
 * These aliases ensure that existing code continues to work while
 * new code uses the enhanced type names. Deprecated types will be
 * removed in future major versions with appropriate migration guides.
 * 
 * Migration Strategy:
 * 1. Update code to use new type names
 * 2. Test thoroughly with new interfaces
 * 3. Remove legacy imports before next major version
 */
export type {
    /** @deprecated Use KeyPair instead */
    KeyPair as LegacyKeyPair,
    
    /** @deprecated Use MeshNode instead */
    MeshNode as LegacyPeerInfo,
    
    /** @deprecated Use PlaintextMessage instead */
    PlaintextMessage as LegacyGhostMessage
};