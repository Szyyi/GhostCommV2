// core/src/types/crypto.ts
// Enhanced TypeScript type definitions for GhostComm cryptography v2.0

import { ReactNode } from "react";

// ===== CRYPTOGRAPHIC PRIMITIVES =====

/**
 * Supported cryptographic algorithms
 */
export enum CryptoAlgorithm {
    // Signing
    ED25519 = 'Ed25519',

    // Key Exchange
    X25519 = 'X25519',
    ECDH_P256 = 'ECDH-P256',  // Future: for post-quantum hybrid

    // Symmetric Encryption
    CHACHA20_POLY1305 = 'ChaCha20-Poly1305',
    XCHACHA20_POLY1305 = 'XChaCha20-Poly1305',  // Extended nonce version
    AES_256_GCM = 'AES-256-GCM',  // Alternative for hardware acceleration

    // Key Derivation
    HKDF_SHA256 = 'HKDF-SHA256',
    ARGON2ID = 'Argon2id',  // For password-based key derivation

    // Hashing
    SHA256 = 'SHA-256',
    SHA512 = 'SHA-512',
    BLAKE3 = 'BLAKE3'  // Future: faster alternative
}

// ===== KEY MANAGEMENT =====

/**
 * Enhanced key pair with metadata and versioning
 */
export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    algorithm: CryptoAlgorithm;
    createdAt: number;
    keyId?: string;  // Optional unique identifier
}

/**
 * Extended key pair with multiple key types
 */
export interface ExtendedKeyPair {
    identity: KeyPair;      // Ed25519 for signing
    encryption: KeyPair;    // X25519 for encryption
    preKeys?: PreKey[];     // Pre-generated ephemeral keys
    fingerprint: string;    // 256-bit fingerprint
    version: number;        // Key format version
}

/**
 * Pre-generated ephemeral keys for async key exchange
 */
export interface PreKey {
    keyId: number;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    signature: Uint8Array;  // Signed by identity key
    createdAt: number;
    usedAt?: number;
}

/**
 * Session keys for Double Ratchet implementation
 */
export interface SessionKeys {
    rootKey: Uint8Array;         // 32 bytes
    chainKey: Uint8Array;        // 32 bytes
    sendingKey?: Uint8Array;     // Current sending key
    receivingKey?: Uint8Array;   // Current receiving key
    messageNumber: number;       // For ordering
    previousChainLength: number; // Messages in previous chain
}

// ===== MESSAGE TYPES =====

/**
 * Enhanced message types with priority levels
 */
export enum MessageType {
    // Core message types
    DIRECT = 'direct',           // Direct person-to-person message
    BROADCAST = 'broadcast',     // Public message to all nearby nodes
    GROUP = 'group',            // Group chat message (new)

    // Protocol messages
    RELAY = 'relay',            // Forwarded message in mesh network
    DISCOVERY = 'discovery',     // Node discovery/handshake
    KEY_EXCHANGE = 'key_exchange', // Diffie-Hellman key exchange (new)

    // Control messages
    ACK = 'ack',                // Message acknowledgment
    RECEIPT = 'receipt',        // Delivery receipt (new)
    TYPING = 'typing',          // Typing indicator (new)

    // Security messages
    KEY_UPDATE = 'key_update',  // Key rotation notification (new)
    REVOCATION = 'revocation'   // Key revocation (new)
}

/**
 * Message priority for mesh routing decisions
 */
export enum MessagePriority {
    CRITICAL = 0,   // Emergency/SOS messages
    HIGH = 1,       // Key exchanges, ACKs
    NORMAL = 2,     // Regular messages
    LOW = 3         // Discovery, typing indicators
}

// ===== ENHANCED MESSAGE STRUCTURES =====

/**
 * Enhanced message header with security features
 */
export interface MessageHeader {
    // Version and identification
    version: number;            // Protocol version
    messageId: string;          // 256-bit unique ID

    // Routing information
    sourceId: string;           // Sender's fingerprint
    destinationId?: string;     // Recipient's fingerprint
    groupId?: string;           // Group identifier (new)

    // Timing and ordering
    timestamp: number;          // Unix timestamp in ms
    sequenceNumber: number;     // Message sequence (new)

    // Mesh routing
    ttl: number;               // Time-to-live in hops
    hopCount: number;          // Current hop count
    priority: MessagePriority; // Routing priority (new)
    relayPath: string[];       // Node IDs in relay path

    // Security
    signature: Uint8Array;     // Ed25519 signature
    previousMessageHash?: string; // Chain messages (new)
}

/**
 * Enhanced plaintext message with richer metadata
 */
export interface PlaintextMessage {
    header: MessageHeader;

    // Message content
    type: MessageType;
    payload: string;            // Actual message content

    // Optional fields
    replyTo?: string;          // Message ID being replied to
    attachments?: AttachmentMetadata[]; // File attachments (new)
    mentions?: string[];       // User IDs mentioned (new)
    reactions?: MessageReaction[]; // Reactions (new)

    // Security
    ephemeralExpiry?: number;  // Self-destruct timer (new)
    burnAfterReading?: boolean; // Delete after reading (new)
}

/**
 * Enhanced encrypted message with double ratchet support
 */
export interface EncryptedMessage {
    // Envelope metadata (unencrypted for routing)
    header: {
        messageId: string;
        sourceId: string;
        destinationId?: string;
        groupId?: string;
        timestamp: number;
        ttl: number;
        hopCount: number;
        priority: MessagePriority;
    };

    // Double Ratchet fields
    ephemeralPublicKey: string;  // Hex-encoded X25519 ephemeral key
    previousChainLength: number;  // Messages in previous chain (new)
    messageNumber: number;        // Message number in chain (new)

    // Encrypted payload
    nonce: string;               // 24-byte nonce for XChaCha20
    ciphertext: string;          // Encrypted message + header
    authTag: string;             // 16-byte Poly1305 MAC

    // Optional group message fields
    groupKeyId?: string;         // Group key version (new)
    senderKeyShare?: string;     // Sender's key for group (new)
}

// ===== ADDITIONAL TYPES =====

/**
 * File attachment metadata
 */
export interface AttachmentMetadata {
    id: string;
    filename: string;
    mimeType: string;
    size: number;
    hash: string;              // SHA-256 of content
    encryptionKey?: string;    // Per-file encryption key
    chunks?: number;           // For chunked transfer
}

/**
 * Message reactions
 */
export interface MessageReaction {
    emoji: string;
    userId: string;
    timestamp: number;
}

/**
 * Enhanced peer/node information
 */
export interface MeshNode {
    // Identity
    nodeId: string;              // 256-bit fingerprint
    publicKeys: {
        identity: Uint8Array;    // Ed25519
        encryption: Uint8Array;  // X25519
        preKeys?: PreKey[];      // Available pre-keys
    };

    // Network status
    lastSeen: number;
    firstSeen: number;          // When first discovered (new)
    isOnline: boolean;          // Currently reachable (new)

    // Capabilities
    protocolVersion: number;    // Supported protocol (new)
    supportedAlgorithms: CryptoAlgorithm[]; // Crypto support (new)
    capabilities: NodeCapability[]; // Feature support (new)

    // Mesh metrics
    signalStrength?: number;    // RSSI value
    batteryLevel?: number;      // Battery percentage
    messageStats?: {            // Statistics (new)
        sent: number;
        received: number;
        relayed: number;
        dropped: number;
    };

    // Trust metrics
    trustScore?: number;        // 0-100 trust level (new)
    verificationStatus?: VerificationStatus; // Verification state (new)
    verifiedBy?: string[];      // Node IDs that verified (new)

    // Optional metadata
    deviceName?: string;
    deviceType?: DeviceType;   // Phone, tablet, IoT (new)
    location?: GeoHash;        // Coarse location (new)
}

/**
 * Node capabilities
 */
export enum NodeCapability {
    RELAY = 'relay',
    STORAGE = 'storage',
    BRIDGE = 'bridge',          // Internet bridge
    GROUP_CHAT = 'group_chat',
    FILE_TRANSFER = 'file_transfer',
    VOICE_NOTES = 'voice_notes'
}

/**
 * Device types
 */
export enum DeviceType {
    PHONE = 'phone',
    TABLET = 'tablet',
    LAPTOP = 'laptop',
    IOT = 'iot',
    DEDICATED_RELAY = 'relay'
}

/**
 * Verification status for nodes
 */
export enum VerificationStatus {
    UNVERIFIED = 'unverified',
    VERIFIED = 'verified',
    TRUSTED = 'trusted',
    BLOCKED = 'blocked'
}

/**
 * Coarse geohash for proximity (privacy-preserving)
 */
export interface GeoHash {
    hash: string;              // 4-6 character geohash
    precision: number;         // Precision level
}

// ===== ROUTING & MESH =====

/**
 * Enhanced routing information
 */
export interface RouteInfo {
    destinationId: string;
    nextHop: string;
    hopCount: number;
    reliability: number;        // 0-1 success rate
    latency?: number;          // Average latency in ms
    bandwidth?: number;        // Estimated bandwidth
    lastUpdated: number;
    alternativeRoutes?: RouteInfo[]; // Backup routes (new)
}

/**
 * Message queue for store-and-forward
 */
export interface QueuedMessage {
    message: EncryptedMessage;
    destinationId: string;
    attempts: number;
    nextRetry: number;
    maxRetries: number;
    priority: MessagePriority;
    createdAt: number;
    expiresAt: number;
}

// ===== SECURITY INTERFACES =====

/**
 * Enhanced key pair interface with all security operations
 */
export interface IGhostKeyPair {
    export: any;
    getShortFingerprint(): string;
    // Key access
    getFingerprint(): string;                    // 256-bit fingerprint
    getIdentityPublicKey(): Uint8Array;
    getEncryptionPublicKey(): Uint8Array;
    getEncryptionPrivateKey(): Uint8Array;

    // Cryptographic operations
    signMessage(message: Uint8Array): Uint8Array;
    verifySignature(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
    performKeyExchange(theirPublicKey: Uint8Array, salt?: Uint8Array): Uint8Array;

    // Double Ratchet operations (new)
    initializeSession(theirPublicKey: Uint8Array): SessionKeys;
    ratchetSession(session: SessionKeys, theirEphemeralKey?: Uint8Array): SessionKeys;

    // Key management
    rotateEncryptionKey(): KeyPair;             // Generate new encryption key (new)
    generatePreKeys(count: number): PreKey[];    // Generate pre-keys (new)

    // Import/Export
    exportKeys(): ExportedKeys;
    exportPublicKeys(): ExportedPublicKeys;

    // Metadata
    getCreatedAt(): number;
    getVersion(): number;
}

/**
 * Exported key format
 */
export interface ExportedKeys {
    publicKey: any;
    version: number;
    identityPrivate: string;
    identityPublic: string;
    encryptionPrivate: string;
    encryptionPublic: string;
    preKeys?: Array<{
        keyId: number;
        private: string;
        public: string;
    }>;
    createdAt: number;
}

/**
 * Exported public keys only
 */
export interface ExportedPublicKeys {
    version: number;
    identityPublic: string;
    encryptionPublic: string;
    fingerprint: string;
    preKeys?: Array<{
        keyId: number;
        public: string;
        signature: string;
    }>;
}

/**
 * Enhanced message encryption interface
 */
export interface IMessageEncryption {
    // Basic encryption
    encryptMessage(message: PlaintextMessage, senderKeyPair: IGhostKeyPair, recipientPublicKey: Uint8Array): Promise<EncryptedMessage>;
    decryptMessage(encryptedMessage: EncryptedMessage, recipientKeyPair: IGhostKeyPair): Promise<PlaintextMessage>;

    // Group messaging (new)
    encryptGroupMessage(message: PlaintextMessage, senderKeyPair: IGhostKeyPair, groupKey: Uint8Array): Promise<EncryptedMessage>;
    decryptGroupMessage(encryptedMessage: EncryptedMessage, groupKey: Uint8Array): Promise<PlaintextMessage>;

    // Broadcast messages
    createBroadcastMessage(message: PlaintextMessage, senderKeyPair: IGhostKeyPair): Promise<EncryptedMessage>;
    decryptBroadcastMessage(encryptedMessage: EncryptedMessage, senderPublicKey: Uint8Array): Promise<PlaintextMessage>;

    // Session management (new)
    establishSession(senderKeyPair: IGhostKeyPair, recipientPublicKey: Uint8Array): Promise<SessionKeys>;
    encryptWithSession(message: PlaintextMessage, session: SessionKeys): Promise<EncryptedMessage>;
    decryptWithSession(encryptedMessage: EncryptedMessage, session: SessionKeys): Promise<PlaintextMessage>;

    // Utilities
    generateMessageId(): string;
    validateMessage(message: PlaintextMessage): boolean;
    calculateMessageHash(message: PlaintextMessage): string;
}

// ===== STORAGE INTERFACES =====

/**
 * Enhanced message storage with indexing
 */
export interface IMessageStore {
    // Basic operations
    storeMessage(message: EncryptedMessage): Promise<void>;
    getMessage(messageId: string): Promise<EncryptedMessage | null>;
    getMessagesForNode(nodeId: string): Promise<EncryptedMessage[]>;
    removeMessage(messageId: string): Promise<void>;

    // Batch operations (new)
    storeMessages(messages: EncryptedMessage[]): Promise<void>;
    removeMessages(messageIds: string[]): Promise<void>;

    // Query operations (new)
    queryMessages(filter: MessageFilter): Promise<EncryptedMessage[]>;
    getMessagesByTimeRange(start: number, end: number): Promise<EncryptedMessage[]>;
    getMessagesByPriority(priority: MessagePriority): Promise<EncryptedMessage[]>;

    // Maintenance
    pruneExpiredMessages(): Promise<number>;
    compactStorage(): Promise<void>;              // Defragment storage (new)

    // Statistics
    getStorageStats(): Promise<StorageStats>;
    getMessageStats(): Promise<MessageStats>;     // Message statistics (new)
}

/**
 * Message query filter
 */
export interface MessageFilter {
    nodeId?: string;
    messageType?: MessageType;
    priority?: MessagePriority;
    startTime?: number;
    endTime?: number;
    limit?: number;
    offset?: number;
}

/**
 * Storage statistics
 */
export interface StorageStats {
    totalMessages: number;
    totalSize: number;         // In bytes
    oldestMessage: number;     // Timestamp
    newestMessage: number;     // Timestamp
    byType: Record<MessageType, number>;
    byPriority: Record<MessagePriority, number>;
}

/**
 * Message statistics
 */
export interface MessageStats {
    sent: number;
    received: number;
    relayed: number;
    dropped: number;
    expired: number;
    delivered: number;
    pending: number;
}

// ===== NETWORK STATISTICS =====

/**
 * Enhanced network statistics
 */
export interface NetworkStats {
    totalConnections: ReactNode;
    // Node metrics
    totalNodes: number;
    activeNodes: number;
    trustedNodes: number;
    blockedNodes: number;

    // Message metrics
    messagesSent: number;
    messagesReceived: number;
    messagesRelayed: number;
    messagesDropped: number;

    // Performance metrics
    averageHopCount: number;
    averageLatency: number;
    deliverySuccessRate: number;

    // Network health
    networkDensity: number;    // Nodes per area
    networkReachability: number; // Percentage of reachable nodes

    // Bandwidth metrics (new)
    bytesTransmitted: number;
    bytesReceived: number;
    averageThroughput: number;

    // Time-based metrics
    uptime: number;
    lastUpdated: number;
}

// ===== BLE SPECIFIC TYPES =====

/**
 * Enhanced BLE advertisement
 */
export interface BLEAdvertisement {
    // Identity
    nodeId: string;
    publicKey: string;         // Hex-encoded X25519 public key

    // Service info
    serviceUUID: string;
    characteristicUUIDs: string[];

    // Status
    protocolVersion: number;
    capabilities: NodeCapability[];
    batteryLevel?: number;

    // Message queue
    messageCount: number;
    queueSize: number;         // Total queue size in bytes
    highPriorityCount: number; // High priority messages

    // Mesh info
    neighborCount: number;     // Known neighbors
    routeCount: number;       // Known routes

    // Timestamps
    timestamp: number;
    sequenceNumber: number;   // For detecting replays

    // Signature
    signature: string;        // Ed25519 signature of advertisement
}

/**
 * BLE connection state
 */
export enum ConnectionState {
    DISCONNECTED = 'disconnected',
    CONNECTING = 'connecting',
    CONNECTED = 'connected',
    AUTHENTICATING = 'authenticating',
    AUTHENTICATED = 'authenticated',
    DISCONNECTING = 'disconnecting',
    FAILED = 'failed'
}

/**
 * BLE connection info
 */
export interface ConnectionInfo {
    peerId: string;
    state: ConnectionState;
    rssi: number;
    mtu: number;              // Maximum transmission unit
    throughput: number;       // Estimated throughput
    latency: number;         // Round-trip time
    packetsTransmitted: number;
    packetsReceived: number;
    errors: number;
    lastActivity: number;
    sessionKeys?: SessionKeys; // Encrypted session
}

// ===== ERROR TYPES =====

/**
 * Cryptographic error types
 */
export enum CryptoError {
    INVALID_KEY = 'INVALID_KEY',
    DECRYPTION_FAILED = 'DECRYPTION_FAILED',
    SIGNATURE_VERIFICATION_FAILED = 'SIGNATURE_VERIFICATION_FAILED',
    KEY_EXCHANGE_FAILED = 'KEY_EXCHANGE_FAILED',
    INVALID_MESSAGE_FORMAT = 'INVALID_MESSAGE_FORMAT',
    MESSAGE_EXPIRED = 'MESSAGE_EXPIRED',
    REPLAY_DETECTED = 'REPLAY_DETECTED',
    SESSION_NOT_FOUND = 'SESSION_NOT_FOUND'
}

/**
 * Export all types for backward compatibility
 */
export type {
    KeyPair as LegacyKeyPair,
    MeshNode as LegacyPeerInfo,
    PlaintextMessage as LegacyGhostMessage
};