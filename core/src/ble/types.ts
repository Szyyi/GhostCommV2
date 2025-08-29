// core/src/ble/types.ts
// Enhanced BLE type definitions with advanced security features - Protocol v2

import {
    SessionKeys,
    PreKey,
    MessagePriority,
    ConnectionState,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    CryptoAlgorithm,
    EncryptedMessage
} from '../types/crypto';

// ===== CORE BLE NODE TYPES =====

/**
 * Enhanced BLE node with full cryptographic identity
 */
export interface BLENode {
    // Identity
    id: string;                       // 256-bit fingerprint (SHA-256 of public keys)
    name: string;                     // Human-readable device name

    // Cryptographic keys (REQUIRED for v2)
    identityKey: Uint8Array;          // Ed25519 identity public key - REQUIRED
    encryptionKey: Uint8Array;        // X25519 encryption public key
    preKeys?: PreKey[];               // Available pre-keys for async key exchange

    // Key validation tracking
    keysValidatedAt?: number;         // When keys were last validated
    keyValidationMethod?: 'handshake' | 'advertisement' | 'message';

    // Connection status
    isConnected: boolean;             // Current connection status
    connectionId?: string;            // BLE connection identifier
    session?: BLESession;             // Active Double Ratchet session

    // Network metrics
    lastSeen: number;                 // Unix timestamp of last contact
    firstSeen: number;                // When first discovered
    rssi: number;                     // Signal strength (-100 to 0 dBm)
    lastRSSI: number;                 // Last recorded RSSI
    txPower?: number;                 // Transmission power
    distance?: number;                // Estimated distance in meters

    // Security status
    verificationStatus: VerificationStatus;  // Trust level
    verifiedAt?: number;              // When verified
    verificationMethod?: VerificationMethod; // How verified
    trustScore: number;               // 0-100 trust rating

    // Capabilities
    protocolVersion: number;          // MUST be 2 for new protocol
    capabilities: NodeCapability[];   // Node capabilities
    deviceType: DeviceType;           // Device type
    supportedAlgorithms: CryptoAlgorithm[]; // Crypto support

    // Mesh metrics
    isRelay: boolean;                 // Can relay messages
    relayStats?: RelayStatistics;    // Relay performance
    routingTable?: Map<string, RouteMetrics>; // Known routes

    // Anti-tracking
    bluetoothAddress: string;         // Current BLE MAC address
    addressRotationTime?: number;    // When address will rotate
    previousAddresses?: string[];    // Historical addresses for correlation

    // Additional fields
    batteryLevel?: number;            // Battery percentage
    canSee: any;                      // Visibility state (preserved from original)
}

/**
 * Active BLE session with Double Ratchet state and message chain tracking
 */
export interface BLESession {
    sessionId: string;                // Unique session identifier
    state: ConnectionState;           // Connection state
    establishedAt: number;            // Session establishment time
    lastActivity: number;             // Last message timestamp

    // Double Ratchet state
    sessionKeys: SessionKeys;         // Current session keys
    sendMessageNumber: number;        // Outgoing message counter
    receiveMessageNumber: number;     // Incoming message counter

    // Message chain tracking (Protocol v2)
    lastSentMessageHash?: string;     // Hash of last sent message
    lastReceivedMessageHash?: string; // Hash of last received message
    sentSequenceNumber: number;       // Outgoing sequence number
    receivedSequenceNumber: number;   // Incoming sequence number

    // Public key cache for verification
    peerIdentityKey?: Uint8Array;     // Cached peer's Ed25519 public key
    peerEncryptionKey?: Uint8Array;   // Cached peer's X25519 public key

    // Connection parameters
    mtu: number;                      // Maximum transmission unit
    connectionInterval: number;       // BLE connection interval (ms)
    latency: number;                  // Connection latency
    supervisionTimeout: number;       // Link supervision timeout

    // Security parameters
    channelBinding?: Uint8Array;     // Channel binding token
    attestation?: DeviceAttestation; // Device attestation data

    // Performance metrics
    throughput: number;               // Bytes per second
    packetLoss: number;              // Packet loss rate (0-1)
    messagesExchanged: number;       // Total messages
    bytesTransferred: number;        // Total bytes
}

// ===== ADVERTISEMENT TYPES =====

/**
 * Enhanced BLE advertisement with signatures and anti-tracking
 */
export interface BLEAdvertisementData {
    // Protocol version
    version: number;                  // Protocol version (must be 2)

    // Identity (rotating for privacy)
    ephemeralId: string;             // Rotating ephemeral ID

    // Cryptographic proof
    identityProof: IdentityProof;    // Proves ownership of identity

    // Network status
    timestamp: number;               // Advertisement timestamp
    sequenceNumber: number;          // For replay protection

    // Capabilities
    capabilities: NodeCapability[];  // Node capabilities
    deviceType: DeviceType;          // Device type
    protocolVersion: number;         // Supported protocol

    // Mesh information
    meshInfo: MeshAdvertisement;     // Mesh network data

    // Optional fields
    batteryLevel?: number;           // Battery percentage (0-100)
    txPower?: number;                // Transmission power for ranging
}

/**
 * Identity proof for advertisement authentication
 */
export interface IdentityProof {
    publicKeyHash: string;           // Hash of identity public key
    publicKey: string;               // Full hex-encoded Ed25519 public key (v2)
    timestamp: number;               // Proof timestamp
    nonce: string;                   // Random nonce
    signature: string;               // Ed25519 signature
    preKeyBundle?: PreKeyBundle;     // Optional pre-keys for key exchange
}

/**
 * Pre-key bundle for asynchronous key exchange
 */
export interface PreKeyBundle {
    identityKey: string;             // Hex-encoded Ed25519 public key
    signedPreKey: {
        keyId: number;
        publicKey: string;           // Hex-encoded X25519 public key
        signature: string;           // Ed25519 signature
    };
    oneTimePreKeys?: Array<{         // One-time pre-keys
        keyId: number;
        publicKey: string;
    }>;
}

/**
 * Mesh-specific advertisement data
 */
export interface MeshAdvertisement {
    nodeCount: number;               // Known nodes in mesh
    messageQueueSize: number;        // Pending messages
    routingTableVersion: number;     // Routing table version
    networkId?: string;              // Network identifier
    beaconInterval: number;          // Beacon interval in ms
}

// ===== MESSAGE TYPES =====

/**
 * Enhanced BLE message with full encryption metadata and verification context
 */
export interface BLEMessage {
    // Message identity
    messageId: string;               // 256-bit unique identifier
    version: number;                 // Protocol version (must be 2)

    // Routing information
    sourceId: string;                // Original sender fingerprint
    destinationId?: string;          // Final recipient fingerprint
    ttl: number;                     // Time-to-live in ms
    hopCount: number;                // Current hop count
    maxHops: number;                 // Maximum allowed hops
    priority: MessagePriority;       // Message priority

    // Sender verification context (Protocol v2 - CRITICAL)
    senderPublicKey: string;         // Hex-encoded Ed25519 public key for verification
    messageSignature: string;        // Ed25519 signature of the message
    
    // Message chain fields (Protocol v2)
    messageHash: string;             // SHA-256 hash of this message
    previousMessageHash: string;     // Hash of previous message in chain
    sequenceNumber: number;          // Message sequence number

    // Encrypted payload
    encryptedPayload: EncryptedMessage; // Full encrypted message

    // Fragmentation
    fragment?: MessageFragment;      // Fragment information

    // Routing path
    routePath: string[];             // Node IDs in route
    nextHop?: string;                // Next node in route

    // Security
    relaySignatures: RelaySignature[]; // Signatures from relays

    // Timestamps
    createdAt: number;               // Creation timestamp
    expiresAt: number;              // Expiration timestamp
}

/**
 * Message fragmentation information
 */
export interface MessageFragment {
    fragmentId: string;              // Fragment set identifier
    index: number;                   // Fragment index (0-based)
    total: number;                   // Total fragments
    size: number;                    // Fragment size in bytes
    checksum: string;                // Fragment checksum
}

/**
 * Relay signature for path authentication
 */
export interface RelaySignature {
    nodeId: string;                  // Relay node fingerprint
    timestamp: number;               // Relay timestamp
    signature: string;               // Ed25519 signature
    rssi?: number;                   // Signal strength at relay
}

// ===== CONNECTION EVENTS =====

/**
 * Enhanced connection event with security context
 */
export interface BLEConnectionEvent {
    type: 'connected' | 'disconnected' | 'error' | 'authenticated' | 'session_established';
    nodeId: string;
    connectionId?: string;

    // Security context
    session?: BLESession;
    verificationStatus?: VerificationStatus;

    // Connection parameters
    mtu?: number;
    rssi?: number;

    // Error information
    error?: BLEError;

    // Timestamp
    timestamp: number;
}

/**
 * Enhanced message event with delivery tracking and verification
 */
export interface BLEMessageEvent {
    type: 'message_received' | 'message_sent' | 'message_failed' |
          'message_acknowledged' | 'message_relayed' | 'fragment_received' |
          'signature_verification_failed';  // Protocol v2

    message: BLEMessage;

    // Context
    fromNodeId?: string;
    toNodeId?: string;
    sessionId?: string;

    // Verification context (Protocol v2)
    senderNode?: BLENode;            // Full node info including public keys
    verificationResult?: {
        verified: boolean;
        method: 'signature' | 'session';
        error?: string;
    };

    // Delivery status
    delivered?: boolean;
    acknowledgment?: MessageAcknowledgment;

    // Error information
    error?: BLEError;

    // Metrics
    latency?: number;                // End-to-end latency
    hopCount?: number;               // Actual hops taken

    // Timestamp
    timestamp: number;
}

/**
 * Message acknowledgment
 */
export interface MessageAcknowledgment {
    messageId: string;
    nodeId: string;
    timestamp: number;
    signature: string;               // Signed acknowledgment
}

/**
 * Enhanced discovery event with verification
 */
export interface BLEDiscoveryEvent {
    type: 'node_discovered' | 'node_lost' | 'node_updated' | 'node_verified';
    node: BLENode;

    // Discovery context
    advertisement?: BLEAdvertisementData;
    rssi: number;

    // Verification
    verificationResult?: VerificationResult;

    // Timestamp
    timestamp: number;
}

/**
 * Verification result
 */
export interface VerificationResult {
    verified: boolean;
    method: VerificationMethod;
    verifierNodeId?: string;
    attestation?: string;
    timestamp: number;
}

// ===== SECURITY TYPES =====

/**
 * Verification methods
 */
export enum VerificationMethod {
    QR_CODE = 'qr_code',            // QR code exchange
    NUMERIC_COMPARISON = 'numeric',  // Numeric code comparison
    FINGERPRINT = 'fingerprint',     // Key fingerprint verification
    PRE_SHARED = 'pre_shared',       // Pre-shared key
    TRUSTED_THIRD_PARTY = 'trusted', // Verified by trusted node
    OUT_OF_BAND = 'out_of_band'     // Out-of-band verification
}

/**
 * Device attestation for secure boot verification
 */
export interface DeviceAttestation {
    deviceId: string;                // Unique device identifier
    firmwareHash: string;            // Firmware hash
    bootNonce: string;               // Boot-time nonce
    signature: string;               // Attestation signature
    certificateChain?: string[];     // Optional certificate chain
}

/**
 * BLE-specific error types
 */
export interface BLEError {
    code: BLEErrorCode;
    message: string;
    details?: any;
    timestamp: number;
}

/**
 * BLE error codes - Enhanced for Protocol v2
 */
export enum BLEErrorCode {
    // Connection errors
    CONNECTION_FAILED = 'CONNECTION_FAILED',
    CONNECTION_TIMEOUT = 'CONNECTION_TIMEOUT',
    CONNECTION_LOST = 'CONNECTION_LOST',

    // Authentication errors
    AUTHENTICATION_FAILED = 'AUTH_FAILED',
    INVALID_SIGNATURE = 'INVALID_SIGNATURE',
    KEY_EXCHANGE_FAILED = 'KEY_EXCHANGE_FAILED',
    SESSION_EXPIRED = 'SESSION_EXPIRED',

    // Signature verification errors (Protocol v2)
    NO_SENDER_KEY = 'NO_SENDER_KEY',
    SIGNATURE_VERIFICATION_FAILED = 'SIG_VERIFY_FAILED',
    INVALID_MESSAGE_CHAIN = 'INVALID_MESSAGE_CHAIN',
    SEQUENCE_NUMBER_MISMATCH = 'SEQ_NUM_MISMATCH',

    // Message errors
    MESSAGE_TOO_LARGE = 'MESSAGE_TOO_LARGE',
    FRAGMENTATION_ERROR = 'FRAGMENTATION_ERROR',
    DECRYPTION_FAILED = 'DECRYPTION_FAILED',

    // Routing errors
    NO_ROUTE = 'NO_ROUTE',
    TTL_EXPIRED = 'TTL_EXPIRED',
    MAX_HOPS_EXCEEDED = 'MAX_HOPS_EXCEEDED',

    // Resource errors
    QUEUE_FULL = 'QUEUE_FULL',
    OUT_OF_MEMORY = 'OUT_OF_MEMORY',
    RATE_LIMITED = 'RATE_LIMITED',

    // Protocol errors
    UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',
    INVALID_FORMAT = 'INVALID_FORMAT',
    REPLAY_DETECTED = 'REPLAY_DETECTED',
    PROTOCOL_VERSION_MISMATCH = 'PROTOCOL_VERSION_MISMATCH'
}

// ===== MESH ROUTING TYPES =====

/**
 * Routing table entry
 */
export interface RouteEntry {
    destinationId: string;           // Target node
    nextHop: string;                 // Next node in route
    hopCount: number;                // Distance to destination
    metrics: RouteMetrics;           // Route quality metrics
    lastUpdated: number;            // Last update timestamp
    expires: number;                 // Route expiration
}

/**
 * Route quality metrics
 */
export interface RouteMetrics {
    reliability: number;             // Success rate (0-1)
    latency: number;                 // Average latency in ms
    bandwidth: number;               // Estimated bandwidth
    packetLoss: number;             // Packet loss rate (0-1)
    jitter: number;                  // Latency variation
    cost: number;                    // Computed route cost
}

/**
 * Relay statistics
 */
export interface RelayStatistics {
    messagesRelayed: number;
    bytesRelayed: number;
    successRate: number;
    averageLatency: number;
    activeRoutes: number;
    lastRelayTime: number;
}

// ===== PROTOCOL v2 TYPES =====

/**
 * Protocol handshake for version negotiation and key exchange
 */
export interface ProtocolHandshake {
    protocolVersion: number;         // Must be 2 for current protocol
    supportedVersions: number[];     // For backward compatibility check
    identityKey: string;             // Hex-encoded Ed25519 public key
    encryptionKey: string;           // Hex-encoded X25519 public key
    timestamp: number;
    nonce: string;
    signature: string;               // Signed with identity key
    capabilities: NodeCapability[];
    requireSignatureVerification: boolean;  // Must be true for v2
}

/**
 * Message verification context helper
 */
export interface MessageVerificationContext {
    message: BLEMessage;
    senderPublicKey: Uint8Array;    // Ed25519 public key
    signature: Uint8Array;           // Message signature
    previousMessageHash?: string;    // For chain verification
    sequenceNumber?: number;         // For sequence verification
}

// ===== CONFIGURATION =====

/**
 * Enhanced BLE configuration with security parameters
 */
export const BLE_CONFIG = {
    // Service UUIDs
    SERVICE_UUID: '6ba7b810-9dad-11d1-80b4-00c04fd430c8',

    // Characteristic UUIDs
    CHARACTERISTICS: {
        // Discovery and handshake
        NODE_DISCOVERY: '6ba7b811-9dad-11d1-80b4-00c04fd430c8',
        KEY_EXCHANGE: '6ba7b815-9dad-11d1-80b4-00c04fd430c8',

        // Messaging
        MESSAGE_EXCHANGE: '6ba7b812-9dad-11d1-80b4-00c04fd430c8',
        MESSAGE_ACKNOWLEDGMENT: '6ba7b816-9dad-11d1-80b4-00c04fd430c8',

        // Network management
        NETWORK_STATUS: '6ba7b813-9dad-11d1-80b4-00c04fd430c8',
        ROUTING_TABLE: '6ba7b814-9dad-11d1-80b4-00c04fd430c8',

        // Security
        VERIFICATION: '6ba7b817-9dad-11d1-80b4-00c04fd430c8',
        ATTESTATION: '6ba7b818-9dad-11d1-80b4-00c04fd430c8'
    },

    // Timing parameters (ms)
    ADVERTISEMENT_INTERVAL: 5000,        // 5 seconds base interval
    ADVERTISEMENT_RANDOMIZATION: 1000,    // ±1 second randomization
    SCAN_INTERVAL: 5000,                // 5 seconds
    SCAN_WINDOW: 4500,                  // 4.5 seconds
    CONNECTION_TIMEOUT: 10000,           // 10 seconds
    AUTHENTICATION_TIMEOUT: 5000,        // 5 seconds

    // Security parameters
    ADDRESS_ROTATION_INTERVAL: 900000,   // 15 minutes
    SESSION_LIFETIME: 86400000,          // 24 hours
    KEY_ROTATION_INTERVAL: 3600000,      // 1 hour
    REPLAY_WINDOW_SIZE: 1000,            // Number of messages

    // Message parameters
    MESSAGE_TTL: 300000,                 // 5 minutes default
    MAX_HOP_COUNT: 10,                   // Maximum mesh hops
    MAX_MESSAGE_SIZE: 65536,             // 64KB maximum
    FRAGMENT_SIZE: 512,                  // BLE MTU limit
    DEFAULT_MTU: 247,                    // Default BLE MTU
    MAX_MTU: 517,                        // Maximum BLE 5.0 MTU

    // Queue parameters
    MAX_QUEUE_SIZE: 100,                 // Maximum queued messages
    QUEUE_CLEANUP_INTERVAL: 60000,       // 1 minute
    MESSAGE_RETRY_COUNT: 3,              // Retry attempts
    MESSAGE_RETRY_DELAY: 1000,           // 1 second

    // Rate limiting
    MAX_MESSAGES_PER_SECOND: 10,         // Per connection
    MAX_CONNECTIONS: 8,                  // Maximum simultaneous
    MAX_DISCOVERY_RATE: 5,               // Discoveries per second

    // Mesh parameters
    ROUTING_UPDATE_INTERVAL: 30000,      // 30 seconds
    NEIGHBOR_TIMEOUT: 120000,            // 2 minutes
    ROUTE_EXPIRY: 600000,                // 10 minutes
    MAX_ROUTE_AGE: 3600000,              // 1 hour

    // Performance tuning
    CONNECTION_INTERVAL_MIN: 7.5,        // ms
    CONNECTION_INTERVAL_MAX: 30,         // ms
    CONNECTION_LATENCY: 0,               // slave latency
    SUPERVISION_TIMEOUT: 4000,           // ms

    // Power management
    LOW_POWER_MODE: false,               // Enable low power
    BEACON_ONLY_MODE: false,            // Beacon-only mode
    ADAPTIVE_POWER: true                // Adaptive TX power
};

/**
 * BLE security configuration for Protocol v2
 */
export const BLE_SECURITY_CONFIG = {
    // Protocol version (MUST match encryption.ts)
    PROTOCOL_VERSION: 2,
    
    // Security requirements
    REQUIRE_SIGNATURE_VERIFICATION: true,
    REQUIRE_MESSAGE_CHAINING: true,
    REQUIRE_SEQUENCE_NUMBERS: true,
    
    // Replay protection
    REPLAY_WINDOW_SIZE: 1000,
    MAX_SEQUENCE_NUMBER_GAP: 100,
    
    // Session management
    SESSION_LIFETIME: 86400000,          // 24 hours
    SESSION_REFRESH_INTERVAL: 3600000,   // 1 hour
    
    // Key management
    REQUIRE_PUBLIC_KEY_IN_MESSAGE: true,
    CACHE_PEER_KEYS: true,
    KEY_CACHE_TTL: 3600000,              // 1 hour
};

// ===== CALLBACK TYPES =====

/**
 * Generic BLE event callback
 */
export type BLEEventCallback = (
    event: BLEConnectionEvent | BLEMessageEvent | BLEDiscoveryEvent
) => void;

/**
 * Connection state callback
 */
export type ConnectionCallback = (
    nodeId: string,
    state: ConnectionState,
    session?: BLESession
) => void;

/**
 * Message handler callback - Enhanced for Protocol v2
 */
export type MessageCallback = (
    message: BLEMessage,
    fromNode: BLENode,      // Contains identityKey for verification
    session: BLESession,    // Contains cached peer keys
    verificationResult: {   // Explicit verification result
        verified: boolean;
        senderPublicKey?: Uint8Array;
        error?: string;
    }
) => Promise<void>;

/**
 * Discovery callback
 */
export type DiscoveryCallback = (
    node: BLENode,
    advertisement: BLEAdvertisementData
) => void;

/**
 * Verification callback
 */
export type VerificationCallback = (
    nodeId: string,
    result: VerificationResult
) => void;

// ===== UTILITY TYPES =====

/**
 * BLE manager state
 */
export interface BLEManagerState {
    isScanning: boolean;
    isAdvertising: boolean;
    connections: Map<string, BLESession>;
    discoveredNodes: Map<string, BLENode>;
    messageQueue: Map<string, BLEMessage[]>;
    routingTable: Map<string, RouteEntry>;
    statistics: BLEStatistics;
}

/**
 * BLE statistics
 */
export interface BLEStatistics {
    // Connection stats
    totalConnections: number;
    activeConnections: number;
    failedConnections: number;

    // Message stats
    messagesSent: number;
    messagesReceived: number;
    messagesRelayed: number;
    messagesDropped: number;

    // Discovery stats
    nodesDiscovered: number;
    nodesVerified: number;

    // Performance stats
    averageLatency: number;
    averageThroughput: number;
    packetLossRate: number;

    // Security stats
    authenticationsSucceeded: number;
    authenticationsFailed: number;
    replaysDetected: number;

    // Timestamps
    startTime: number;
    lastResetTime: number;
}

/**
 * BLE capabilities for feature detection
 */
export interface BLECapabilities {
    bluetooth5: boolean;              // BLE 5.0+ support
    longRange: boolean;              // Long range support
    extendedAdvertising: boolean;    // Extended advertising
    periodicAdvertising: boolean;    // Periodic advertising
    connectionlessCte: boolean;      // Direction finding
    multiplePhy: boolean;            // 2M/Coded PHY support
    maxMtu: number;                  // Maximum MTU supported
    maxConnections: number;          // Maximum connections
    offloadedFiltering: boolean;    // Hardware filtering
    offloadedScanning: boolean;     // Hardware scanning
}

// Re-export types from crypto module
export { ConnectionState, NodeCapability, DeviceType, VerificationStatus };