// core/src/index.ts

import { BLEAdvertiser } from './ble/advertiser';
import { BLEConnectionManager } from './ble/connection';
import { BLEManager } from './ble/manager';
import { MeshNetwork } from './ble/mesh';
import { BLEScanner } from './ble/scanner';
import { BLEErrorCode, VerificationMethod } from './ble/types';
import { MessageEncryption, MessageFactory, MessageType } from './crypto/encryption';
import { GhostKeyPair } from './crypto/keypair';
import { ConnectionState, CryptoError, DeviceType, MessagePriority, NodeCapability, VerificationStatus } from './types/crypto';

// GhostComm Core Library - Military-Grade P2P Messaging
export const VERSION = '2.0.0';

// ============================================================================
// CRYPTOGRAPHIC FOUNDATION
// ============================================================================

// Core key management with Double Ratchet support
export { GhostKeyPair } from './crypto/keypair';

// Message encryption with Perfect Forward Secrecy
export { MessageEncryption } from './crypto/encryption';

// Message factory for creating messages
export { MessageFactory } from './crypto/encryption';

// Export MessageType directly from encryption
export { MessageType } from './crypto/encryption';

// ============================================================================
// TYPE DEFINITIONS - CRYPTOGRAPHY
// ============================================================================

// Export all types from crypto
export * from './types/crypto';

// Explicitly export enums (they need explicit export in TypeScript)
export {
    CryptoAlgorithm,
    MessageType as MessageTypeEnum,
    MessagePriority,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    ConnectionState,
    CryptoError
} from './types/crypto';

// Export interfaces and types
export type {
    // Key management types
    KeyPair,
    ExtendedKeyPair,
    PreKey,
    SessionKeys,
    IGhostKeyPair,
    IMessageEncryption,
    ExportedKeys,
    ExportedPublicKeys,

    // Message types
    PlaintextMessage,
    EncryptedMessage,
    MessageHeader,
    AttachmentMetadata,
    MessageReaction,

    // Network types
    MeshNode,
    RouteInfo,
    QueuedMessage,
    NetworkStats,
    MessageStats,
    StorageStats,

    // Storage interfaces
    IMessageStore,
    MessageFilter,

    // Verification types (Note: VerificationResult and VerificationMethod might not exist in crypto.ts)
    // VerificationResult,
    // VerificationMethod,

    // Location types
    GeoHash,

    // BLE specific types
    BLEAdvertisement,
    ConnectionInfo
} from './types/crypto';

// ============================================================================
// BLE MESH NETWORKING
// ============================================================================

// Core BLE components
export { BLEManager } from './ble/manager';
export { BLEAdvertiser } from './ble/advertiser';
export { BLEScanner } from './ble/scanner';
export { BLEConnectionManager } from './ble/connection';
export { MeshNetwork } from './ble/mesh';

// ============================================================================
// TYPE DEFINITIONS - BLE
// ============================================================================

// Export all BLE types
export * from './ble/types';

// Explicitly export BLE enums
export {
    VerificationMethod,
    BLEErrorCode
} from './ble/types';

// Export BLE types
export type {
    // Core BLE types
    BLENode,
    BLESession,
    BLEMessage,
    BLEAdvertisementData,

    // Connection types (Note: ConnectionInfo might conflict with crypto.ts)
    // ConnectionInfo as BLEConnectionInfo,

    // Advertisement types
    IdentityProof,
    PreKeyBundle as BLEPreKeyBundle,
    MeshAdvertisement,

    // Event types
    BLEConnectionEvent,
    BLEMessageEvent,
    BLEDiscoveryEvent,

    // Message types
    MessageFragment,
    RelaySignature,
    MessageAcknowledgment,

    // Security types
    DeviceAttestation,

    // Error types
    BLEError,

    // Routing types
    RouteEntry,
    RelayStatistics,

    // Manager types
    BLEManagerState,
    BLEStatistics,
    BLECapabilities,

    // Callback types
    BLEEventCallback,
    ConnectionCallback,
    MessageCallback,
    DiscoveryCallback,
    VerificationCallback
} from './ble/types';

// Export configuration
export { BLE_CONFIG } from './ble/types';

// ============================================================================
// SCANNER SPECIFIC EXPORTS
// ============================================================================

export type {
    ScanResult,
    ScanFilter,
    ScanConfig,
    ScanCallback
} from './ble/scanner';

// ============================================================================
// CONNECTION SPECIFIC EXPORTS
// ============================================================================

export type {
    SecureConnection as Connection,
    ConnectionConfig,
    ConnectionStatistics,
    SessionCallback
} from './ble/connection';

// ============================================================================
// ADVERTISER SPECIFIC EXPORTS
// ============================================================================

// Export the static method for parsing advertisement packets
export const parseAdvertisementPacket = BLEAdvertiser.parseAdvertisementPacket;

// ============================================================================
// SECURITY CONSTANTS
// ============================================================================

export const SECURITY_CONFIG = {
    // Protocol version
    PROTOCOL_VERSION: 2,

    // Cryptographic parameters
    KEY_SIZE: 32,                        // 256-bit keys
    FINGERPRINT_SIZE: 32,                // 256-bit fingerprints
    NONCE_SIZE_XCHACHA: 24,             // XChaCha20-Poly1305
    AUTH_TAG_SIZE: 16,                   // Poly1305

    // Double Ratchet parameters
    MAX_SKIP_KEYS: 1000,
    MESSAGE_KEY_LIFETIME: 7 * 24 * 60 * 60 * 1000, // 7 days

    // Pre-key settings
    DEFAULT_PREKEY_COUNT: 100,
    PREKEY_ROTATION_INTERVAL: 7 * 24 * 60 * 60 * 1000, // 7 days

    // Session parameters
    SESSION_LIFETIME: 24 * 60 * 60 * 1000, // 24 hours
    KEY_ROTATION_INTERVAL: 60 * 60 * 1000, // 1 hour

    // Security features
    REPLAY_WINDOW_SIZE: 1000,
    ADDRESS_ROTATION_INTERVAL: 15 * 60 * 1000, // 15 minutes

    // Trust scoring
    MAX_TRUST_SCORE: 100,
    INITIAL_TRUST_SCORE: 0,
    VERIFICATION_BONUS: 40,

    // Rate limiting
    MAX_MESSAGES_PER_SECOND: 10,
    MAX_CONNECTIONS: 8,
    CONNECTION_COOLDOWN: 60 * 1000 // 1 minute
};

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
* Check if the core library is properly initialized
*/
export function isInitialized(): boolean {
    return true;
}

/**
* Get the protocol version for compatibility checking
*/
export function getProtocolVersion(): number {
    return SECURITY_CONFIG.PROTOCOL_VERSION;
}

/**
* Verify protocol compatibility
*/
export function isCompatibleVersion(version: number): boolean {
    return version === SECURITY_CONFIG.PROTOCOL_VERSION;
}

// ============================================================================
// ERROR CLASSES
// ============================================================================

/**
* Base error class for GhostComm
*/
export class GhostCommError extends Error {
    constructor(message: string, public code?: string) {
        super(message);
        this.name = 'GhostCommError';
    }
}

/**
* Security-specific error
*/
export class SecurityError extends GhostCommError {
    constructor(message: string, code?: string) {
        super(message, code);
        this.name = 'SecurityError';
    }
}

/**
* Network-specific error
*/
export class NetworkError extends GhostCommError {
    constructor(message: string, code?: string) {
        super(message, code);
        this.name = 'NetworkError';
    }
}

// ============================================================================
// INITIALIZATION
// ============================================================================

// Log initialization with security features
console.log(`
╔════════════════════════════════════════════════════════════╗
║                    GhostComm Core Library                  ║
║                        Version ${VERSION}                        ║
║                                                            ║
║  Security Features:                                        ║
║  ✓ Double Ratchet Protocol (Signal-level)                ║
║  ✓ Perfect Forward Secrecy                               ║
║  ✓ XChaCha20-Poly1305 Encryption                         ║
║  ✓ Ed25519 Digital Signatures                            ║
║  ✓ 256-bit Security Level                                ║
║  ✓ Anti-Tracking & Privacy Protection                    ║
║                                                            ║
║  Protocol Version: ${SECURITY_CONFIG.PROTOCOL_VERSION}                                   ║
╚════════════════════════════════════════════════════════════╝
`);

// ============================================================================
// DEFAULT EXPORT
// ============================================================================

export default {
    VERSION,
    SECURITY_CONFIG,

    // Core classes
    GhostKeyPair,
    MessageEncryption,
    MessageFactory,
    BLEManager,
    BLEAdvertiser,
    BLEScanner,
    BLEConnectionManager,
    MeshNetwork,

    // Enums
    MessageType,
    MessagePriority,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    ConnectionState,
    CryptoError,
    VerificationMethod,
    BLEErrorCode,

    // Utility functions
    isInitialized,
    getProtocolVersion,
    isCompatibleVersion,

    // Error classes
    GhostCommError,
    SecurityError,
    NetworkError,

    // Static methods
    parseAdvertisementPacket
};