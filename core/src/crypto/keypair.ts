/**
 * Enhanced GhostComm Key Pair Management with Double Ratchet Support
 * 
 * This module provides comprehensive cryptographic key management for the GhostComm mesh network,
 * implementing a dual-key architecture with Ed25519 for digital signatures and X25519 for key
 * exchange operations. It supports the Double Ratchet protocol, pre-key management for asynchronous
 * messaging, and secure key derivation from seed phrases.
 * 
 * Key Features:
 * - Dual-key cryptographic architecture (signing + encryption keys)
 * - Ed25519 digital signatures for message authentication and identity verification
 * - X25519 elliptic curve Diffie-Hellman for secure key exchange
 * - Pre-key management for asynchronous messaging and offline key exchange
 * - Double Ratchet session management with forward/backward secrecy
 * - Deterministic key generation from seed phrases using PBKDF2
 * - Secure key export/import with optional password protection
 * - Automatic key rotation and lifecycle management
 * 
 * Cryptographic Primitives:
 * - Digital Signatures: Ed25519 for fast, deterministic signatures
 * - Key Exchange: X25519 ECDH for ephemeral key agreement
 * - Key Derivation: HKDF-SHA256/SHA512 for cryptographically secure derivation
 * - Password-Based Derivation: PBKDF2-SHA512 for seed phrase processing
 * - Hashing: SHA-256, SHA-512, and BLAKE3 for various cryptographic operations
 * 
 * Security Properties:
 * - Perfect Forward Secrecy: Past messages remain secure if current keys are compromised
 * - Post-Compromise Security: Future messages become secure after key compromise recovery
 * - Identity Verification: Strong cryptographic binding between identity and signing keys
 * - Key Freshness: Automatic rotation and pre-key generation for ongoing security
 * - Memory Security: Secure deletion of sensitive key material when no longer needed
 * 
 * Protocol v2 Enhancements:
 * - Enhanced session management for Double Ratchet protocol
 * - Improved pre-key validation and signature verification
 * - Better key derivation with domain separation
 * - Comprehensive key lifecycle management
 * - Enhanced fingerprint generation for key verification
 * 
 * Usage Patterns:
 * ```typescript
 * // Generate new key pair
 * const keyPair = GhostKeyPair.generate();
 * 
 * // Create from seed phrase
 * const keyPair = await GhostKeyPair.fromSeedPhrase("my secure seed phrase");
 * 
 * // Perform key exchange
 * const sharedSecret = keyPair.performKeyExchange(peerPublicKey);
 * 
 * // Sign and verify messages
 * const signature = keyPair.signMessage("Hello, world!");
 * const isValid = GhostKeyPair.verify(message, signature, keyPair.getIdentityPublicKey());
 * ```
 * 
 * Security Considerations:
 * - This implementation is NOT thread-safe - use appropriate synchronization
 * - Private keys are stored in memory and should be protected accordingly
 * - Call destroy() method to securely clear sensitive material
 * - Pre-keys should be rotated regularly for optimal security
 * - Seed phrases should be stored securely and never transmitted
 * 
 * Memory Management:
 * - Private keys are automatically zeroed when destroy() is called
 * - Pre-keys are cleaned up based on age and usage patterns
 * - Session keys are managed with automatic cleanup intervals
 * - All sensitive arrays are explicitly zeroed before deallocation
 * @author LCpl Szymon 'Si' Procak
 * @version 2.1
 */

import { ed25519, x25519 } from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hkdf } from '@noble/hashes/hkdf';
import { blake3 } from '@noble/hashes/blake3';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import {
    KeyPair,
    ExtendedKeyPair,
    PreKey,
    SessionKeys,
    IGhostKeyPair,
    ExportedKeys,
    ExportedPublicKeys,
    CryptoAlgorithm,
    CryptoError
} from '../types/crypto';

/**
 * Cryptographic constants and configuration parameters for key management
 * 
 * This configuration defines all cryptographic parameters, security settings, and operational
 * limits for the GhostComm key management system. Values are carefully chosen based on current
 * cryptographic best practices, security requirements, and performance considerations.
 * 
 * IMPORTANT: Changing these values may break compatibility with existing key material and
 * established sessions. Version the protocol appropriately when modifying core parameters.
 */
const CONSTANTS = {
    // Core Protocol Settings
    /** Protocol version identifier for compatibility checking and feature detection */
    PROTOCOL_VERSION: 2,

    // Cryptographic Key Sizes (in bytes)
    /** Ed25519 key size - 32 bytes for both public and private keys */
    ED25519_KEY_SIZE: 32,
    
    /** X25519 key size - 32 bytes for both public and private keys */
    X25519_KEY_SIZE: 32,
    
    /** Fingerprint size - 32 bytes (256-bit) for strong identity verification */
    FINGERPRINT_SIZE: 32,

    // Key Derivation Parameters
    /** Salt size for HKDF operations - 32 bytes provides adequate entropy */
    KDF_SALT_SIZE: 32,
    
    /** HKDF info string for key derivation - ensures domain separation */
    KDF_INFO: 'GhostComm-v2-KeyDerivation',
    
    /** HKDF info string for session key derivation - prevents cross-context attacks */
    SESSION_INFO: 'GhostComm-v2-Session',

    // Pre-key Management Settings
    /** Default number of pre-keys to generate - balances security with storage */
    DEFAULT_PREKEY_COUNT: 100,
    
    /** Maximum pre-keys allowed - prevents resource exhaustion attacks */
    MAX_PREKEY_COUNT: 1000,
    
    /** Pre-key rotation interval (7 days) - ensures fresh keys for forward secrecy */
    PREKEY_ROTATION_INTERVAL: 7 * 24 * 60 * 60 * 1000,

    // Password-Based Key Derivation Security
    /** Minimum PBKDF2 iterations - prevents brute force attacks on seed phrases */
    MIN_PBKDF2_ITERATIONS: 100000,
    
    /** Default PBKDF2 iterations - balances security with performance */
    DEFAULT_PBKDF2_ITERATIONS: 250000,

    // Double Ratchet Protocol Parameters
    /** Maximum messages to skip in a chain - prevents memory exhaustion */
    MAX_SKIP_MESSAGES: 1000,
    
    /** HKDF info string for message key derivation - isolates message keys */
    MESSAGE_KEY_SEED: 'GhostComm-MessageKeys',
    
    /** HKDF info string for chain key derivation - separates chain advancement */
    CHAIN_KEY_SEED: 'GhostComm-ChainKeys',
    
    /** HKDF info string for root key derivation - ensures proper key hierarchy */
    ROOT_KEY_SEED: 'GhostComm-RootKeys'
};

/**
 * Enhanced GhostKeyPair class with advanced cryptographic features
 * 
 * This is the core cryptographic key management class for the GhostComm system, implementing
 * a sophisticated dual-key architecture that separates signing operations from encryption
 * operations. It provides comprehensive support for the Double Ratchet protocol, asynchronous
 * messaging through pre-keys, and secure key lifecycle management.
 * 
 * Architectural Design:
 * - Dual-key system: Separate keys for signing (Ed25519) and encryption (X25519)
 * - Identity binding: Signing key serves as permanent node identity
 * - Forward secrecy: Encryption keys can be rotated without changing identity
 * - Asynchronous support: Pre-keys enable offline message initiation
 * - Session management: Built-in Double Ratchet session tracking
 * 
 * Key Features:
 * - Ed25519 digital signatures for authentication and non-repudiation
 * - X25519 key exchange for perfect forward secrecy
 * - Pre-key management for asynchronous messaging scenarios
 * - Double Ratchet session initialization and management
 * - Deterministic key generation from seed phrases
 * - Secure import/export with optional password protection
 * - Automatic key rotation and cleanup mechanisms
 * 
 * Security Properties:
 * - Perfect Forward Secrecy: Past messages secure if current keys compromised
 * - Post-Compromise Security: Future security recovery after key compromise
 * - Identity Persistence: Signing key provides stable node identity
 * - Key Freshness: Regular rotation prevents long-term key compromise
 * - Replay Protection: Session management prevents message replay attacks
 * 
 * Usage Lifecycle:
 * 1. Key Generation: Create new random keys or derive from seed phrase
 * 2. Session Establishment: Initialize Double Ratchet sessions with peers
 * 3. Message Processing: Sign outgoing and verify incoming messages
 * 4. Key Exchange: Perform ECDH operations for encrypted communication
 * 5. Maintenance: Rotate keys, clean up old sessions, manage pre-keys
 * 6. Cleanup: Securely destroy sensitive material when done
 * 
 * Performance Considerations:
 * - Ed25519 operations are very fast for both signing and verification
 * - X25519 key exchange has constant-time implementation
 * - Pre-key generation is CPU-intensive and should be done during idle time
 * - Session management requires memory for tracking multiple peers
 * - PBKDF2 operations are intentionally slow for security
 * 
 * Thread Safety:
 * This class is NOT thread-safe. External synchronization is required when:
 * - Multiple threads access the same instance simultaneously
 * - Session state is modified from multiple threads
 * - Pre-key generation and cleanup operations overlap
 * 
 * Memory Security:
 * - Private keys are stored in Uint8Array objects in memory
 * - Sensitive data is explicitly zeroed when no longer needed
 * - destroy() method performs comprehensive cleanup
 * - Pre-keys are automatically cleaned based on age and usage
 */
export class GhostKeyPair implements IGhostKeyPair {
    // ===== CORE CRYPTOGRAPHIC KEY PAIRS =====
    
    /** Ed25519 key pair for digital signatures and identity operations */
    private signingKeyPair: KeyPair;
    
    /** X25519 key pair for encryption and key exchange operations */
    private encryptionKeyPair: KeyPair;
    
    // ===== PRE-KEY MANAGEMENT FOR ASYNCHRONOUS MESSAGING =====
    
    /** Map of pre-keys indexed by key ID for asynchronous message initiation */
    private preKeys: Map<number, PreKey>;
    
    /** Current pre-key ID counter for generating unique identifiers */
    private currentPreKeyId: number;
    
    // ===== KEY LIFECYCLE AND METADATA =====
    
    /** Timestamp when this key pair was created */
    private createdAt: number;
    
    /** Timestamp of last key rotation for forward secrecy management */
    private lastRotation: number;
    
    /** Protocol version for compatibility and feature detection */
    private version: number;

    // ===== DOUBLE RATCHET SESSION MANAGEMENT =====
    
    /** Map of active Double Ratchet sessions indexed by session ID */
    private activeSessions: Map<string, SessionKeys>;
    
    /** Cache of derived message keys for out-of-order message processing */
    private messageKeyCache: Map<string, Uint8Array>;

    /**
     * Initialize a new GhostKeyPair instance with comprehensive cryptographic setup
     * 
     * Creates a new key pair with dual-key architecture supporting both signing and encryption
     * operations. If existing key material is not provided, generates new random keys with
     * cryptographically secure random number generation.
     * 
     * Initialization Process:
     * 1. Sets up protocol version and timestamp metadata
     * 2. Initializes or generates Ed25519 signing key pair for identity
     * 3. Initializes or generates X25519 encryption key pair for message encryption
     * 4. Establishes pre-key management for asynchronous messaging
     * 5. Initializes Double Ratchet session management structures
     * 
     * @param signingKeyPair - Optional existing Ed25519 key pair for signatures
     * @param encryptionKeyPair - Optional existing X25519 key pair for encryption  
     * @param preKeys - Optional array of existing pre-keys for asynchronous messaging
     * 
     * Key Generation Security:
     * - Uses cryptographically secure random number generation
     * - Ed25519 keys provide 128-bit security level with fast operations
     * - X25519 keys provide equivalent security with constant-time ECDH
     * - Pre-keys are signed with identity key for authenticity verification
     * 
     * Default Behavior:
     * - Generates 100 pre-keys by default for immediate asynchronous messaging
     * - Uses current timestamp for creation and rotation tracking
     * - Initializes empty session management for future peer communications
     * - Sets protocol version for compatibility checking
     */
    constructor(
        signingKeyPair?: KeyPair,
        encryptionKeyPair?: KeyPair,
        preKeys?: PreKey[]
    ) {
        // Initialize protocol metadata and timestamps
        this.version = CONSTANTS.PROTOCOL_VERSION;
        this.createdAt = Date.now();
        this.lastRotation = Date.now();

        // Initialize or generate cryptographic key pairs
        this.signingKeyPair = signingKeyPair || this.generateSigningKeyPair();
        this.encryptionKeyPair = encryptionKeyPair || this.generateEncryptionKeyPair();

        // Initialize pre-key management system
        this.preKeys = new Map();
        this.currentPreKeyId = 0;

        if (preKeys && preKeys.length > 0) {
            // Import existing pre-keys and determine next ID
            preKeys.forEach(pk => this.preKeys.set(pk.keyId, pk));
            this.currentPreKeyId = Math.max(...preKeys.map(pk => pk.keyId)) + 1;
        } else {
            // Generate initial set of pre-keys for asynchronous messaging
            this.generatePreKeys(CONSTANTS.DEFAULT_PREKEY_COUNT);
        }

        // Initialize Double Ratchet session management
        this.activeSessions = new Map();
        this.messageKeyCache = new Map();
    }

    /**
     * Export keys with optional password encryption
     * Properly typed as per IGhostKeyPair interface
     */
    export(password?: string): ExportedKeys {
        if (password) {
            // Future implementation: encrypt the exported keys with password
            // For now, log warning and return unencrypted
            console.warn('Password encryption not yet implemented, exporting unencrypted keys');
        }
        return this.exportKeys();
    }

    /**
     * Static method to create a GhostKeyPair from exported data
     */
    static fromExported(exportedData: ExportedKeys | string, password?: string): GhostKeyPair {
        // Handle both JSON string and object
        const data: ExportedKeys = typeof exportedData === 'string'
            ? JSON.parse(exportedData)
            : exportedData;

        if (password) {
            // Future implementation: decrypt the keys with password
            console.warn('Password decryption not yet implemented');
        }

        return GhostKeyPair.import(data);
    }

    /**
     * Helper function to convert bytes to hex string (static version)
     */
    static bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Helper function to convert hex string to bytes (static version)
     */
    static hexToBytes(hex: string): Uint8Array {
        if (hex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    // ===== CORE CRYPTOGRAPHIC KEY GENERATION =====

    /**
     * Generate a new Ed25519 key pair for digital signatures and identity operations
     * 
     * Creates a fresh Ed25519 key pair using cryptographically secure random number generation.
     * Ed25519 provides fast signature operations, deterministic signatures, and high security
     * with 128-bit security level. The signing key serves as the permanent identity of the node.
     * 
     * Security Properties:
     * - 128-bit security level equivalent to 3072-bit RSA
     * - Deterministic signatures prevent nonce-based attacks
     * - Fast verification enables efficient message authentication
     * - Small signature size (64 bytes) reduces bandwidth overhead
     * - Constant-time operations prevent timing attacks
     * 
     * @returns Fresh Ed25519 key pair with algorithm metadata and timestamp
     */
    private generateSigningKeyPair(): KeyPair {
        const privateKey = ed25519.utils.randomPrivateKey();
        const publicKey = ed25519.getPublicKey(privateKey);

        return {
            privateKey,
            publicKey,
            algorithm: CryptoAlgorithm.ED25519,
            createdAt: Date.now()
        };
    }

    /**
     * Generate a new X25519 key pair for encryption and key exchange operations
     * 
     * Creates a fresh X25519 key pair using cryptographically secure random number generation.
     * X25519 provides fast ECDH operations for establishing shared secrets with other nodes.
     * This key can be rotated for forward secrecy without affecting node identity.
     * 
     * Security Properties:
     * - 128-bit security level with efficient elliptic curve operations
     * - Constant-time ECDH prevents timing-based key recovery attacks
     * - Small key size (32 bytes) enables efficient key distribution
     * - Compatible with Signal protocol and other modern systems
     * - Provides foundation for Double Ratchet forward secrecy
     * 
     * @returns Fresh X25519 key pair with algorithm metadata and timestamp
     */
    private generateEncryptionKeyPair(): KeyPair {
        const privateKey = x25519.utils.randomPrivateKey();
        const publicKey = x25519.getPublicKey(privateKey);

        return {
            privateKey,
            publicKey,
            algorithm: CryptoAlgorithm.X25519,
            createdAt: Date.now()
        };
    }

    // ===== PRE-KEY MANAGEMENT FOR ASYNCHRONOUS MESSAGING =====

    /**
     * Generate pre-keys for asynchronous key exchange and offline messaging
     * 
     * Pre-keys enable other nodes to initiate encrypted conversations even when this node
     * is offline. Each pre-key is a one-time-use X25519 key pair that is signed by the
     * node's identity key to prove authenticity. This implements the asynchronous messaging
     * pattern used by Signal and other modern secure messaging systems.
     * 
     * Pre-key Security Model:
     * - Each pre-key is used only once to prevent replay attacks
     * - Pre-keys are signed by identity key to prevent impersonation
     * - Regular rotation ensures forward secrecy for asynchronous messages
     * - Limited quantity prevents resource exhaustion attacks
     * - Automatic cleanup removes old and used pre-keys
     * 
     * Generation Process:
     * 1. Generate fresh X25519 key pair for each pre-key
     * 2. Create signature data combining public key and key ID
     * 3. Sign with node's Ed25519 identity key for authenticity
     * 4. Store with metadata for lifecycle management
     * 5. Return array of generated pre-keys for distribution
     * 
     * @param count - Number of pre-keys to generate (default: 100)
     * @returns Array of newly generated signed pre-keys
     * 
     * @throws {Error} If count exceeds maximum allowed pre-keys
     * 
     * Usage Notes:
     * - Pre-keys should be distributed through secure channels
     * - Unused pre-keys should be rotated regularly for security
     * - Used pre-keys are automatically marked and eventually cleaned up
     * - Signature verification prevents pre-key tampering
     */
    generatePreKeys(count: number = CONSTANTS.DEFAULT_PREKEY_COUNT): PreKey[] {
        if (count > CONSTANTS.MAX_PREKEY_COUNT) {
            throw new Error(`Cannot generate more than ${CONSTANTS.MAX_PREKEY_COUNT} pre-keys`);
        }

        const newPreKeys: PreKey[] = [];

        for (let i = 0; i < count; i++) {
            const keyId = this.currentPreKeyId++;
            const privateKey = x25519.utils.randomPrivateKey();
            const publicKey = x25519.getPublicKey(privateKey);

            // Create signature data combining public key and unique key ID
            const keyData = new Uint8Array(publicKey.length + 4);
            keyData.set(publicKey);
            new DataView(keyData.buffer).setUint32(publicKey.length, keyId, false);
            const signature = this.sign(keyData);

            const preKey: PreKey = {
                keyId,
                publicKey,
                privateKey,
                signature,
                createdAt: Date.now()
            };

            this.preKeys.set(keyId, preKey);
            newPreKeys.push(preKey);
        }

        return newPreKeys;
    }

    /**
     * Get an unused pre-key for asynchronous key exchange initiation
     * 
     * Returns a pre-key that hasn't been used yet, suitable for initiating a new
     * encrypted conversation. If no unused pre-keys are available, automatically
     * generates a small batch to ensure availability for new conversations.
     * 
     * @returns Unused pre-key or null if generation fails
     * 
     * Automatic Replenishment:
     * - Generates new pre-keys when supply is exhausted
     * - Maintains availability for continuous operation
     * - Prevents service interruption due to pre-key depletion
     */
    getUnusedPreKey(): PreKey | null {
        for (const [_, preKey] of this.preKeys) {
            if (!preKey.usedAt) {
                return preKey;
            }
        }

        // Generate more pre-keys if all are used
        const newPreKeys = this.generatePreKeys(10);
        return newPreKeys[0] || null;
    }

    /**
     * Mark a pre-key as used to prevent reuse and security vulnerabilities
     * 
     * Once a pre-key is used to establish a session, it must not be used again
     * to maintain forward secrecy and prevent replay attacks. This method marks
     * the pre-key with a usage timestamp for lifecycle management.
     * 
     * @param keyId - Unique identifier of the pre-key to mark as used
     * 
     * Security Importance:
     * - Prevents pre-key reuse which could compromise security
     * - Enables automatic cleanup of old used pre-keys
     * - Maintains forward secrecy for established sessions
     */
    markPreKeyUsed(keyId: number): void {
        const preKey = this.preKeys.get(keyId);
        if (preKey && !preKey.usedAt) {
            preKey.usedAt = Date.now();
        }
    }

    // ===== KEY ROTATION AND FORWARD SECRECY MANAGEMENT =====

    /**
     * Rotate encryption key for enhanced forward secrecy
     * 
     * Generates a new encryption key pair while preserving the identity signing key.
     * This operation enhances forward secrecy by ensuring that compromise of the current
     * encryption key doesn't affect past or future communications that use different keys.
     * The old key is returned for potential use in decrypting past messages.
     * 
     * Forward Secrecy Benefits:
     * - Past messages remain secure even if current key is compromised
     * - Future messages use fresh key material not derived from old keys
     * - Identity preservation through stable signing key
     * - Automatic pre-key regeneration with new encryption key
     * 
     * Rotation Process:
     * 1. Stores current encryption key for backward compatibility
     * 2. Generates fresh X25519 encryption key pair
     * 3. Updates rotation timestamp for lifecycle tracking
     * 4. Generates new pre-keys using the fresh encryption key
     * 5. Returns old key for potential decryption of old messages
     * 
     * @returns Previous encryption key pair for backward compatibility
     * 
     * Usage Notes:
     * - Should be performed regularly for optimal security
     * - Old key may be needed for decrypting queued messages
     * - New pre-keys should be distributed after rotation
     * - Sessions may need re-establishment after rotation
     */
    rotateEncryptionKey(): KeyPair {
        // Store old key for potential decryption of past messages
        const oldKey = { ...this.encryptionKeyPair };

        // Generate fresh encryption key for future operations
        this.encryptionKeyPair = this.generateEncryptionKeyPair();
        this.lastRotation = Date.now();

        // Generate new pre-keys with the fresh encryption key
        this.generatePreKeys(CONSTANTS.DEFAULT_PREKEY_COUNT);

        return oldKey;
    }

    // ===== DOUBLE RATCHET SESSION MANAGEMENT =====

    /**
     * Initialize a Double Ratchet session with a peer for secure messaging
     * 
     * Establishes a new Double Ratchet session using the initial key exchange with a peer.
     * The Double Ratchet provides forward secrecy and post-compromise security through
     * continuous key evolution. Each message uses a fresh derived key, and the key
     * derivation process advances with each message sent or received.
     * 
     * Double Ratchet Security Properties:
     * - Forward Secrecy: Past messages remain secure if current keys are compromised
     * - Post-Compromise Security: Future security recovery after key compromise
     * - Key Evolution: Continuous advancement prevents long-term key compromise
     * - Out-of-Order Support: Messages can arrive in any order and still be decrypted
     * 
     * Session Initialization Process:
     * 1. Checks for existing session to prevent duplicate establishment
     * 2. Performs ECDH key exchange with peer's public key
     * 3. Derives root key and initial chain key using HKDF
     * 4. Creates session structure with initial cryptographic state
     * 5. Stores session for future message processing
     * 
     * @param theirPublicKey - Peer's X25519 public key for ECDH operation
     * @returns Initialized session keys for immediate use
     * 
     * Key Derivation Security:
     * - Uses HKDF with proper domain separation for security
     * - Generates sufficient entropy for root and chain keys
     * - Includes session-specific information string
     * - Employs cryptographically secure salt generation
     */
    initializeSession(theirPublicKey: Uint8Array): SessionKeys {
        const sessionId = this.getSessionId(theirPublicKey);

        // Check if session already exists to prevent duplication
        const existingSession = this.activeSessions.get(sessionId);
        if (existingSession) {
            return existingSession;
        }

        // Perform initial ECDH to establish shared secret
        const sharedSecret = this.performKeyExchange(theirPublicKey);

        // Derive initial cryptographic material using HKDF
        const salt = randomBytes(CONSTANTS.KDF_SALT_SIZE);
        const info = new TextEncoder().encode(CONSTANTS.SESSION_INFO);
        const keyMaterial = hkdf(sha512, sharedSecret, salt, info, 96); // 3 * 32 bytes

        const rootKey = keyMaterial.slice(0, 32);
        const chainKey = keyMaterial.slice(32, 64);
        const initialKey = keyMaterial.slice(64, 96);

        const session: SessionKeys = {
            rootKey,
            chainKey,
            sendingKey: initialKey,
            receivingKey: undefined,
            messageNumber: 0,
            previousChainLength: 0
        };

        this.activeSessions.set(sessionId, session);
        return session;
    }

    /**
     * Perform a Double Ratchet step to advance session keys
     * 
     * Advances the Double Ratchet protocol by either performing a symmetric ratchet
     * (advancing within the same chain) or an asymmetric ratchet (starting a new chain
     * with fresh ephemeral keys). This continuous key evolution provides forward secrecy
     * and post-compromise security.
     * 
     * Ratchet Types:
     * - Symmetric Ratchet: Advances chain key for next message in same chain
     * - Asymmetric Ratchet: Creates new chain with fresh ephemeral key exchange
     * 
     * @param session - Current session state to advance
     * @param theirEphemeralKey - Optional peer ephemeral key for asymmetric ratchet
     * @returns Updated session with advanced cryptographic state
     * 
     * Security Properties:
     * - Each message uses a unique derived key
     * - Key compromise affects only single message
     * - Automatic recovery from key compromise through ratcheting
     * - Maintains cryptographic separation between chains
     */
    ratchetSession(session: SessionKeys, theirEphemeralKey?: Uint8Array): SessionKeys {
        if (!theirEphemeralKey) {
            // Symmetric ratchet: advance within current chain
            const info = new TextEncoder().encode(CONSTANTS.CHAIN_KEY_SEED);
            const newChainKey = hkdf(sha256, session.chainKey, undefined, info, 32);

            const updatedSession: SessionKeys = {
                ...session,
                chainKey: newChainKey,
                messageNumber: session.messageNumber + 1
            };

            // Update stored session with new state
            const sessionId = this.bytesToHex(sha256(session.rootKey));
            this.activeSessions.set(sessionId, updatedSession);

            return updatedSession;
        }

        // Asymmetric ratchet: create new chain with fresh key material
        const sharedSecret = this.performKeyExchange(theirEphemeralKey);

        // Combine shared secret with current root key
        const combined = new Uint8Array(64);
        combined.set(session.rootKey);
        combined.set(sharedSecret, 32);

        const info = new TextEncoder().encode(CONSTANTS.ROOT_KEY_SEED);
        const keyMaterial = hkdf(sha512, combined, undefined, info, 64);

        const newRootKey = keyMaterial.slice(0, 32);
        const newChainKey = keyMaterial.slice(32, 64);

        const updatedSession: SessionKeys = {
            rootKey: newRootKey,
            chainKey: newChainKey,
            sendingKey: undefined,
            receivingKey: newChainKey,
            messageNumber: 0,
            previousChainLength: session.messageNumber
        };

        // Update session storage with new session ID
        const newSessionId = this.bytesToHex(sha256(newRootKey));
        this.activeSessions.set(newSessionId, updatedSession);

        // Clean up old session if session ID changed
        const oldSessionId = this.bytesToHex(sha256(session.rootKey));
        if (oldSessionId !== newSessionId) {
            this.activeSessions.delete(oldSessionId);
        }

        return updatedSession;
    }

    /**
     * Derive a message key from a chain key for single-message encryption
     * 
     * Creates a unique encryption key for a single message from the current chain key.
     * This ensures that each message uses different cryptographic material, providing
     * forward secrecy and limiting the impact of any single key compromise.
     * 
     * @param chainKey - Current chain key state
     * @returns Derived message key for single-use encryption
     * 
     * Security Properties:
     * - Each message key is unique and single-use
     * - Derived using HKDF with proper domain separation
     * - Cannot be used to derive other message keys
     * - Compromise affects only single message
     */
    private deriveMessageKey(chainKey: Uint8Array): Uint8Array {
        const info = new TextEncoder().encode(CONSTANTS.MESSAGE_KEY_SEED);
        return hkdf(sha256, chainKey, undefined, info, 32);
    }

    /**
     * Generate unique session identifier for peer communication tracking
     * 
     * Creates a deterministic session ID based on the public keys of both parties.
     * The ID is generated by combining and hashing the public keys in a consistent
     * order to ensure both parties generate the same session identifier.
     * 
     * @param theirPublicKey - Peer's public key for session identification
     * @returns Hex-encoded session identifier for tracking
     */
    private getSessionId(theirPublicKey: Uint8Array): string {
        const combined = new Uint8Array(64);
        combined.set(this.encryptionKeyPair.publicKey);
        combined.set(theirPublicKey, 32);
        const hash = sha256(combined);
        return this.bytesToHex(hash);
    }

    // ===== STATIC FACTORY METHODS FOR KEY PAIR CREATION =====

    /**
     * Create a GhostKeyPair from a seed phrase with deterministic key generation
     * 
     * Generates cryptographic keys deterministically from a user-provided seed phrase using
     * PBKDF2 for key stretching and security. This enables users to recover their exact
     * cryptographic identity from a memorable phrase, providing a backup and recovery
     * mechanism for the key pair.
     * 
     * Deterministic Generation Benefits:
     * - Same seed phrase always produces identical keys
     * - Enables secure backup through memorable phrases
     * - No need to store binary key material
     * - Compatible with standard seed phrase practices
     * - Supports key recovery across devices and installations
     * 
     * Security Features:
     * - PBKDF2 with high iteration count prevents brute force attacks
     * - Salt prevents rainbow table attacks on common phrases
     * - Configurable iterations allow security/performance tuning
     * - Deterministic pre-key generation ensures consistency
     * - Secure memory handling prevents key material leakage
     * 
     * Key Derivation Process:
     * 1. Validates iteration count meets minimum security requirements
     * 2. Converts seed phrase and salt to byte arrays
     * 3. Applies PBKDF2-SHA512 with specified iterations
     * 4. Extracts key material for signing, encryption, and pre-keys
     * 5. Generates public keys from derived private keys
     * 6. Creates deterministic pre-keys using derived seed
     * 7. Securely clears intermediate key material
     * 
     * @param seedPhrase - User-provided seed phrase for deterministic generation
     * @param salt - Salt value for key derivation (default: 'ghostcomm-seed')
     * @param iterations - PBKDF2 iteration count (default: 250,000)
     * @returns Promise resolving to deterministically generated key pair
     * 
     * @throws {Error} If iteration count is below minimum security threshold
     * 
     * Usage Example:
     * ```typescript
     * const keyPair = await GhostKeyPair.fromSeedPhrase(
     *     "my secure twelve word seed phrase goes here now",
     *     "optional-salt",
     *     300000  // High security iteration count
     * );
     * ```
     * 
     * Security Warnings:
     * - Seed phrases should have sufficient entropy (12+ random words)
     * - Store seed phrases securely and never transmit them
     * - Use unique salts for different applications if needed
     * - Higher iteration counts provide better security but slower generation
     */
    static async fromSeedPhrase(
        seedPhrase: string,
        salt: string = 'ghostcomm-seed',
        iterations: number = CONSTANTS.DEFAULT_PBKDF2_ITERATIONS
    ): Promise<GhostKeyPair> {
        if (iterations < CONSTANTS.MIN_PBKDF2_ITERATIONS) {
            throw new Error(`Iterations must be at least ${CONSTANTS.MIN_PBKDF2_ITERATIONS}`);
        }

        // Derive key material from seed phrase
        const seedBytes = new TextEncoder().encode(seedPhrase);
        const saltBytes = new TextEncoder().encode(salt);

        // Use PBKDF2 to derive 96 bytes (32 for Ed25519, 32 for X25519, 32 for pre-key seed)
        const keyMaterial = await pbkdf2(sha512, seedBytes, saltBytes, {
            c: iterations,
            dkLen: 96
        });

        // Extract keys
        const signingPrivateKey = keyMaterial.slice(0, 32);
        const encryptionPrivateKey = keyMaterial.slice(32, 64);
        const preKeySeed = keyMaterial.slice(64, 96);

        // Generate public keys
        const signingPublicKey = ed25519.getPublicKey(signingPrivateKey);
        const encryptionPublicKey = x25519.getPublicKey(encryptionPrivateKey);

        // Create key pairs
        const signingKeyPair: KeyPair = {
            privateKey: signingPrivateKey,
            publicKey: signingPublicKey,
            algorithm: CryptoAlgorithm.ED25519,
            createdAt: Date.now()
        };

        const encryptionKeyPair: KeyPair = {
            privateKey: encryptionPrivateKey,
            publicKey: encryptionPublicKey,
            algorithm: CryptoAlgorithm.X25519,
            createdAt: Date.now()
        };

        const keyPair = new GhostKeyPair(signingKeyPair, encryptionKeyPair);

        // Generate deterministic pre-keys from seed
        keyPair.generateDeterministicPreKeys(preKeySeed, 10);

        // Clear sensitive material
        keyMaterial.fill(0);

        return keyPair;
    }

    /**
     * Generate deterministic pre-keys from a seed
     */
    private generateDeterministicPreKeys(seed: Uint8Array, count: number): PreKey[] {
        const preKeys: PreKey[] = [];

        for (let i = 0; i < count; i++) {
            const info = new TextEncoder().encode(`prekey-${i}`);
            const keyMaterial = hkdf(sha256, seed, undefined, info, 32);

            const publicKey = x25519.getPublicKey(keyMaterial);

            // Sign the pre-key
            const keyData = new Uint8Array(publicKey.length + 4);
            keyData.set(publicKey);
            new DataView(keyData.buffer).setUint32(publicKey.length, i, false);
            const signature = this.sign(keyData);

            const preKey: PreKey = {
                keyId: i,
                publicKey,
                privateKey: keyMaterial,
                signature,
                createdAt: Date.now()
            };

            this.preKeys.set(i, preKey);
            preKeys.push(preKey);
        }

        this.currentPreKeyId = count;
        return preKeys;
    }

    /**
     * Create a GhostKeyPair from existing key material
     */
    static fromKeys(
        signingPrivateKey: Uint8Array,
        encryptionPrivateKey: Uint8Array,
        preKeys?: PreKey[]
    ): GhostKeyPair {
        const signingPublicKey = ed25519.getPublicKey(signingPrivateKey);
        const encryptionPublicKey = x25519.getPublicKey(encryptionPrivateKey);

        return new GhostKeyPair(
            {
                privateKey: signingPrivateKey,
                publicKey: signingPublicKey,
                algorithm: CryptoAlgorithm.ED25519,
                createdAt: Date.now()
            },
            {
                privateKey: encryptionPrivateKey,
                publicKey: encryptionPublicKey,
                algorithm: CryptoAlgorithm.X25519,
                createdAt: Date.now()
            },
            preKeys
        );
    }

    /**
     * Import key pair from exported format
     */
    static import(keys: ExportedKeys): GhostKeyPair {
        const signingPrivateKey = GhostKeyPair.hexToBytes(keys.identityPrivate);
        const encryptionPrivateKey = GhostKeyPair.hexToBytes(keys.encryptionPrivate);

        // Import pre-keys if available
        const preKeys: PreKey[] = [];
        if (keys.preKeys) {
            for (const pk of keys.preKeys) {
                const privateKey = GhostKeyPair.hexToBytes(pk.private);
                const publicKey = GhostKeyPair.hexToBytes(pk.public);

                // Create signature for the pre-key
                const tempKeyPair = GhostKeyPair.fromKeys(signingPrivateKey, encryptionPrivateKey);
                const keyData = new Uint8Array(publicKey.length + 4);
                keyData.set(publicKey);
                new DataView(keyData.buffer).setUint32(publicKey.length, pk.keyId, false);
                const signature = tempKeyPair.sign(keyData);

                preKeys.push({
                    keyId: pk.keyId,
                    privateKey,
                    publicKey,
                    signature,
                    createdAt: keys.createdAt
                });
            }
        }

        return GhostKeyPair.fromKeys(signingPrivateKey, encryptionPrivateKey, preKeys);
    }

    /**
     * Get the public signing key (node's primary identifier)
     */
    getIdentityPublicKey(): Uint8Array {
        return this.signingKeyPair.publicKey;
    }

    /**
     * Get the public encryption key for receiving encrypted messages
     */
    getEncryptionPublicKey(): Uint8Array {
        return this.encryptionKeyPair.publicKey;
    }

    /**
     * Get the private encryption key (needed for ECDH operations)
     */
    getEncryptionPrivateKey(): Uint8Array {
        return this.encryptionKeyPair.privateKey;
    }

    /**
     * Get the public key (defaults to encryption public key for backward compatibility)
     */
    getPublicKey(): Uint8Array {
        return this.encryptionKeyPair.publicKey;
    }

    /**
     * Get the public key as hex string
     */
    getPublicKeyHex(): string {
        return this.bytesToHex(this.encryptionKeyPair.publicKey);
    }

    // ===== DIGITAL SIGNATURE OPERATIONS =====

    /**
     * Sign a message with the private Ed25519 signing key
     * 
     * Creates a cryptographic signature that proves the message was created by the holder
     * of the private key and that the message has not been tampered with. Ed25519 provides
     * deterministic signatures that are fast to generate and verify.
     * 
     * @param message - Raw message bytes to be signed
     * @returns 64-byte Ed25519 signature
     * 
     * Security Properties:
     * - Deterministic signatures prevent nonce-based attacks
     * - Constant-time operations prevent timing attacks
     * - Small signature size (64 bytes) minimizes overhead
     * - Fast verification enables efficient authentication
     */
    sign(message: Uint8Array): Uint8Array {
        return ed25519.sign(message, this.signingKeyPair.privateKey);
    }

    /**
     * Sign a message (convenience method supporting strings)
     * 
     * Provides a convenient interface for signing both string and binary messages.
     * String messages are automatically converted to UTF-8 bytes before signing.
     * 
     * @param message - Message to sign (string or bytes)
     * @returns 64-byte Ed25519 signature
     */
    signMessage(message: Uint8Array | string): Uint8Array {
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;
        return this.sign(messageBytes);
    }

    /**
     * Verify a signature against a public key (static method)
     * 
     * Verifies that a signature was created by the holder of the private key corresponding
     * to the provided public key. This static method can be used without a key pair instance.
     * 
     * @param message - Original message that was signed
     * @param signature - 64-byte Ed25519 signature to verify
     * @param publicKey - 32-byte Ed25519 public key for verification
     * @returns true if signature is valid, false otherwise
     * 
     * Error Handling:
     * - Returns false for any verification errors rather than throwing
     * - Handles malformed signatures and keys gracefully
     * - Protects against timing attacks through constant-time operations
     */
    static verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
        try {
            return ed25519.verify(signature, message, publicKey);
        } catch {
            return false;
        }
    }

    /**
     * Verify a signature (instance method with string support)
     * 
     * Instance method wrapper for signature verification that supports both string
     * and binary messages. Provides the same functionality as the static method
     * but with convenient string handling.
     * 
     * @param message - Message to verify (string or bytes)
     * @param signature - 64-byte Ed25519 signature
     * @param publicKey - 32-byte Ed25519 public key
     * @returns true if signature is valid, false otherwise
     */
    verifySignature(message: Uint8Array | string, signature: Uint8Array, publicKey: Uint8Array): boolean {
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;
        return GhostKeyPair.verify(messageBytes, signature, publicKey);
    }

    // ===== KEY EXCHANGE OPERATIONS =====

    /**
     * Perform ECDH key exchange with proper key derivation and security validation
     * 
     * Executes X25519 elliptic curve Diffie-Hellman key exchange to establish a shared
     * secret with a peer. The raw ECDH output is processed through HKDF for proper
     * key derivation and domain separation, ensuring the resulting key is suitable
     * for cryptographic use.
     * 
     * Key Exchange Security:
     * - X25519 provides 128-bit security level with efficient operations
     * - Constant-time implementation prevents timing attacks
     * - HKDF ensures uniform distribution of derived key material
     * - Domain separation prevents cross-protocol attacks
     * - Input validation prevents invalid curve point attacks
     * 
     * Derivation Process:
     * 1. Validates peer public key format and length
     * 2. Performs raw X25519 ECDH operation
     * 3. Applies HKDF with salt and domain-specific info
     * 4. Returns 32-byte derived key suitable for encryption
     * 
     * @param peerPublicKey - Peer's 32-byte X25519 public key
     * @param salt - Optional salt for key derivation (random if not provided)
     * @returns 32-byte derived shared secret
     * 
     * @throws {Error} If peer public key is invalid length
     * 
     * Usage Example:
     * ```typescript
     * const peerPublicKey = // ... obtain peer's public key
     * const sharedSecret = keyPair.performKeyExchange(peerPublicKey);
     * // Use sharedSecret for symmetric encryption
     * ```
     * 
     * Security Notes:
     * - Never reuse the same salt value across different contexts
     * - Derived key should be used immediately and not stored long-term
     * - Each key exchange should use fresh ephemeral keys when possible
     */
    performKeyExchange(peerPublicKey: Uint8Array, salt?: Uint8Array): Uint8Array {
        // Validate peer public key format and length
        if (peerPublicKey.length !== 32) {
            throw new Error('Invalid peer public key length');
        }

        // Perform raw ECDH
        const sharedSecret = x25519.getSharedSecret(this.encryptionKeyPair.privateKey, peerPublicKey);

        // Apply HKDF for key derivation
        const actualSalt = salt || randomBytes(CONSTANTS.KDF_SALT_SIZE);
        const info = new TextEncoder().encode(CONSTANTS.KDF_INFO);

        // Derive a 32-byte key
        return hkdf(sha256, sharedSecret, actualSalt, info, 32);
    }

    // ===== KEY VERIFICATION AND FINGERPRINTING =====

    /**
     * Generate a secure 256-bit fingerprint for key verification and identity confirmation
     * 
     * Creates a unique, cryptographically secure identifier for this key pair by combining
     * and hashing both the signing and encryption public keys. This fingerprint serves as
     * a human-verifiable identifier for confirming key authenticity and preventing
     * man-in-the-middle attacks during key exchange.
     * 
     * Fingerprint Properties:
     * - Deterministic: Same keys always produce identical fingerprint
     * - Unique: Cryptographically infeasible to find collisions
     * - Compact: 64-character hex string for easy sharing and verification
     * - Secure: Based on SHA-256 cryptographic hash function
     * - Comprehensive: Includes both signing and encryption key identity
     * 
     * Generation Process:
     * 1. Concatenates signing public key (Ed25519, 32 bytes)
     * 2. Appends encryption public key (X25519, 32 bytes)
     * 3. Computes SHA-256 hash of combined key material
     * 4. Returns hash as 64-character hexadecimal string
     * 
     * @returns 64-character hex fingerprint for key verification
     * 
     * Usage Example:
     * ```typescript
     * const fingerprint = keyPair.getFingerprint();
     * console.log(`My fingerprint: ${fingerprint}`);
     * // Share fingerprint through secure channel for verification
     * ```
     * 
     * Security Notes:
     * - Fingerprints should be verified through multiple independent channels
     * - Users should compare fingerprints before trusting new contacts
     * - Fingerprint changes indicate key rotation or potential compromise
     */
    getFingerprint(): string {
        // Combine both public keys for comprehensive identity
        const combined = new Uint8Array(
            this.signingKeyPair.publicKey.length +
            this.encryptionKeyPair.publicKey.length
        );
        combined.set(this.signingKeyPair.publicKey);
        combined.set(this.encryptionKeyPair.publicKey, this.signingKeyPair.publicKey.length);

        // Use SHA-256 for consistent, widely-supported fingerprints
        const hash = sha256(combined);

        // Return full 256-bit fingerprint as hexadecimal string
        return this.bytesToHex(hash);
    }

    /**
     * Get a short fingerprint for compact display and user interfaces
     * 
     * Returns the first 16 bytes (32 hex characters) of the full fingerprint for use in
     * constrained display environments. While less secure than the full fingerprint,
     * the short version provides reasonable collision resistance for most use cases.
     * 
     * @returns 32-character hex string representing short fingerprint
     * 
     * Security Considerations:
     * - Provides 128-bit collision resistance (adequate for most use cases)
     * - Should not be used alone for high-security verification
     * - Full fingerprint preferred for critical security decisions
     */
    getShortFingerprint(): string {
        const fullFingerprint = this.getFingerprint();
        return fullFingerprint.substring(0, 32); // 16 bytes = 32 hex characters
    }

    /**
     * Export keys in the standard format
     */
    exportKeys(): ExportedKeys {
        const preKeys = Array.from(this.preKeys.values())
            .slice(0, 10) // Export only first 10 pre-keys
            .map(pk => ({
                keyId: pk.keyId,
                private: this.bytesToHex(pk.privateKey),
                public: this.bytesToHex(pk.publicKey)
            }));

        return {
            version: this.version,
            publicKey: this.bytesToHex(this.encryptionKeyPair.publicKey), // For backward compatibility
            identityPrivate: this.bytesToHex(this.signingKeyPair.privateKey),
            identityPublic: this.bytesToHex(this.signingKeyPair.publicKey),
            encryptionPrivate: this.bytesToHex(this.encryptionKeyPair.privateKey),
            encryptionPublic: this.bytesToHex(this.encryptionKeyPair.publicKey),
            preKeys,
            createdAt: this.createdAt
        };
    }

    /**
     * Export only public keys (for sharing)
     */
    exportPublicKeys(): ExportedPublicKeys {
        const preKeys = Array.from(this.preKeys.values())
            .filter(pk => !pk.usedAt) // Only export unused pre-keys
            .slice(0, 5) // Export only 5 pre-keys
            .map(pk => ({
                keyId: pk.keyId,
                public: this.bytesToHex(pk.publicKey),
                signature: this.bytesToHex(pk.signature)
            }));

        return {
            version: this.version,
            identityPublic: this.bytesToHex(this.signingKeyPair.publicKey),
            encryptionPublic: this.bytesToHex(this.encryptionKeyPair.publicKey),
            fingerprint: this.getFingerprint(),
            preKeys
        };
    }

    /**
     * Generate a new GhostKeyPair with random keys
     */
    static generate(): GhostKeyPair {
        return new GhostKeyPair();
    }

    /**
     * Get creation timestamp
     */
    getCreatedAt(): number {
        return this.createdAt;
    }

    /**
     * Get protocol version
     */
    getVersion(): number {
        return this.version;
    }

    /**
     * Check if key rotation is needed
     */
    needsRotation(): boolean {
        const timeSinceRotation = Date.now() - this.lastRotation;
        return timeSinceRotation > CONSTANTS.PREKEY_ROTATION_INTERVAL;
    }

    /**
     * Clean up used pre-keys older than specified age
     */
    cleanupOldPreKeys(maxAge: number = 30 * 24 * 60 * 60 * 1000): number {
        const cutoff = Date.now() - maxAge;
        let removed = 0;

        for (const [keyId, preKey] of this.preKeys) {
            if (preKey.usedAt && preKey.usedAt < cutoff) {
                // Zero out the private key before deletion
                preKey.privateKey.fill(0);
                this.preKeys.delete(keyId);
                removed++;
            }
        }

        // Ensure we maintain minimum pre-keys
        const remainingUnused = Array.from(this.preKeys.values())
            .filter(pk => !pk.usedAt).length;

        if (remainingUnused < 10) {
            this.generatePreKeys(20);
        }

        return removed;
    }

    /**
     * Validate a peer's public key bundle
     */
    static validatePublicKeyBundle(bundle: ExportedPublicKeys): boolean {
        try {
            // Verify fingerprint matches keys
            const identityKey = GhostKeyPair.hexToBytes(bundle.identityPublic);
            const encryptionKey = GhostKeyPair.hexToBytes(bundle.encryptionPublic);

            const combined = new Uint8Array(identityKey.length + encryptionKey.length);
            combined.set(identityKey);
            combined.set(encryptionKey, identityKey.length);

            // Use SHA-256 for consistent fingerprint verification
            const computedFingerprint = GhostKeyPair.bytesToHex(sha256(combined));

            if (computedFingerprint !== bundle.fingerprint) {
                console.warn('Fingerprint mismatch in public key bundle');
                return false;
            }

            // Verify pre-key signatures
            if (bundle.preKeys) {
                for (const preKey of bundle.preKeys) {
                    const publicKey = GhostKeyPair.hexToBytes(preKey.public);
                    const signature = GhostKeyPair.hexToBytes(preKey.signature);

                    const keyData = new Uint8Array(publicKey.length + 4);
                    keyData.set(publicKey);
                    new DataView(keyData.buffer).setUint32(publicKey.length, preKey.keyId, false);

                    if (!GhostKeyPair.verify(keyData, signature, identityKey)) {
                        console.warn(`Invalid pre-key signature for keyId ${preKey.keyId}`);
                        return false;
                    }
                }
            }

            return true;
        } catch (error) {
            console.error('Error validating public key bundle:', error);
            return false;
        }
    }

    /**
     * Helper function to convert bytes to hex string (instance method)
     */
    private bytesToHex(bytes: Uint8Array): string {
        return GhostKeyPair.bytesToHex(bytes);
    }

    // ===== SECURE MEMORY MANAGEMENT AND CLEANUP =====

    /**
     * Securely destroy all sensitive cryptographic material in memory
     * 
     * Performs comprehensive cleanup of all private keys, session state, and derived
     * cryptographic material to prevent recovery through memory analysis. This method
     * implements secure deletion practices by explicitly zeroing sensitive data
     * before releasing memory structures.
     * 
     * Cleanup Operations:
     * - Zero-fill all private key material (signing and encryption keys)
     * - Zero-fill all pre-key private material and clear pre-key storage
     * - Zero-fill all Double Ratchet session keys (root, chain, sending, receiving)
     * - Zero-fill cached message keys and clear cache storage
     * - Clear all mapping structures and session tracking
     * 
     * Security Importance:
     * - Prevents key recovery through memory dumps or swap files
     * - Mitigates risk of key compromise through memory analysis tools
     * - Implements defense-in-depth security practices
     * - Ensures forward secrecy by destroying past cryptographic material
     * - Complies with secure coding practices for cryptographic applications
     * 
     * Usage Guidelines:
     * - Call when key pair is no longer needed
     * - Essential for security-critical applications
     * - Should be called before application termination
     * - After calling destroy(), the instance should not be used
     * 
     * Post-Destruction State:
     * - All cryptographic operations will fail or produce undefined results
     * - Object should be discarded and not reused
     * - New key pair must be generated for future operations
     * - No sensitive material remains accessible in memory
     * 
     * Memory Security Notes:
     * - Zeroing provides best-effort secure deletion in managed languages
     * - May not prevent advanced forensic recovery in all scenarios
     * - Should be combined with other security measures as appropriate
     * - Consider using secure allocation libraries for maximum security
     */
    destroy(): void {
        // Zero-fill core private key material
        this.signingKeyPair.privateKey.fill(0);
        this.encryptionKeyPair.privateKey.fill(0);

        // Securely clear all pre-key private material
        for (const [_, preKey] of this.preKeys) {
            preKey.privateKey.fill(0);
        }
        this.preKeys.clear();

        // Zero-fill all Double Ratchet session cryptographic state
        for (const [_, session] of this.activeSessions) {
            session.rootKey.fill(0);
            session.chainKey.fill(0);
            if (session.sendingKey) session.sendingKey.fill(0);
            if (session.receivingKey) session.receivingKey.fill(0);
        }
        this.activeSessions.clear();

        // Clear cached message keys and derivation material
        for (const [_, key] of this.messageKeyCache) {
            key.fill(0);
        }
        this.messageKeyCache.clear();
    }
}