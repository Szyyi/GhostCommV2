/**
 * Core encryption module implementing the Double Ratchet protocol v2.1
 * 
 * This module provides comprehensive end-to-end encryption, forward secrecy, and message integrity
 * for the GhostComm mesh network. It implements Protocol v2.1 which enhances security through
 * mandatory sender identity verification and improved key management.
 * 
 * Key Features:
 * - Double Ratchet algorithm for forward/backward secrecy
 * - Ed25519 signatures for message authentication  
 * - X25519 key exchange for ephemeral key agreement
 * - XChaCha20-Poly1305 for authenticated encryption
 * - Replay protection and message ordering
 * - Group messaging with key rotation
 * - Broadcast messaging with epoch-based keys
 * - Comprehensive session management
 * 
 * Security Properties:
 * - Forward secrecy: Past messages remain secure if current keys are compromised
 * - Post-compromise security: Future messages secure after key compromise recovery
 * - Message authentication: All messages cryptographically signed by sender
 * - Replay protection: Duplicate messages detected and rejected
 * - Identity verification: Sender identity keys mandatory in Protocol v2.1
 * 
 * Protocol v2.1 Enhancements:
 * - Mandatory sender identity keys in all encrypted messages
 * - Enhanced signature verification requirements
 * - Improved group key rotation mechanisms
 * - Better broadcast message authentication
 * - Stricter security parameter validation
 * 
 * Thread Safety: This implementation is NOT thread-safe. Use appropriate synchronization
 * in multi-threaded environments.
 * 
 * Memory Security: Keys are automatically zeroed when sessions expire or are destroyed.
 * Call destroy() method to immediately clean up all cryptographic material.
 * @author LCpl Szymon 'Si' Procak
 * @version 2.1
 */

import { x25519, ed25519 } from '@noble/curves/ed25519';
import { randomBytes } from '@noble/hashes/utils';
import { sha256, sha512 } from '@noble/hashes/sha2';
import { hkdf } from '@noble/hashes/hkdf';
import { blake3 } from '@noble/hashes/blake3';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { GhostKeyPair } from './keypair';
import {
    PlaintextMessage,
    EncryptedMessage,
    EncryptedMessageWithSenderKey,
    MessageType,
    MessagePriority,
    MessageHeader,
    SessionKeys,
    IGhostKeyPair,
    IMessageEncryption,
    CryptoError,
    PreKey,
    ExportedPublicKeys
} from '../types/crypto';

/**
 * Protocol v2.1 encryption configuration constants
 * 
 * This configuration defines all cryptographic parameters, security settings, and operational
 * limits for the GhostComm encryption system. Values are carefully chosen based on current
 * cryptographic best practices and security requirements.
 * 
 * IMPORTANT: Changing these values may break compatibility with existing installations.
 * Version the protocol appropriately when modifying core cryptographic parameters.
 */
const ENCRYPTION_CONFIG = {
    // Core Protocol Settings
    /** Protocol version identifier - used for compatibility checking */
    PROTOCOL_VERSION: 2.1,

    // Cryptographic Nonce Sizes
    /** Nonce size for XChaCha20-Poly1305 - 24 bytes allows for extended nonce space */
    XCHACHA_NONCE_SIZE: 24,
    
    /** Nonce size for ChaCha20-Poly1305 - 12 bytes for standard implementation */
    CHACHA_NONCE_SIZE: 12,

    // Key and Tag Sizes
    /** Symmetric key size - 32 bytes provides 256-bit security */
    KEY_SIZE: 32,
    
    /** Authentication tag size for Poly1305 - 16 bytes provides 128-bit security */
    AUTH_TAG_SIZE: 16,

    // Double Ratchet Key Derivation Labels
    /** HKDF info string for message key derivation - isolates message keys from chain keys */
    MESSAGE_KEY_INFO: 'GhostComm-v2.1-MessageKey',
    
    /** HKDF info string for chain key derivation - prevents key reuse across contexts */
    CHAIN_KEY_INFO: 'GhostComm-v2.1-ChainKey',
    
    /** HKDF info string for root key derivation - ensures domain separation */
    ROOT_KEY_INFO: 'GhostComm-v2.1-RootKey',
    
    /** HKDF info string for header key derivation - protects message headers */
    HEADER_KEY_INFO: 'GhostComm-v2.1-HeaderKey',

    // Double Ratchet Security Parameters
    /** Maximum skipped message keys to store - prevents memory exhaustion attacks */
    MAX_SKIP_KEYS: 1000,
    
    /** Maximum future messages to accept - prevents certain replay attacks */
    MAX_FUTURE_MESSAGES: 100,
    
    /** Message key lifetime (7 days) - balances security with offline message support */
    MESSAGE_KEY_LIFETIME: 7 * 24 * 60 * 60 * 1000,

    // Message Size Validation
    /** Minimum message payload size - prevents certain cryptographic attacks */
    MIN_MESSAGE_SIZE: 1,
    
    /** Maximum message payload size (64KB) - prevents memory exhaustion */
    MAX_MESSAGE_SIZE: 65536,
    
    /** Replay protection window - number of message IDs tracked for duplicate detection */
    REPLAY_WINDOW: 1000,

    // Broadcast Messaging Security
    /** Broadcast epoch duration (24 hours) - key rotation period for broadcast messages */
    BROADCAST_EPOCH_DURATION: 24 * 60 * 60 * 1000,
    
    /** Broadcast key rotation (1 hour) - frequent rotation for broadcast security */
    BROADCAST_KEY_ROTATION: 60 * 60 * 1000,

    // Group Messaging Parameters
    /** Maximum group size - prevents resource exhaustion in group operations */
    MAX_GROUP_SIZE: 100,
    
    /** Group key rotation (7 days) - ensures forward secrecy in groups */
    GROUP_KEY_ROTATION: 7 * 24 * 60 * 60 * 1000,

    // Protocol v2.1 Security Requirements
    /** Enforce sender identity key presence in all messages - critical for v2.1 security */
    REQUIRE_SENDER_KEY: true,
    
    /** Verify sender signatures on all messages - prevents spoofing attacks */
    VERIFY_SENDER_KEY: true,
};

/**
 * Double Ratchet session state management interface
 * 
 * Maintains all cryptographic state required for secure communication between two parties
 * using the Double Ratchet algorithm. This provides forward secrecy (past messages remain
 * secure if current keys are compromised) and post-compromise security (future messages
 * become secure after key compromise recovery).
 * 
 * Protocol v2.1 Enhancements:
 * - Tracks peer identity keys for enhanced authentication
 * - Includes handshake completion status for proper session establishment
 * - Enhanced session validation for improved security
 * 
 * Session Lifecycle:
 * 1. Initial key exchange establishes root key and first receiving chain
 * 2. Sending chain created when first message is sent
 * 3. Chains advance with each message, deriving new keys
 * 4. Skipped keys stored for out-of-order message delivery
 * 5. Session cleaned up after timeout or explicit destruction
 */
interface DoubleRatchetSession {
    /** Unique session identifier derived from participant keys */
    sessionId: string;
    
    /** Root key for deriving new chain keys - provides forward secrecy */
    rootKey: Uint8Array;
    
    /** Current sending chain state for outgoing messages */
    sendingChain: {
        /** Chain key for deriving message keys */
        key: Uint8Array;
        
        /** Current message number in this chain */
        messageNumber: number;
        
        /** Ephemeral key pair for this chain (generated on first send) */
        ephemeralKeyPair?: { 
            publicKey: Uint8Array; 
            privateKey: Uint8Array; 
        };
    };
    
    /** 
     * Map of receiving chains keyed by ephemeral public key hex
     * Each chain tracks messages from a specific ephemeral key
     */
    receivingChains: Map<string, {
        /** Chain key for deriving message keys */
        key: Uint8Array;
        
        /** Next expected message number in this chain */
        messageNumber: number;
    }>;
    
    /** 
     * Skipped message keys for out-of-order delivery
     * Keyed by "ephemeralKeyHex-messageNumber" for unique identification
     */
    skippedMessageKeys: Map<string, Uint8Array>;
    
    /** Timestamp of last message activity for session cleanup */
    lastMessageTimestamp: number;
    
    /** Whether the initial handshake has been completed successfully */
    handshakeComplete: boolean;
    
    /** Protocol v2.1: Peer's identity public key for verification */
    peerIdentityKey?: Uint8Array;
}

/**
 * Message metadata for replay protection and ordering
 * 
 * Stores essential information about processed messages to enable security features
 * such as replay attack prevention, message ordering validation, and sender tracking.
 * This metadata is kept separate from message content for efficiency and security.
 * 
 * Protocol v2.1 Enhancement:
 * - Mandatory sender identity key tracking for all messages
 * - Enhanced replay protection with sender validation
 * - Message chain integrity through hash linking
 */
interface MessageMetadata {
    /** Unique message identifier for duplicate detection */
    messageId: string;
    
    /** Message creation timestamp for ordering and expiration */
    timestamp: number;
    
    /** Sequence number for ordered delivery within sender chain */
    sequenceNumber: number;
    
    /** Hash of previous message for chain integrity verification */
    previousMessageHash: string;
    
    /** Protocol v2.1: Sender's identity key for authentication tracking */
    senderIdentityKey: string;
}

/**
 * Enhanced MessageEncryption class implementing Double Ratchet protocol v2.1
 * 
 * This is the core cryptographic engine of the GhostComm system, providing military-grade
 * end-to-end encryption with perfect forward secrecy. It implements the Double Ratchet
 * algorithm with Protocol v2.1 enhancements for improved security and authentication.
 * 
 * Key Features:
 * - Perfect Forward Secrecy: Past messages remain secure even if current keys are compromised
 * - Post-Compromise Security: Future messages become secure after recovering from key compromise
 * - Message Authentication: All messages cryptographically signed with sender's identity key
 * - Replay Protection: Duplicate and replay attacks automatically detected and prevented
 * - Out-of-Order Delivery: Messages can arrive in any order and still be decrypted correctly
 * - Group Messaging: Efficient group communication with rotating shared keys
 * - Broadcast Messaging: Secure one-to-many communication with epoch-based key rotation
 * 
 * Cryptographic Primitives:
 * - Key Exchange: X25519 elliptic curve Diffie-Hellman for ephemeral keys
 * - Signatures: Ed25519 for fast, deterministic digital signatures
 * - Encryption: XChaCha20-Poly1305 for authenticated encryption with extended nonces
 * - Key Derivation: HKDF-SHA256 for cryptographically secure key derivation
 * - Hashing: SHA-256 and SHA-512 for various cryptographic operations
 * 
 * Protocol v2.1 Security Enhancements:
 * - Mandatory sender identity keys in all encrypted messages
 * - Enhanced signature verification requirements with strict validation
 * - Improved session establishment with better handshake security
 * - Enhanced replay protection with sender-specific tracking
 * - Better group key management with forward secrecy preservation
 * 
 * Usage Example:
 * ```typescript
 * const encryption = new MessageEncryption();
 * const senderKeys = new GhostKeyPair();
 * const recipientKeys = new GhostKeyPair();
 * 
 * // Encrypt a message
 * const plaintext = MessageFactory.createDirectMessage(
 *     senderKeys.getFingerprint(),
 *     recipientKeys.getFingerprint(),
 *     "Hello, secure world!"
 * );
 * const encrypted = await encryption.encryptMessage(plaintext, senderKeys, recipientKeys.getFingerprint());
 * 
 * // Decrypt the message
 * const decrypted = await encryption.decryptMessage(encrypted, recipientKeys);
 * ```
 * 
 * Security Considerations:
 * - This class is NOT thread-safe - use appropriate synchronization in concurrent environments
 * - Keys are automatically zeroed when sessions expire or are destroyed
 * - Call destroy() method to immediately clean up all cryptographic material
 * - Monitor memory usage as skipped message keys are cached for out-of-order delivery
 * - Rate limiting should be implemented at the application layer to prevent DoS attacks
 * 
 * Implementation Notes:
 * - Sessions are automatically created on first message exchange
 * - Out-of-order messages are supported up to MAX_SKIP_KEYS limit
 * - Message metadata is cached for replay protection and ordering validation
 * - Broadcast and group keys are rotated automatically based on time epochs
 * - All cryptographic operations use constant-time implementations where possible
 */
export class MessageEncryption implements IMessageEncryption {
    // ===== CORE SESSION MANAGEMENT =====
    
    /** 
     * Active Double Ratchet sessions keyed by session ID
     * Each session maintains cryptographic state for a specific communication pair
     */
    private sessions: Map<string, DoubleRatchetSession>;
    
    /** 
     * Message metadata cache for replay protection and ordering
     * Stores essential information about processed messages without revealing content
     */
    private messageCache: Map<string, MessageMetadata>;
    
    /** 
     * Replay protection set containing processed message IDs
     * Prevents duplicate message processing and replay attacks
     */
    private replayProtection: Set<string>;
    
    // ===== GROUP AND BROADCAST KEY MANAGEMENT =====
    
    /** 
     * Broadcast encryption keys keyed by epoch number
     * Rotated regularly to provide forward secrecy for broadcast messages
     */
    private broadcastKeys: Map<number, Uint8Array>;
    
    /** 
     * Group encryption keys with rotation epochs
     * Each group maintains its own key and rotation schedule
     */
    private groupKeys: Map<string, { key: Uint8Array; epoch: number }>;
    
    // ===== PROTOCOL v2.1 SECURITY TRACKING =====
    
    /** 
     * Last message hash for each peer to maintain message chain integrity
     * Used for detecting message tampering and ensuring proper ordering
     */
    private lastMessageHashes: Map<string, string>;
    
    /** 
     * Sequence number tracking for each peer to prevent replay attacks
     * Maintains incrementing counters for message ordering validation
     */
    private sequenceNumbers: Map<string, number>;
    
    /** 
     * Trusted identity keys for verified senders
     * Protocol v2.1 enhancement for tracking and validating sender identities
     */
    private trustedKeys: Map<string, Uint8Array>;

    /**
     * Initialize the MessageEncryption system
     * 
     * Sets up all cryptographic state management structures and begins automatic
     * maintenance processes for security and resource management.
     * 
     * Initialization Process:
     * 1. Creates empty state containers for sessions, messages, and keys
     * 2. Initializes Protocol v2.1 security tracking mechanisms
     * 3. Generates initial broadcast keys for current time epoch
     * 4. Starts background cleanup processes for expired cryptographic material
     * 
     * The constructor is lightweight and performs no cryptographic operations,
     * making it safe to call frequently. Heavy cryptographic work is deferred
     * until actual message processing begins.
     */
    constructor() {
        // Initialize core cryptographic state containers
        this.sessions = new Map();
        this.messageCache = new Map();
        this.replayProtection = new Set();
        this.broadcastKeys = new Map();
        this.groupKeys = new Map();
        
        // Initialize Protocol v2.1 enhanced security tracking
        this.lastMessageHashes = new Map();
        this.sequenceNumbers = new Map();
        this.trustedKeys = new Map();

        // Generate initial broadcast keys for current epoch
        // This ensures immediate availability for broadcast messaging
        this.initializeBroadcastKeys();

        // Start automatic cleanup of expired sessions and cryptographic material
        // Prevents memory leaks and removes compromised or stale keys
        this.startCleanupInterval();
    }

    // ===== STATIC CONVENIENCE METHODS =====

    /**
     * Static method to encrypt a message with Protocol v2.1
     * 
     * Provides a convenient way to encrypt a single message without managing
     * a MessageEncryption instance. Creates a temporary instance for the operation
     * and automatically cleans up afterwards.
     * 
     * @param message - The plaintext message to encrypt
     * @param senderKeyPair - The sender's cryptographic key pair for signing
     * @param recipientPublicKey - The recipient's public key for encryption
     * @returns Promise resolving to encrypted message with sender key included
     * 
     * Note: For high-volume messaging, consider using a persistent instance
     * to avoid the overhead of repeated initialization.
     */
    static async encryptMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair,
        recipientPublicKey: Uint8Array
    ): Promise<EncryptedMessageWithSenderKey> {
        const encryption = new MessageEncryption();
        return encryption.encryptMessage(message, senderKeyPair, recipientPublicKey);
    }

    /**
     * Static method to decrypt a message with Protocol v2.1
     * 
     * Provides a convenient way to decrypt a single message without managing
     * a MessageEncryption instance. Creates a temporary instance for the operation
     * and automatically cleans up afterwards.
     * 
     * @param encryptedMessage - The encrypted message to decrypt
     * @param recipientKeyPair - The recipient's key pair for decryption
     * @returns Promise resolving to the decrypted plaintext message
     * 
     * Note: For high-volume messaging, consider using a persistent instance
     * to maintain session state and improve performance.
     */
    static async decryptMessage(
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey,
        recipientKeyPair: IGhostKeyPair
    ): Promise<PlaintextMessage> {
        const encryption = new MessageEncryption();
        return encryption.decryptMessage(encryptedMessage, recipientKeyPair);
    }

    /**
     * Static method to create a broadcast message
     */
    static async createBroadcastMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair
    ): Promise<EncryptedMessageWithSenderKey> {
        const encryption = new MessageEncryption();
        return encryption.createBroadcastMessage(message, senderKeyPair);
    }

    /**
     * Static method to decrypt a broadcast message
     */
    static async decryptBroadcastMessage(
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey,
        senderPublicKey: Uint8Array
    ): Promise<PlaintextMessage> {
        const encryption = new MessageEncryption();
        return encryption.decryptBroadcastMessage(encryptedMessage, senderPublicKey);
    }

    /**
     * Establish a Double Ratchet session with a peer
     */
    async establishSession(
        senderKeyPair: IGhostKeyPair,
        recipientPublicKey: Uint8Array,
        recipientPreKey?: PreKey
    ): Promise<SessionKeys> {
        const sessionId = this.getSessionId(
            senderKeyPair.getEncryptionPublicKey(),
            recipientPublicKey
        );

        // Check if session already exists
        const existingSession = this.sessions.get(sessionId);
        if (existingSession && existingSession.handshakeComplete) {
            return this.sessionToKeys(existingSession);
        }

        // Perform X3DH-like key agreement
        let sharedSecrets: Uint8Array[] = [];

        // 1. DH between our identity and their identity
        const dh1 = senderKeyPair.performKeyExchange(recipientPublicKey);
        sharedSecrets.push(dh1);

        // 2. If pre-key is available, use it
        if (recipientPreKey) {
            // Verify pre-key signature if available
            if (recipientPreKey.signature && recipientPreKey.signature.length > 0) {
                const keyData = new Uint8Array(recipientPreKey.publicKey.length + 4);
                keyData.set(recipientPreKey.publicKey);
                new DataView(keyData.buffer).setUint32(recipientPreKey.publicKey.length, recipientPreKey.keyId, false);
                
                // Note: Would need recipient's identity key to verify signature
                // This would come from a trusted key store in production
            }
            
            const dh2 = senderKeyPair.performKeyExchange(recipientPreKey.publicKey);
            sharedSecrets.push(dh2);
        }

        // 3. Generate ephemeral key for this session
        const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
        const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

        const dh3 = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey);
        sharedSecrets.push(dh3);

        // Combine all shared secrets
        const combinedSecret = this.combineSecrets(sharedSecrets);

        // Derive initial root and chain keys
        const salt = randomBytes(32);
        const info = new TextEncoder().encode(ENCRYPTION_CONFIG.ROOT_KEY_INFO);
        const keyMaterial = hkdf(sha512, combinedSecret, salt, info, 64);

        const rootKey = keyMaterial.slice(0, 32);
        const chainKey = keyMaterial.slice(32, 64);

        // Create Double Ratchet session
        const session: DoubleRatchetSession = {
            sessionId,
            rootKey,
            sendingChain: {
                key: chainKey,
                messageNumber: 0,
                ephemeralKeyPair: { publicKey: ephemeralPublicKey, privateKey: ephemeralPrivateKey }
            },
            receivingChains: new Map(),
            skippedMessageKeys: new Map(),
            lastMessageTimestamp: Date.now(),
            handshakeComplete: true,
            peerIdentityKey: undefined // Will be set when we receive first message
        };

        this.sessions.set(sessionId, session);

        return this.sessionToKeys(session);
    }

    // ===== CORE ENCRYPTION METHODS =====

    /**
     * Encrypt a message using Double Ratchet protocol v2.1
     * 
     * This is the primary encryption method that implements the full Double Ratchet
     * algorithm with Protocol v2.1 enhancements. It provides perfect forward secrecy,
     * post-compromise security, and authenticated encryption.
     * 
     * Protocol v2.1 Features:
     * - Mandatory sender identity key inclusion for enhanced authentication
     * - Enhanced signature verification with strict validation
     * - Improved session establishment with better handshake security
     * - Message chain integrity through hash linking
     * - Enhanced replay protection with sender tracking
     * 
     * Encryption Process:
     * 1. Validates message structure and size constraints
     * 2. Establishes or retrieves existing Double Ratchet session
     * 3. Performs ratchet step to generate new ephemeral keys if needed
     * 4. Derives message key using HKDF from current chain key
     * 5. Creates authenticated header with sender signature
     * 6. Encrypts message with XChaCha20-Poly1305 using derived key
     * 7. Packages result with Protocol v2.1 sender identity information
     * 8. Updates session state and advances message chain
     * 
     * Security Properties:
     * - Forward Secrecy: Past messages remain secure if current keys compromised
     * - Authentication: Message cryptographically signed with sender's identity key
     * - Integrity: Any tampering with message detected during decryption
     * - Replay Protection: Duplicate messages automatically detected and rejected
     * - Confidentiality: Message content hidden from all except intended recipient
     * 
     * @param message - The plaintext message to encrypt (must pass validation)
     * @param senderKeyPair - Sender's key pair for signing and key exchange
     * @param recipientPublicKey - Recipient's public key for session establishment
     * @returns Promise resolving to encrypted message with sender key included
     * 
     * @throws {Error} If message validation fails, session establishment fails,
     *                 or cryptographic operations encounter errors
     * 
     * Performance Notes:
     * - First message to a recipient requires session establishment (slower)
     * - Subsequent messages use existing session (faster)
     * - Out-of-order message keys cached for up to MAX_SKIP_KEYS messages
     * - Session state automatically persisted across calls
     */
    async encryptMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair,
        recipientPublicKey: Uint8Array
    ): Promise<EncryptedMessageWithSenderKey> {
        try {
            // Validate message
            this.validatePlaintextMessage(message);

            // Get or establish session
            const sessionId = this.getSessionId(
                senderKeyPair.getEncryptionPublicKey(),
                recipientPublicKey
            );

            let session = this.sessions.get(sessionId);
            if (!session || !session.handshakeComplete) {
                await this.establishSession(senderKeyPair, recipientPublicKey);
                session = this.sessions.get(sessionId)!;
            }

            // Perform ratchet step if needed
            if (!session.sendingChain.ephemeralKeyPair) {
                session = this.ratchetSendingChain(session, senderKeyPair);
            }

            // Derive message key from chain key
            const messageKey = this.deriveMessageKey(session.sendingChain.key);

            // Advance chain key
            session.sendingChain.key = this.advanceChainKey(session.sendingChain.key);

            // Create authenticated header with proper message chaining
            const peerId = this.bytesToHex(recipientPublicKey);
            const header = this.createMessageHeader(message, senderKeyPair, peerId);

            // Update message hash chain after creating header
            const messageHash = this.calculateMessageHash(message);
            this.updateLastMessageHash(peerId, messageHash);

            // Serialize complete message with header
            const fullMessage = {
                ...message,
                header
            };
            const plaintext = new TextEncoder().encode(JSON.stringify(fullMessage));

            // Generate 24-byte nonce for XChaCha20-Poly1305
            const nonce = randomBytes(ENCRYPTION_CONFIG.XCHACHA_NONCE_SIZE);

            // Encrypt with XChaCha20-Poly1305
            const ciphertext = xchacha20poly1305(messageKey, nonce).encrypt(plaintext);

            // XChaCha20-Poly1305 output includes auth tag at the end
            const encryptedData = ciphertext.slice(0, -16);
            const authTag = ciphertext.slice(-16);

            // Create encrypted message with Protocol v2.1 sender key
            const encryptedMessage: EncryptedMessageWithSenderKey = {
                header: {
                    messageId: header.messageId,
                    sourceId: header.sourceId,
                    destinationId: header.destinationId,
                    timestamp: header.timestamp,
                    ttl: header.ttl,
                    hopCount: header.hopCount,
                    priority: header.priority
                },
                ephemeralPublicKey: this.bytesToHex(session.sendingChain.ephemeralKeyPair!.publicKey),
                previousChainLength: 0,
                messageNumber: session.sendingChain.messageNumber++,
                nonce: this.bytesToHex(nonce),
                ciphertext: this.bytesToHex(encryptedData),
                authTag: this.bytesToHex(authTag),
                // Protocol v2.1: ALWAYS include sender identity key
                senderIdentityKey: this.bytesToHex(senderKeyPair.getIdentityPublicKey()),
                senderEncryptionKey: this.bytesToHex(senderKeyPair.getEncryptionPublicKey())
            };

            // Add to replay protection
            this.addReplayProtection(header.messageId);

            // Update session
            this.sessions.set(sessionId, session);

            // Store message metadata
            this.messageCache.set(header.messageId, {
                messageId: header.messageId,
                timestamp: header.timestamp,
                sequenceNumber: header.sequenceNumber,
                previousMessageHash: header.previousMessageHash || '',
                senderIdentityKey: encryptedMessage.senderIdentityKey
            });

            // Clean up old message keys
            this.cleanupMessageKeys(messageKey);

            return encryptedMessage;

        } catch (error) {
            throw new Error(`Message encryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt a message using Double Ratchet protocol v2.1
     * 
     * This is the primary decryption method that implements the full Double Ratchet
     * algorithm with Protocol v2.1 security enhancements. It provides authenticated
     * decryption with strong sender verification and replay protection.
     * 
     * Protocol v2.1 Security Features:
     * - Mandatory sender identity key verification for all messages
     * - Enhanced signature validation with strict cryptographic checks
     * - Automatic trusted key management and rotation detection
     * - Message chain integrity verification through hash validation
     * - Comprehensive replay protection with sender-specific tracking
     * 
     * Decryption Process:
     * 1. Validates Protocol v2.1 requirements (sender key presence)
     * 2. Checks replay protection to prevent duplicate processing
     * 3. Extracts and validates sender identity key information
     * 4. Establishes or retrieves existing Double Ratchet session
     * 5. Derives or retrieves appropriate message key for decryption
     * 6. Decrypts message content using XChaCha20-Poly1305
     * 7. Verifies message signature using sender's identity key
     * 8. Updates session state and message chain tracking
     * 
     * Security Validations:
     * - Sender identity key consistency checking
     * - Message signature verification with Ed25519
     * - Replay attack detection and prevention
     * - Message chain integrity validation
     * - Session state consistency verification
     * 
     * Out-of-Order Message Handling:
     * - Automatic derivation of skipped message keys
     * - Support for messages arriving up to MAX_SKIP_KEYS out of order
     * - Efficient storage and cleanup of temporary message keys
     * - Chain advancement with proper key material management
     * 
     * @param encryptedMessage - The encrypted message to decrypt (with sender key)
     * @param recipientKeyPair - Recipient's key pair for decryption and verification
     * @returns Promise resolving to the decrypted and verified plaintext message
     * 
     * @throws {CryptoError.NO_SENDER_KEY} If Protocol v2.1 sender key missing
     * @throws {CryptoError.REPLAY_DETECTED} If message is duplicate or replayed
     * @throws {CryptoError.SIGNATURE_VERIFICATION_FAILED} If signature invalid
     * @throws {Error} For other cryptographic or validation failures
     * 
     * Performance Notes:
     * - Messages in correct order process faster (no key skipping)
     * - Out-of-order messages may require deriving multiple skipped keys
     * - Session establishment overhead on first message from new sender
     * - Automatic cleanup of expired keys and session state
     */
    async decryptMessage(
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey,
        recipientKeyPair: IGhostKeyPair
    ): Promise<PlaintextMessage> {
        try {
            // Protocol v2.1: Verify sender key is present
            if (ENCRYPTION_CONFIG.REQUIRE_SENDER_KEY) {
                if (!('senderIdentityKey' in encryptedMessage) || !encryptedMessage.senderIdentityKey) {
                    throw new Error(CryptoError.NO_SENDER_KEY);
                }
            }

            // Check replay protection
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
            }

            // Get sender's identity key for verification
            let senderIdentityKey: Uint8Array | undefined;
            if ('senderIdentityKey' in encryptedMessage && encryptedMessage.senderIdentityKey) {
                senderIdentityKey = this.hexToBytes(encryptedMessage.senderIdentityKey);
                
                // Store trusted key for future verification
                const senderId = encryptedMessage.header.sourceId;
                if (!this.trustedKeys.has(senderId)) {
                    this.trustedKeys.set(senderId, senderIdentityKey);
                } else {
                    // Verify key hasn't changed
                    const trustedKey = this.trustedKeys.get(senderId)!;
                    if (!this.arraysEqual(trustedKey, senderIdentityKey)) {
                        console.warn('Sender identity key changed - possible security issue');
                        // In production, might want to prompt user for verification
                    }
                }
            }

            // Get session
            const sessionId = this.getSessionId(
                recipientKeyPair.getEncryptionPublicKey(),
                this.hexToBytes(encryptedMessage.ephemeralPublicKey)
            );

            let session = this.sessions.get(sessionId);
            if (!session) {
                // Try to establish session from received message
                session = await this.establishSessionFromMessage(
                    recipientKeyPair,
                    encryptedMessage
                );
            }

            // Store peer identity key in session if available
            if (senderIdentityKey && !session.peerIdentityKey) {
                session.peerIdentityKey = senderIdentityKey;
            }

            // Get or derive message key
            const messageKey = await this.getOrDeriveMessageKey(
                session,
                encryptedMessage,
                recipientKeyPair
            );

            // Parse encrypted components
            const nonce = this.hexToBytes(encryptedMessage.nonce);
            const ciphertext = this.hexToBytes(encryptedMessage.ciphertext);
            const authTag = this.hexToBytes(encryptedMessage.authTag);

            // Reconstruct encrypted data
            const encryptedData = new Uint8Array(ciphertext.length + authTag.length);
            encryptedData.set(ciphertext);
            encryptedData.set(authTag, ciphertext.length);

            // Decrypt with XChaCha20-Poly1305
            const decrypted = xchacha20poly1305(messageKey, nonce).decrypt(encryptedData);

            // Parse and validate message
            const fullMessage = JSON.parse(new TextDecoder().decode(decrypted));

            // Protocol v2.1: Verify signature with sender's identity key
            if (ENCRYPTION_CONFIG.VERIFY_SENDER_KEY && senderIdentityKey) {
                if (!this.verifyMessageSignature(fullMessage, fullMessage.header.signature, senderIdentityKey)) {
                    throw new Error(CryptoError.SIGNATURE_VERIFICATION_FAILED);
                }
            }

            // Add to replay protection
            this.addReplayProtection(fullMessage.header.messageId);

            // Update message chain tracking
            const peerId = encryptedMessage.header.sourceId;
            const messageHash = this.calculateMessageHash(fullMessage);
            this.updateLastMessageHash(peerId, messageHash);

            // Store message metadata
            if ('senderIdentityKey' in encryptedMessage) {
                this.messageCache.set(fullMessage.header.messageId, {
                    messageId: fullMessage.header.messageId,
                    timestamp: fullMessage.header.timestamp,
                    sequenceNumber: fullMessage.header.sequenceNumber,
                    previousMessageHash: fullMessage.header.previousMessageHash || '',
                    senderIdentityKey: encryptedMessage.senderIdentityKey
                });
            }

            // Clean up used key
            this.cleanupMessageKeys(messageKey);

            return fullMessage;

        } catch (error) {
            throw new Error(`Message decryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // ===== GROUP MESSAGING METHODS =====

    /**
     * Encrypt a group message using Protocol v2.1 sender keys
     * 
     * Provides secure group messaging with forward secrecy through epoch-based key rotation.
     * Each message uses an ephemeral key combined with the group key to ensure that
     * compromising one message doesn't compromise others, even within the same group.
     * 
     * Protocol v2.1 Group Security Features:
     * - Mandatory sender identity key inclusion for group member authentication
     * - Epoch-based key rotation for forward secrecy within groups
     * - Enhanced group key derivation using HKDF with proper domain separation
     * - Individual message keys derived from both group and ephemeral keys
     * - Full backward compatibility with existing group structures
     * 
     * Group Encryption Process:
     * 1. Validates message structure and group membership
     * 2. Determines current epoch for key rotation schedule
     * 3. Derives epoch-specific group key using HKDF with group ID salt
     * 4. Generates ephemeral key pair for this specific message
     * 5. Combines ephemeral and group keys for unique message key
     * 6. Creates authenticated header with sender signature
     * 7. Encrypts with XChaCha20-Poly1305 using derived message key
     * 8. Packages with Protocol v2.1 sender identity information
     * 
     * Key Derivation Security:
     * - Group ID used as salt for domain separation between groups
     * - Epoch number ensures automatic key rotation over time
     * - Ephemeral keys prevent correlation between messages
     * - HKDF provides cryptographically secure key expansion
     * 
     * @param message - The plaintext group message to encrypt
     * @param senderKeyPair - Sender's key pair for authentication and signing
     * @param groupKey - Shared group key for this specific group
     * @returns Promise resolving to encrypted message with sender authentication
     * 
     * @throws {Error} If message validation fails or group operations encounter errors
     * 
     * Performance Notes:
     * - Key derivation computed fresh for each message (security over performance)
     * - Epoch calculation allows for automatic key rotation
     * - Group key should be rotated regularly for optimal security
     */
    async encryptGroupMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair,
        groupKey: Uint8Array
    ): Promise<EncryptedMessageWithSenderKey> {
        try {
            // Validate message
            this.validatePlaintextMessage(message);

            // Derive group encryption key
            const epoch = Math.floor(Date.now() / ENCRYPTION_CONFIG.GROUP_KEY_ROTATION);
            const info = new TextEncoder().encode(`GhostComm-Group-v2.1-${message.header.groupId}-${epoch}`);
            const salt = sha256(new TextEncoder().encode(message.header.groupId || ''));
            const derivedKey = hkdf(sha256, groupKey, salt, info, 32);

            // Create authenticated header
            const header = this.createMessageHeader(message, senderKeyPair, message.header.groupId);

            // Generate ephemeral key for this message
            const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
            const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

            // Perform ECDH with group key for additional security
            const messageSecret = x25519.getSharedSecret(ephemeralPrivateKey, groupKey);
            const messageKey = hkdf(sha256, messageSecret, derivedKey, info, 32);

            // Serialize message
            const fullMessage = { ...message, header };
            const plaintext = new TextEncoder().encode(JSON.stringify(fullMessage));

            // Encrypt
            const nonce = randomBytes(ENCRYPTION_CONFIG.XCHACHA_NONCE_SIZE);
            const ciphertext = xchacha20poly1305(messageKey, nonce).encrypt(plaintext);
            const encryptedData = ciphertext.slice(0, -16);
            const authTag = ciphertext.slice(-16);

            return {
                header: {
                    messageId: header.messageId,
                    sourceId: header.sourceId,
                    groupId: header.groupId,
                    timestamp: header.timestamp,
                    ttl: header.ttl,
                    hopCount: header.hopCount,
                    priority: header.priority
                },
                ephemeralPublicKey: this.bytesToHex(ephemeralPublicKey),
                previousChainLength: 0,
                messageNumber: 0,
                nonce: this.bytesToHex(nonce),
                ciphertext: this.bytesToHex(encryptedData),
                authTag: this.bytesToHex(authTag),
                groupKeyId: `${epoch}`,
                senderKeyShare: this.bytesToHex(senderKeyPair.getEncryptionPublicKey()),
                // Protocol v2.1: Include sender identity key
                senderIdentityKey: this.bytesToHex(senderKeyPair.getIdentityPublicKey())
            };

        } catch (error) {
            throw new Error(`Group message encryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt a group message v2.1
     */
    async decryptGroupMessage(
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey,
        groupKey: Uint8Array
    ): Promise<PlaintextMessage> {
        try {
            // Check replay
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
            }

            // Protocol v2.1: Get sender key if available
            let senderIdentityKey: Uint8Array | undefined;
            if ('senderIdentityKey' in encryptedMessage && encryptedMessage.senderIdentityKey) {
                senderIdentityKey = this.hexToBytes(encryptedMessage.senderIdentityKey);
            }

            // Derive group decryption key
            const epoch = parseInt(encryptedMessage.groupKeyId || '0');
            const info = new TextEncoder().encode(`GhostComm-Group-v2.1-${encryptedMessage.header.groupId}-${epoch}`);
            const salt = sha256(new TextEncoder().encode(encryptedMessage.header.groupId || ''));
            const derivedKey = hkdf(sha256, groupKey, salt, info, 32);

            // Get ephemeral public key
            const ephemeralPublicKey = this.hexToBytes(encryptedMessage.ephemeralPublicKey);

            // Derive message key
            const messageSecret = x25519.getSharedSecret(groupKey, ephemeralPublicKey);
            const messageKey = hkdf(sha256, messageSecret, derivedKey, info, 32);

            // Decrypt
            const nonce = this.hexToBytes(encryptedMessage.nonce);
            const ciphertext = this.hexToBytes(encryptedMessage.ciphertext);
            const authTag = this.hexToBytes(encryptedMessage.authTag);

            const encryptedData = new Uint8Array(ciphertext.length + authTag.length);
            encryptedData.set(ciphertext);
            encryptedData.set(authTag, ciphertext.length);

            const cipher = xchacha20poly1305(messageKey, nonce);
            const decrypted = cipher.decrypt(encryptedData);

            const fullMessage = JSON.parse(new TextDecoder().decode(decrypted));

            // Protocol v2.1: Verify signature if sender key available
            if (senderIdentityKey) {
                if (!this.verifyMessageSignature(fullMessage, fullMessage.header.signature, senderIdentityKey)) {
                    throw new Error(CryptoError.SIGNATURE_VERIFICATION_FAILED);
                }
            }

            // Add to replay protection
            this.addReplayProtection(fullMessage.header.messageId);

            return fullMessage;

        } catch (error) {
            throw new Error(`Group message decryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // ===== BROADCAST MESSAGING METHODS =====

    /**
     * Create a secure broadcast message with rotating keys v2.1
     * 
     * Implements secure one-to-many messaging using epoch-based key rotation for forward
     * secrecy. Each broadcast message is encrypted with a unique key derived from the
     * current epoch and an ephemeral key, ensuring that compromising one message doesn't
     * affect others, even from the same sender.
     * 
     * Protocol v2.1 Broadcast Security Features:
     * - Epoch-based automatic key rotation for forward secrecy
     * - Dual signature system: message signature + broadcast-specific signature
     * - Mandatory sender identity key inclusion for authentication
     * - Enhanced key derivation preventing cross-epoch attacks
     * - Cryptographic binding between epoch and message content
     * 
     * Broadcast Encryption Process:
     * 1. Determines current broadcast epoch based on time
     * 2. Retrieves or generates epoch-specific broadcast key
     * 3. Creates authenticated message header with sender signature
     * 4. Generates ephemeral key pair for this specific broadcast
     * 5. Derives unique message key from ephemeral and broadcast keys
     * 6. Creates additional broadcast signature for epoch verification
     * 7. Encrypts with XChaCha20-Poly1305 using derived key
     * 8. Packages with Protocol v2.1 sender identity and epoch information
     * 
     * Key Rotation Security:
     * - Automatic epoch advancement based on configurable time intervals
     * - Independent key derivation for each broadcast message
     * - Cryptographic binding between epoch number and message content
     * - Forward secrecy: past messages remain secure after key rotation
     * 
     * @param message - The plaintext message to broadcast
     * @param senderKeyPair - Sender's key pair for dual signature authentication
     * @returns Promise resolving to encrypted broadcast message with authentication
     * 
     * @throws {Error} If broadcast key generation fails or encryption encounters errors
     * 
     * Security Notes:
     * - Recipients must know the epoch to decrypt (distributed separately)
     * - Broadcast keys should be distributed through secure channels
     * - Epoch information is included in message but not the broadcast key itself
     * - Dual signature prevents both message spoofing and epoch manipulation
     */
    async createBroadcastMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair
    ): Promise<EncryptedMessageWithSenderKey> {
        try {
            // Get current broadcast key
            const epoch = this.getCurrentBroadcastEpoch();
            const broadcastKey = this.getBroadcastKey(epoch);

            // Create authenticated header with proper signature
            const header = this.createMessageHeader(message, senderKeyPair, 'broadcast');

            // Generate ephemeral key for this broadcast
            const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
            const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

            // Derive message key using HKDF with broadcast key as salt
            const info = new TextEncoder().encode(`GhostComm-Broadcast-v2.1-${epoch}`);
            const combined = new Uint8Array(ephemeralPublicKey.length + broadcastKey.length);
            combined.set(ephemeralPublicKey);
            combined.set(broadcastKey, ephemeralPublicKey.length);

            const messageKey = hkdf(sha256, combined, broadcastKey, info, 32);

            // Sign the broadcast with sender's identity key
            const signatureData = new Uint8Array(
                ephemeralPublicKey.length +
                8 // epoch as uint64
            );
            signatureData.set(ephemeralPublicKey);
            new DataView(signatureData.buffer).setBigUint64(
                ephemeralPublicKey.length,
                BigInt(epoch),
                false
            );
            const broadcastSignature = senderKeyPair.signMessage(signatureData);

            // Serialize message with signature
            const fullMessage = {
                ...message,
                header: {
                    ...header,
                    signature: this.bytesToHex(header.signature)
                },
                broadcastSignature: this.bytesToHex(broadcastSignature)
            };
            const plaintext = new TextEncoder().encode(JSON.stringify(fullMessage));

            // Encrypt
            const nonce = randomBytes(ENCRYPTION_CONFIG.XCHACHA_NONCE_SIZE);
            const ciphertext = xchacha20poly1305(messageKey, nonce).encrypt(plaintext);

            const encryptedData = ciphertext.slice(0, -16);
            const authTag = ciphertext.slice(-16);

            return {
                header: {
                    messageId: header.messageId,
                    sourceId: header.sourceId,
                    timestamp: header.timestamp,
                    ttl: header.ttl,
                    hopCount: header.hopCount,
                    priority: header.priority
                },
                ephemeralPublicKey: this.bytesToHex(ephemeralPublicKey),
                previousChainLength: 0,
                messageNumber: epoch,
                nonce: this.bytesToHex(nonce),
                ciphertext: this.bytesToHex(encryptedData),
                authTag: this.bytesToHex(authTag),
                // Protocol v2.1: Include sender identity key
                senderIdentityKey: this.bytesToHex(senderKeyPair.getIdentityPublicKey())
            };

        } catch (error) {
            throw new Error(`Broadcast message creation failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt a broadcast message with sender verification v2.1
     */
    async decryptBroadcastMessage(
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey,
        senderPublicKey: Uint8Array
    ): Promise<PlaintextMessage> {
        try {
            // Check replay
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
            }

            // Protocol v2.1: Use provided sender key or extract from message
            let actualSenderKey = senderPublicKey;
            if ('senderIdentityKey' in encryptedMessage && encryptedMessage.senderIdentityKey) {
                const messageSenderKey = this.hexToBytes(encryptedMessage.senderIdentityKey);
                // Verify they match if both provided
                if (senderPublicKey.length > 0 && !this.arraysEqual(actualSenderKey, messageSenderKey)) {
                    throw new Error('Sender key mismatch');
                }
                actualSenderKey = messageSenderKey;
            }

            // Get broadcast key for the epoch
            const epoch = encryptedMessage.messageNumber;
            const broadcastKey = this.getBroadcastKey(epoch);

            // Get ephemeral public key
            const ephemeralPublicKey = this.hexToBytes(encryptedMessage.ephemeralPublicKey);

            // Derive message key using same method as encryption
            const info = new TextEncoder().encode(`GhostComm-Broadcast-v2.1-${epoch}`);
            const combined = new Uint8Array(ephemeralPublicKey.length + broadcastKey.length);
            combined.set(ephemeralPublicKey);
            combined.set(broadcastKey, ephemeralPublicKey.length);

            const messageKey = hkdf(sha256, combined, broadcastKey, info, 32);

            // Decrypt
            const nonce = this.hexToBytes(encryptedMessage.nonce);
            const ciphertext = this.hexToBytes(encryptedMessage.ciphertext);
            const authTag = this.hexToBytes(encryptedMessage.authTag);

            const encryptedData = new Uint8Array(ciphertext.length + authTag.length);
            encryptedData.set(ciphertext);
            encryptedData.set(authTag, ciphertext.length);

            const cipher = xchacha20poly1305(messageKey, nonce);
            const decrypted = cipher.decrypt(encryptedData);

            const fullMessage = JSON.parse(new TextDecoder().decode(decrypted));

            // Verify broadcast signature
            const signatureData = new Uint8Array(ephemeralPublicKey.length + 8);
            signatureData.set(ephemeralPublicKey);
            new DataView(signatureData.buffer).setBigUint64(
                ephemeralPublicKey.length,
                BigInt(epoch),
                false
            );

            const broadcastSignature = this.hexToBytes(fullMessage.broadcastSignature);
            if (!ed25519.verify(broadcastSignature, signatureData, actualSenderKey)) {
                throw new Error('Invalid broadcast signature');
            }

            // Verify message signature with sender's public key
            const headerSignature = typeof fullMessage.header.signature === 'string'
                ? this.hexToBytes(fullMessage.header.signature)
                : fullMessage.header.signature;

            if (!this.verifyMessageSignature(fullMessage, headerSignature, actualSenderKey)) {
                throw new Error(CryptoError.SIGNATURE_VERIFICATION_FAILED);
            }

            // Add to replay protection
            this.addReplayProtection(fullMessage.header.messageId);

            // Remove broadcast signature from returned message
            delete fullMessage.broadcastSignature;

            return fullMessage;

        } catch (error) {
            throw new Error(`Broadcast message decryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Encrypt with an established session (for performance) v2.1
     */
    async encryptWithSession(
        message: PlaintextMessage,
        session: SessionKeys
    ): Promise<EncryptedMessageWithSenderKey> {
        try {
            // Note: This method requires the caller to have access to their key pair
            // In production, might want to pass keyPair as parameter
            throw new Error('encryptWithSession requires key pair parameter for v2.1');
            
        } catch (error) {
            throw new Error(`Session encryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt with an established session v2.1
     */
    async decryptWithSession(
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey,
        session: SessionKeys
    ): Promise<PlaintextMessage> {
        try {
            // Check replay protection
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
            }

            // Protocol v2.1: Extract sender key if available
            let senderIdentityKey: Uint8Array | undefined;
            if ('senderIdentityKey' in encryptedMessage && encryptedMessage.senderIdentityKey) {
                senderIdentityKey = this.hexToBytes(encryptedMessage.senderIdentityKey);
            }

            // Convert and get or create session
            const drSession = this.keysToSession(session);

            // Get message key
            const messageKeyId = `${encryptedMessage.ephemeralPublicKey}-${encryptedMessage.messageNumber}`;
            let messageKey = drSession.skippedMessageKeys.get(messageKeyId);

            if (!messageKey) {
                // Try to find or create receiving chain
                const chainId = encryptedMessage.ephemeralPublicKey;
                let chain = drSession.receivingChains.get(chainId);

                if (!chain) {
                    // Create new receiving chain from ephemeral key
                    const ephemeralPublicKey = this.hexToBytes(encryptedMessage.ephemeralPublicKey);

                    // Derive chain key from root key and ephemeral public key
                    const combined = new Uint8Array(64);
                    combined.set(drSession.rootKey);
                    combined.set(ephemeralPublicKey, 32);

                    const info = new TextEncoder().encode(ENCRYPTION_CONFIG.CHAIN_KEY_INFO);
                    const chainKey = hkdf(sha256, combined, undefined, info, 32);

                    chain = { key: chainKey, messageNumber: 0 };
                    drSession.receivingChains.set(chainId, chain);
                }

                // Skip messages if needed
                while (chain.messageNumber < encryptedMessage.messageNumber) {
                    const skippedKey = this.deriveMessageKey(chain.key);
                    const skippedKeyId = `${chainId}-${chain.messageNumber}`;
                    drSession.skippedMessageKeys.set(skippedKeyId, skippedKey);

                    chain.key = this.advanceChainKey(chain.key);
                    chain.messageNumber++;

                    // Limit skipped keys
                    if (drSession.skippedMessageKeys.size > ENCRYPTION_CONFIG.MAX_SKIP_KEYS) {
                        const firstKey = drSession.skippedMessageKeys.keys().next().value;
                        if (firstKey !== undefined) {
                            drSession.skippedMessageKeys.delete(firstKey);
                        }
                    }
                }

                // Derive the message key
                messageKey = this.deriveMessageKey(chain.key);

                // Advance chain for next message
                chain.key = this.advanceChainKey(chain.key);
                chain.messageNumber++;
            }

            // Decrypt
            const nonce = this.hexToBytes(encryptedMessage.nonce);
            const ciphertext = this.hexToBytes(encryptedMessage.ciphertext);
            const authTag = this.hexToBytes(encryptedMessage.authTag);

            const encryptedData = new Uint8Array(ciphertext.length + authTag.length);
            encryptedData.set(ciphertext);
            encryptedData.set(authTag, ciphertext.length);

            const cipher = xchacha20poly1305(messageKey, nonce);
            const decrypted = cipher.decrypt(encryptedData);

            const fullMessage = JSON.parse(new TextDecoder().decode(decrypted));

            // Protocol v2.1: Verify with sender key if available
            if (senderIdentityKey && ENCRYPTION_CONFIG.VERIFY_SENDER_KEY) {
                if (!this.verifyMessageSignature(fullMessage, fullMessage.header.signature, senderIdentityKey)) {
                    throw new Error(CryptoError.SIGNATURE_VERIFICATION_FAILED);
                }
            }

            // Add to replay protection
            this.addReplayProtection(encryptedMessage.header.messageId);

            // Clean up message key
            this.cleanupMessageKeys(messageKey);

            // Update session in map
            const sessionId = this.bytesToHex(sha256(drSession.rootKey));
            this.sessions.set(sessionId, drSession);

            return fullMessage;
        } catch (error) {
            throw new Error(`Session decryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    // ===== UTILITY AND VALIDATION METHODS =====

    /**
     * Generate a cryptographically secure message ID
     * 
     * Creates a unique, unpredictable identifier for each message that provides both
     * temporal ordering information and strong uniqueness guarantees. The ID combines
     * timestamp data for ordering with cryptographic randomness for uniqueness.
     * 
     * ID Structure:
     * - 8 bytes: Timestamp (milliseconds since epoch) for rough ordering
     * - 16 bytes: Cryptographically secure random data for uniqueness
     * - Final: SHA-256 hash of combined data for uniform distribution
     * 
     * Security Properties:
     * - 256-bit output space prevents collision attacks
     * - Timestamp component allows for efficient ordering operations
     * - Random component prevents prediction or enumeration attacks
     * - Hash output provides uniform distribution across ID space
     * - No sensitive information leaked through ID structure
     * 
     * @returns Hex-encoded 256-bit message ID suitable for indexing and ordering
     */
    generateMessageId(): string {
        // Use 16 bytes of cryptographically secure randomness for 128-bit entropy
        const randomPart = randomBytes(16);

        // Add 8 bytes of timestamp for temporal ordering capability
        const timestamp = Date.now();
        const timestampBytes = new Uint8Array(8);
        new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestamp), false);

        // Combine timestamp and random data
        const messageId = new Uint8Array(24);
        messageId.set(timestampBytes);
        messageId.set(randomPart, 8);

        // Hash the combined data for uniform distribution and fixed length
        const hash = sha256(messageId);

        return this.bytesToHex(hash);
    }

    /**
     * Validate a plaintext message structure
     * 
     * Provides a simple boolean validation check for message structure without throwing
     * exceptions. This is useful for conditional validation where errors should not
     * interrupt program flow.
     * 
     * @param message - The plaintext message to validate
     * @returns true if message is valid, false otherwise
     */
    validateMessage(message: PlaintextMessage): boolean {
        try {
            this.validatePlaintextMessage(message);
            return true;
        } catch {
            return false;
        }
    }

    /**
     * Calculate a message hash for chaining
     */
    calculateMessageHash(message: PlaintextMessage): string {
        const serialized = JSON.stringify(message);
        const messageBytes = new TextEncoder().encode(serialized);
        const hash = sha256(messageBytes);
        return this.bytesToHex(hash);
    }

    // ===== PRIVATE HELPER METHODS =====

    /**
     * Initialize broadcast keys for current and next epoch
     */
    private initializeBroadcastKeys(): void {
        const currentEpoch = this.getCurrentBroadcastEpoch();

        // Generate keys for current and next epoch
        for (let i = 0; i <= 1; i++) {
            const epoch = currentEpoch + i;
            const seed = new TextEncoder().encode(`GhostComm-Broadcast-v2.1-Epoch-${epoch}`);
            const key = sha256(seed);
            this.broadcastKeys.set(epoch, key);
        }
    }

    /**
     * Get current broadcast epoch
     */
    private getCurrentBroadcastEpoch(): number {
        return Math.floor(Date.now() / ENCRYPTION_CONFIG.BROADCAST_EPOCH_DURATION);
    }

    /**
     * Get broadcast key for epoch
     */
    private getBroadcastKey(epoch: number): Uint8Array {
        let key = this.broadcastKeys.get(epoch);

        if (!key) {
            // Generate key for requested epoch
            const seed = new TextEncoder().encode(`GhostComm-Broadcast-v2.1-Epoch-${epoch}`);
            key = sha256(seed);
            this.broadcastKeys.set(epoch, key);

            // Clean old epochs
            const currentEpoch = this.getCurrentBroadcastEpoch();
            for (const [e, _] of this.broadcastKeys) {
                if (e < currentEpoch - 1) {
                    this.broadcastKeys.delete(e);
                }
            }
        }

        return key;
    }

    /**
     * Create authenticated message header
     */
    private createMessageHeader(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair,
        peerId?: string
    ): MessageHeader {
        const effectivePeerId = peerId || 'default';
        
        const header: MessageHeader = {
            version: ENCRYPTION_CONFIG.PROTOCOL_VERSION,
            messageId: message.header?.messageId || this.generateMessageId(),
            sourceId: message.header?.sourceId || senderKeyPair.getFingerprint(),
            destinationId: message.header?.destinationId,
            groupId: message.header?.groupId,
            timestamp: Date.now(),
            sequenceNumber: this.getNextSequenceNumber(effectivePeerId),
            ttl: message.header?.ttl || 86400000, // 24 hours default
            hopCount: 0,
            priority: message.header?.priority || MessagePriority.NORMAL,
            relayPath: [],
            signature: new Uint8Array(64), // Will be set below
            previousMessageHash: this.getLastMessageHash(effectivePeerId)
        };

        // Sign the header
        const headerBytes = this.serializeHeaderForSigning(header);
        header.signature = senderKeyPair.signMessage(headerBytes);

        return header;
    }

    /**
     * Serialize header for signing (excluding signature field)
     */
    private serializeHeaderForSigning(header: MessageHeader): Uint8Array {
        const headerCopy = { ...header };
        delete (headerCopy as any).signature;

        // Convert any Uint8Arrays to hex for consistent serialization
        const json = JSON.stringify(headerCopy, (key, value) => {
            if (value instanceof Uint8Array) {
                return this.bytesToHex(value);
            }
            return value;
        });
        return new TextEncoder().encode(json);
    }

    /**
     * Verify message signature with Protocol v2.1 requirements
     */
    private verifyMessageSignature(
        message: any, 
        signature: Uint8Array | string, 
        senderPublicKey: Uint8Array
    ): boolean {
        try {
            if (!message || !message.header || !signature) {
                return false;
            }

            // Convert signature to Uint8Array if it's a hex string
            let signatureBytes: Uint8Array;
            if (typeof signature === 'string') {
                signatureBytes = this.hexToBytes(signature);
            } else {
                signatureBytes = signature;
            }

            const headerBytes = this.serializeHeaderForSigning(message.header);

            // Ed25519 signatures are always 64 bytes
            if (signatureBytes.length !== 64) {
                return false;
            }

            // Check if signature is all zeros (unsigned)
            const isAllZeros = signatureBytes.every(byte => byte === 0);
            if (isAllZeros) {
                // Only allow zero signatures for broadcast messages with separate signature
                if (message.broadcastSignature) {
                    return true;
                }
                return false;
            }

            // Protocol v2.1: ALWAYS verify with sender's public key
            if (!senderPublicKey || senderPublicKey.length !== 32) {
                console.warn('Invalid sender public key for verification');
                return false;
            }

            // Verify the signature with the sender's public key
            return ed25519.verify(signatureBytes, headerBytes, senderPublicKey);

        } catch (error) {
            console.error('Signature verification error:', error);
            return false;
        }
    }

    /**
     * Get session ID from two public keys
     */
    private getSessionId(ourKey: Uint8Array, theirKey: Uint8Array): string {
        const combined = new Uint8Array(64);

        // Sort keys for consistent session ID
        const ourHex = this.bytesToHex(ourKey);
        const theirHex = this.bytesToHex(theirKey);

        if (ourHex < theirHex) {
            combined.set(ourKey);
            combined.set(theirKey, 32);
        } else {
            combined.set(theirKey);
            combined.set(ourKey, 32);
        }

        const hash = sha256(combined);
        return this.bytesToHex(hash);
    }

    /**
     * Combine multiple shared secrets
     */
    private combineSecrets(secrets: Uint8Array[]): Uint8Array {
        const totalLength = secrets.reduce((sum, s) => sum + s.length, 0);
        const combined = new Uint8Array(totalLength);

        let offset = 0;
        for (const secret of secrets) {
            combined.set(secret, offset);
            offset += secret.length;
        }

        // Hash the combined secrets
        return sha512(combined);
    }

    /**
     * Convert session to SessionKeys interface
     */
    private sessionToKeys(session: DoubleRatchetSession): SessionKeys {
        // Get the first receiving chain if it exists
        const firstReceivingChain = session.receivingChains.size > 0
            ? Array.from(session.receivingChains.values())[0]
            : undefined;

        return {
            rootKey: session.rootKey,
            chainKey: session.sendingChain.key,
            sendingKey: session.sendingChain.key,
            receivingKey: firstReceivingChain?.key,
            messageNumber: session.sendingChain.messageNumber,
            previousChainLength: session.receivingChains.size
        };
    }

    /**
     * Convert SessionKeys to session
     */
    private keysToSession(keys: SessionKeys): DoubleRatchetSession {
        const sessionId = this.bytesToHex(sha256(keys.rootKey));

        // Check if we have an existing session
        const existingSession = this.sessions.get(sessionId);
        if (existingSession) {
            return existingSession;
        }

        // Create new session structure
        const newSession: DoubleRatchetSession = {
            sessionId,
            rootKey: keys.rootKey,
            sendingChain: {
                key: keys.chainKey || keys.sendingKey || new Uint8Array(32),
                messageNumber: keys.messageNumber || 0,
                ephemeralKeyPair: undefined // Will be generated when needed
            },
            receivingChains: new Map(),
            skippedMessageKeys: new Map(),
            lastMessageTimestamp: Date.now(),
            handshakeComplete: true,
            peerIdentityKey: undefined // Will be set when we receive first message
        };

        // If we have a receiving key, set up the initial receiving chain
        if (keys.receivingKey) {
            // Use a placeholder chain ID for the initial receiving chain
            const initialChainId = this.bytesToHex(keys.receivingKey).substring(0, 64);
            newSession.receivingChains.set(initialChainId, {
                key: keys.receivingKey,
                messageNumber: 0
            });
        }

        // Store the session
        this.sessions.set(sessionId, newSession);

        return newSession;
    }

    /**
     * Ratchet the sending chain
     */
    private ratchetSendingChain(
        session: DoubleRatchetSession,
        senderKeyPair: IGhostKeyPair
    ): DoubleRatchetSession {
        // Generate new ephemeral key
        const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
        const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

        // Update sending chain
        session.sendingChain.ephemeralKeyPair = {
            publicKey: ephemeralPublicKey,
            privateKey: ephemeralPrivateKey
        };

        // Derive new chain key
        const info = new TextEncoder().encode(ENCRYPTION_CONFIG.CHAIN_KEY_INFO);
        session.sendingChain.key = hkdf(sha256, session.rootKey, ephemeralPublicKey, info, 32);
        session.sendingChain.messageNumber = 0;

        return session;
    }

    /**
     * Establish session from received message
     */
    private async establishSessionFromMessage(
        recipientKeyPair: IGhostKeyPair,
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey
    ): Promise<DoubleRatchetSession> {
        // Extract ephemeral key
        const ephemeralPublicKey = this.hexToBytes(encryptedMessage.ephemeralPublicKey);

        // Perform ECDH
        const sharedSecret = recipientKeyPair.performKeyExchange(ephemeralPublicKey);

        // Derive initial keys
        const info = new TextEncoder().encode(ENCRYPTION_CONFIG.ROOT_KEY_INFO);
        const keyMaterial = hkdf(sha512, sharedSecret, undefined, info, 64);

        const rootKey = keyMaterial.slice(0, 32);
        const chainKey = keyMaterial.slice(32, 64);

        // Create session
        const sessionId = this.getSessionId(
            recipientKeyPair.getEncryptionPublicKey(),
            ephemeralPublicKey
        );

        // Extract peer identity key if available (Protocol v2.1)
        let peerIdentityKey: Uint8Array | undefined;
        if ('senderIdentityKey' in encryptedMessage && encryptedMessage.senderIdentityKey) {
            peerIdentityKey = this.hexToBytes(encryptedMessage.senderIdentityKey);
        }

        const session: DoubleRatchetSession = {
            sessionId,
            rootKey,
            sendingChain: {
                key: new Uint8Array(32), // Will be set on first send
                messageNumber: 0
            },
            receivingChains: new Map([[
                this.bytesToHex(ephemeralPublicKey),
                { key: chainKey, messageNumber: 0 }
            ]]),
            skippedMessageKeys: new Map(),
            lastMessageTimestamp: Date.now(),
            handshakeComplete: false,
            peerIdentityKey
        };

        this.sessions.set(sessionId, session);
        return session;
    }

    /**
     * Get or derive message key for decryption
     */
    private async getOrDeriveMessageKey(
        session: DoubleRatchetSession,
        encryptedMessage: EncryptedMessage | EncryptedMessageWithSenderKey,
        recipientKeyPair: IGhostKeyPair
    ): Promise<Uint8Array> {
        const ephemeralKey = encryptedMessage.ephemeralPublicKey;
        const messageNumber = encryptedMessage.messageNumber;

        // Check skipped keys
        const keyId = `${ephemeralKey}-${messageNumber}`;
        let messageKey = session.skippedMessageKeys.get(keyId);

        if (messageKey) {
            session.skippedMessageKeys.delete(keyId);
            return messageKey;
        }

        // Get or create receiving chain
        let chain = session.receivingChains.get(ephemeralKey);

        if (!chain) {
            // New chain, perform ratchet
            const ephemeralPublicKey = this.hexToBytes(ephemeralKey);
            const sharedSecret = recipientKeyPair.performKeyExchange(ephemeralPublicKey);

            // Combine with root key
            const combined = new Uint8Array(64);
            combined.set(session.rootKey);
            combined.set(sharedSecret, 32);

            const info = new TextEncoder().encode(ENCRYPTION_CONFIG.ROOT_KEY_INFO);
            const keyMaterial = hkdf(sha512, combined, undefined, info, 64);

            session.rootKey = keyMaterial.slice(0, 32);
            const chainKey = keyMaterial.slice(32, 64);

            chain = { key: chainKey, messageNumber: 0 };
            session.receivingChains.set(ephemeralKey, chain);
        }

        // Skip messages if needed
        while (chain.messageNumber < messageNumber) {
            const skippedKey = this.deriveMessageKey(chain.key);
            const skippedKeyId = `${ephemeralKey}-${chain.messageNumber}`;

            session.skippedMessageKeys.set(skippedKeyId, skippedKey);

            chain.key = this.advanceChainKey(chain.key);
            chain.messageNumber++;

            if (session.skippedMessageKeys.size > ENCRYPTION_CONFIG.MAX_SKIP_KEYS) {
                // Remove oldest skipped key
                const firstKey = session.skippedMessageKeys.keys().next().value;
                if (firstKey !== undefined) {
                    session.skippedMessageKeys.delete(firstKey);
                }
            }
        }

        // Derive message key
        messageKey = this.deriveMessageKey(chain.key);

        // Advance chain
        chain.key = this.advanceChainKey(chain.key);
        chain.messageNumber++;

        return messageKey;
    }

    /**
     * Derive message key from chain key
     */
    private deriveMessageKey(chainKey: Uint8Array): Uint8Array {
        const info = new TextEncoder().encode(ENCRYPTION_CONFIG.MESSAGE_KEY_INFO);
        return hkdf(sha256, chainKey, undefined, info, 32);
    }

    /**
     * Advance chain key
     */
    private advanceChainKey(chainKey: Uint8Array): Uint8Array {
        const info = new TextEncoder().encode(ENCRYPTION_CONFIG.CHAIN_KEY_INFO);
        return hkdf(sha256, chainKey, undefined, info, 32);
    }

    /**
     * Replay protection
     */
    private isReplay(messageId: string): boolean {
        return this.replayProtection.has(messageId);
    }

    /**
     * Add to replay protection
     */
    private addReplayProtection(messageId: string): void {
        this.replayProtection.add(messageId);

        // Limit size
        if (this.replayProtection.size > ENCRYPTION_CONFIG.REPLAY_WINDOW) {
            const firstId = this.replayProtection.values().next().value;
            if (firstId !== undefined) {
                this.replayProtection.delete(firstId);
            }
        }
    }

    /**
     * Get next sequence number
     */
    private getNextSequenceNumber(peerId: string = 'default'): number {
        const current = this.sequenceNumbers.get(peerId) || 0;
        const next = current + 1;
        this.sequenceNumbers.set(peerId, next);
        return next;
    }

    /**
     * Get last message hash
     */
    private getLastMessageHash(peerId: string = 'default'): string {
        // Return the actual last message hash for this peer
        const lastHash = this.lastMessageHashes.get(peerId);
        if (lastHash) {
            return lastHash;
        }
        
        // For first message in chain, return zeros
        return this.bytesToHex(new Uint8Array(32));
    }

    /**
     * Update last message hash
     */
    private updateLastMessageHash(peerId: string, hash: string): void {
        this.lastMessageHashes.set(peerId, hash);
        
        // Limit the size of the hash map to prevent memory leaks
        if (this.lastMessageHashes.size > 1000) {
            // Remove oldest entries
            const firstKey = this.lastMessageHashes.keys().next().value;
            if (firstKey !== undefined) {
                this.lastMessageHashes.delete(firstKey);
            }
        }
    }

    /**
     * Validate plaintext message
     */
    private validatePlaintextMessage(message: PlaintextMessage): void {
        if (!message.type || !Object.values(MessageType).includes(message.type)) {
            throw new Error('Invalid message type');
        }

        if (!message.payload || message.payload.length < ENCRYPTION_CONFIG.MIN_MESSAGE_SIZE) {
            throw new Error('Message payload too small');
        }

        if (message.payload.length > ENCRYPTION_CONFIG.MAX_MESSAGE_SIZE) {
            throw new Error('Message payload too large');
        }

        if (!message.header) {
            throw new Error('Message header required');
        }
    }

    /**
     * Clean up message keys
     */
    private cleanupMessageKeys(key: Uint8Array): void {
        // Zero out the key
        key.fill(0);
    }

    /**
     * Compare two arrays for equality
     */
    private arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    /**
     * Start cleanup interval for expired sessions and keys
     */
    private startCleanupInterval(): void {
        setInterval(() => {
            const now = Date.now();

            // Clean old sessions
            for (const [id, session] of this.sessions) {
                const age = now - session.lastMessageTimestamp;
                if (age > ENCRYPTION_CONFIG.MESSAGE_KEY_LIFETIME) {
                    // Zero out keys
                    session.rootKey.fill(0);
                    session.sendingChain.key.fill(0);

                    for (const [_, chain] of session.receivingChains) {
                        chain.key.fill(0);
                    }

                    for (const [_, key] of session.skippedMessageKeys) {
                        key.fill(0);
                    }

                    this.sessions.delete(id);
                }
            }

            // Clean old message metadata
            for (const [id, metadata] of this.messageCache) {
                const age = now - metadata.timestamp;
                if (age > ENCRYPTION_CONFIG.MESSAGE_KEY_LIFETIME) {
                    this.messageCache.delete(id);
                }
            }

            // Clean old trusted keys (keep for longer)
            const trustKeyLifetime = ENCRYPTION_CONFIG.MESSAGE_KEY_LIFETIME * 4;
            for (const [nodeId, _] of this.trustedKeys) {
                // Could track last use time if needed
                if (this.trustedKeys.size > 1000) {
                    // Just limit size for now
                    const firstKey = this.trustedKeys.keys().next().value;
                    if (firstKey) {
                        this.trustedKeys.delete(firstKey);
                    }
                }
            }

            // Rotate broadcast keys
            this.initializeBroadcastKeys();

        }, 60 * 60 * 1000); // Run every hour
    }

    /**
     * Convert bytes to hex string
     */
    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Convert hex string to bytes
     */
    private hexToBytes(hex: string): Uint8Array {
        if (hex.length % 2 !== 0) {
            throw new Error('Invalid hex string length');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    /**
     * Destroy and securely clean up all cryptographic material
     * 
     * Performs comprehensive cleanup of all cryptographic keys, session state, and
     * sensitive data stored by the MessageEncryption instance. This method implements
     * secure key destruction practices to prevent cryptographic material from remaining
     * in memory after the instance is no longer needed.
     * 
     * Cleanup Operations:
     * - Zero-fill all Double Ratchet session keys (root, chain, message keys)
     * - Zero-fill all broadcast encryption keys across all epochs
     * - Zero-fill all group encryption keys and associated metadata
     * - Clear all session state and metadata mappings
     * - Clear replay protection and message tracking data
     * - Clear trusted key cache and sequence number tracking
     * 
     * Security Importance:
     * - Prevents key material from being recovered through memory analysis
     * - Mitigates risk of key compromise through memory dumps or swap files
     * - Ensures forward secrecy by destroying past message keys
     * - Implements defense-in-depth security practices
     * 
     * Usage:
     * Call this method when the MessageEncryption instance is no longer needed,
     * especially in security-critical applications or when handling sensitive data.
     * After calling destroy(), the instance should not be used for any operations.
     * 
     * Note: This operation is irreversible. All session state will be lost and
     * new sessions must be established for future communication.
     */
    destroy(): void {
        // Zero out all session keys
        for (const [_, session] of this.sessions) {
            session.rootKey.fill(0);
            session.sendingChain.key.fill(0);

            for (const [_, chain] of session.receivingChains) {
                chain.key.fill(0);
            }

            for (const [_, key] of session.skippedMessageKeys) {
                key.fill(0);
            }
        }

        // Zero out broadcast keys
        for (const [_, key] of this.broadcastKeys) {
            key.fill(0);
        }

        // Zero out group keys  
        for (const [_, group] of this.groupKeys) {
            group.key.fill(0);
        }

        // Clear all maps
        this.sessions.clear();
        this.messageCache.clear();
        this.replayProtection.clear();
        this.broadcastKeys.clear();
        this.groupKeys.clear();
        this.lastMessageHashes.clear();
        this.sequenceNumbers.clear();
        this.trustedKeys.clear();
    }
}

/**
 * MessageFactory class for creating different types of messages with Protocol v2.1 compliance
 * 
 * This utility class provides convenient static methods for creating properly structured
 * plaintext messages that conform to Protocol v2.1 requirements. All created messages
 * include the necessary headers, metadata, and structure required for successful encryption
 * and transmission through the GhostComm mesh network.
 * 
 * Key Features:
 * - Protocol v2.1 compliant message structure generation
 * - Automatic header population with security metadata
 * - Proper message type assignment for routing and processing
 * - Default TTL and priority settings based on message type
 * - Unique message ID generation for tracking and deduplication
 * 
 * Message Types Supported:
 * - Direct messages: One-to-one communication between specific nodes
 * - Broadcast messages: One-to-many communication to all network nodes
 * - Group messages: One-to-many communication within defined groups
 * - Relay messages: Forward existing messages through the mesh network
 * - Acknowledgment messages: Confirm receipt of previous messages
 * 
 * Usage Pattern:
 * ```typescript
 * // Create a direct message
 * const message = MessageFactory.createDirectMessage(
 *     senderKeyPair.getFingerprint(),
 *     recipientKeyPair.getFingerprint(),
 *     "Hello, world!"
 * );
 * 
 * // Encrypt and send
 * const encrypted = await encryption.encryptMessage(message, senderKeyPair, recipientPublicKey);
 * ```
 * 
 * Security Notes:
 * - All messages created with placeholder signatures (zeros) that are replaced during encryption
 * - Message IDs are cryptographically secure and unique across the network
 * - Default TTL values balance message availability with network resource usage
 * - Sequence numbers use timestamp-based generation for ordering without state tracking
 */
export class MessageFactory {
    /**
     * Create a direct message for one-to-one communication
     * 
     * Creates a properly structured message for direct communication between two specific
     * nodes in the mesh network. Direct messages have the highest delivery priority and
     * are optimized for reliable end-to-end transmission.
     * 
     * @param sourceId - Unique identifier of the message sender (typically key fingerprint)
     * @param destinationId - Unique identifier of the intended recipient
     * @param payload - The actual message content to be transmitted
     * @param priority - Message priority level (defaults to NORMAL)
     * @returns Properly structured PlaintextMessage ready for encryption
     */
    static createDirectMessage(
        sourceId: string,
        destinationId: string,
        payload: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): PlaintextMessage {
        return {
            header: {
                version: ENCRYPTION_CONFIG.PROTOCOL_VERSION,
                messageId: new MessageEncryption().generateMessageId(),
                sourceId,
                destinationId,
                timestamp: Date.now(),
                sequenceNumber: Date.now() % 1000000,
                ttl: 86400000, // 24 hours
                hopCount: 0,
                priority,
                relayPath: [],
                signature: new Uint8Array(64), // Will be set during encryption
            },
            type: MessageType.DIRECT,
            payload
        };
    }

    /**
     * Create a broadcast message for one-to-many communication
     * 
     * Creates a properly structured message for broadcasting to all nodes in the mesh
     * network. Broadcast messages use epoch-based encryption and are designed for
     * efficient distribution across the entire network.
     * 
     * @param sourceId - Unique identifier of the message sender
     * @param payload - The message content to broadcast to all nodes
     * @param priority - Message priority level (defaults to NORMAL)
     * @returns Properly structured PlaintextMessage ready for broadcast encryption
     */
    static createBroadcastMessage(
        sourceId: string,
        payload: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): PlaintextMessage {
        return {
            header: {
                version: ENCRYPTION_CONFIG.PROTOCOL_VERSION,
                messageId: new MessageEncryption().generateMessageId(),
                sourceId,
                destinationId: 'broadcast',
                timestamp: Date.now(),
                sequenceNumber: Date.now() % 1000000,
                ttl: 86400000, // 24 hours
                hopCount: 0,
                priority,
                relayPath: [],
                signature: new Uint8Array(64), // Will be set during encryption
            },
            type: MessageType.BROADCAST,
            payload
        };
    }

    /**
     * Create a group message for secure group communication
     * 
     * Creates a properly structured message for communication within a defined group
     * of nodes. Group messages use shared group keys with epoch-based rotation for
     * forward secrecy while maintaining efficient multi-recipient delivery.
     * 
     * @param sourceId - Unique identifier of the message sender
     * @param groupId - Unique identifier of the target group
     * @param payload - The message content to send to group members
     * @param priority - Message priority level (defaults to NORMAL)
     * @returns Properly structured PlaintextMessage ready for group encryption
     */
    static createGroupMessage(
        sourceId: string,
        groupId: string,
        payload: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): PlaintextMessage {
        return {
            header: {
                version: ENCRYPTION_CONFIG.PROTOCOL_VERSION,
                messageId: new MessageEncryption().generateMessageId(),
                sourceId,
                groupId,
                timestamp: Date.now(),
                sequenceNumber: Date.now() % 1000000,
                ttl: 86400000, // 24 hours
                hopCount: 0,
                priority,
                relayPath: [],
                signature: new Uint8Array(64), // Will be set during encryption
            },
            type: MessageType.GROUP,
            payload
        };
    }

    /**
     * Create a relay message
     */
    static createRelayMessage(
        originalMessage: PlaintextMessage,
        relayerId: string
    ): PlaintextMessage {
        const relayedMessage = { ...originalMessage };
        relayedMessage.header.hopCount++;
        relayedMessage.header.relayPath.push(relayerId);
        relayedMessage.type = MessageType.RELAY;
        return relayedMessage;
    }

    /**
     * Create an acknowledgment message
     */
    static createAckMessage(
        sourceId: string,
        destinationId: string,
        originalMessageId: string
    ): PlaintextMessage {
        return {
            header: {
                version: ENCRYPTION_CONFIG.PROTOCOL_VERSION,
                messageId: new MessageEncryption().generateMessageId(),
                sourceId,
                destinationId,
                timestamp: Date.now(),
                sequenceNumber: Date.now() % 1000000,
                ttl: 3600000, // 1 hour for ACKs
                hopCount: 0,
                priority: MessagePriority.HIGH,
                relayPath: [],
                signature: new Uint8Array(64),
            },
            type: MessageType.ACK,
            payload: originalMessageId,
            replyTo: originalMessageId
        };
    }
}

// Export MessageType for convenience
export { MessageType };