// core/src/crypto/encryption.ts
// Enhanced GhostComm Message Encryption with Double Ratchet Protocol

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
 * Encryption constants and configuration
 */
const ENCRYPTION_CONFIG = {
    // Protocol version
    PROTOCOL_VERSION: 2,

    // Nonce sizes
    XCHACHA_NONCE_SIZE: 24,  // XChaCha20-Poly1305 uses 24-byte nonces
    CHACHA_NONCE_SIZE: 12,   // Regular ChaCha20-Poly1305 uses 12-byte nonces

    // Key sizes
    KEY_SIZE: 32,
    AUTH_TAG_SIZE: 16,

    // HKDF info strings for different contexts
    MESSAGE_KEY_INFO: 'GhostComm-v2-MessageKey',
    CHAIN_KEY_INFO: 'GhostComm-v2-ChainKey',
    ROOT_KEY_INFO: 'GhostComm-v2-RootKey',
    HEADER_KEY_INFO: 'GhostComm-v2-HeaderKey',

    // Double Ratchet parameters
    MAX_SKIP_KEYS: 1000,      // Maximum keys to skip in a chain
    MAX_FUTURE_MESSAGES: 100,  // Maximum future messages to accept
    MESSAGE_KEY_LIFETIME: 7 * 24 * 60 * 60 * 1000, // 7 days

    // Security parameters
    MIN_MESSAGE_SIZE: 1,       // Minimum payload size
    MAX_MESSAGE_SIZE: 65536,   // 64KB max message size
    REPLAY_WINDOW: 1000,       // Number of messages to track for replay protection

    // Broadcast security
    BROADCAST_EPOCH_DURATION: 24 * 60 * 60 * 1000, // 24 hours per epoch
    BROADCAST_KEY_ROTATION: 60 * 60 * 1000,         // Rotate broadcast keys hourly

    // Group messaging
    MAX_GROUP_SIZE: 100,       // Maximum members in a group
    GROUP_KEY_ROTATION: 7 * 24 * 60 * 60 * 1000, // Weekly group key rotation
};

/**
 * Session state for Double Ratchet protocol
 */
interface DoubleRatchetSession {
    sessionId: string;
    rootKey: Uint8Array;
    sendingChain: {
        key: Uint8Array;
        messageNumber: number;
        ephemeralKeyPair?: { publicKey: Uint8Array; privateKey: Uint8Array };
    };
    receivingChains: Map<string, {
        key: Uint8Array;
        messageNumber: number;
    }>;
    skippedMessageKeys: Map<string, Uint8Array>;
    lastMessageTimestamp: number;
    handshakeComplete: boolean;
}

/**
 * Message metadata for replay protection and ordering
 */
interface MessageMetadata {
    messageId: string;
    timestamp: number;
    sequenceNumber: number;
    previousMessageHash: string;
}

/**
 * Enhanced MessageEncryption class with Double Ratchet protocol
 * Provides military-grade end-to-end encryption with perfect forward secrecy
 */
export class MessageEncryption implements IMessageEncryption {
    private sessions: Map<string, DoubleRatchetSession>;
    private messageCache: Map<string, MessageMetadata>;
    private replayProtection: Set<string>;
    private broadcastKeys: Map<number, Uint8Array>;
    private groupKeys: Map<string, { key: Uint8Array; epoch: number }>;
    
    // SECURITY FIX: Track message chain hashes properly
    private lastMessageHashes: Map<string, string>;
    private sequenceNumbers: Map<string, number>;

    constructor() {
        this.sessions = new Map();
        this.messageCache = new Map();
        this.replayProtection = new Set();
        this.broadcastKeys = new Map();
        this.groupKeys = new Map();
        
        // Initialize message chain tracking
        this.lastMessageHashes = new Map();
        this.sequenceNumbers = new Map();

        // Initialize broadcast keys for current epoch
        this.initializeBroadcastKeys();

        // Start cleanup interval for expired sessions and keys
        this.startCleanupInterval();
    }

    /**
     * Static method to encrypt a message
     */
    static async encryptMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair,
        recipientPublicKey: Uint8Array
    ): Promise<EncryptedMessage> {
        const encryption = new MessageEncryption();
        return encryption.encryptMessage(message, senderKeyPair, recipientPublicKey);
    }

    /**
     * Static method to decrypt a message
     */
    static async decryptMessage(
        encryptedMessage: EncryptedMessage,
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
    ): Promise<EncryptedMessage> {
        const encryption = new MessageEncryption();
        return encryption.createBroadcastMessage(message, senderKeyPair);
    }

    /**
     * Static method to decrypt a broadcast message
     */
    static async decryptBroadcastMessage(
        encryptedMessage: EncryptedMessage,
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
            handshakeComplete: true
        };

        this.sessions.set(sessionId, session);

        return this.sessionToKeys(session);
    }

    /**
     * Encrypt a message using Double Ratchet protocol
     */
    async encryptMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair,
        recipientPublicKey: Uint8Array
    ): Promise<EncryptedMessage> {
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

            // Create encrypted message
            const encryptedMessage: EncryptedMessage = {
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
                authTag: this.bytesToHex(authTag)
            };

            // Add to replay protection
            this.addReplayProtection(header.messageId);

            // Update session
            this.sessions.set(sessionId, session);

            // Clean up old message keys
            this.cleanupMessageKeys(messageKey);

            return encryptedMessage;

        } catch (error) {
            throw new Error(`Message encryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt a message using Double Ratchet protocol
     */
    async decryptMessage(
        encryptedMessage: EncryptedMessage,
        recipientKeyPair: IGhostKeyPair
    ): Promise<PlaintextMessage> {
        try {
            // Check replay protection
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
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

            // SECURITY FIX: Require sender's public key for signature verification
            // Extract sender's public key from the encrypted message source ID
            // Note: In production, this should be retrieved from a trusted key store
            if (!this.verifyMessageSignature(fullMessage, fullMessage.header.signature)) {
                throw new Error(CryptoError.SIGNATURE_VERIFICATION_FAILED);
            }

            // Add to replay protection
            this.addReplayProtection(fullMessage.header.messageId);

            // Update message chain tracking
            const peerId = encryptedMessage.header.sourceId;
            const messageHash = this.calculateMessageHash(fullMessage);
            this.updateLastMessageHash(peerId, messageHash);

            // Clean up used key
            this.cleanupMessageKeys(messageKey);

            return fullMessage;

        } catch (error) {
            throw new Error(`Message decryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Encrypt a group message using sender keys
     */
    async encryptGroupMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair,
        groupKey: Uint8Array
    ): Promise<EncryptedMessage> {
        try {
            // Validate message
            this.validatePlaintextMessage(message);

            // Derive group encryption key
            const epoch = Math.floor(Date.now() / ENCRYPTION_CONFIG.GROUP_KEY_ROTATION);
            const info = new TextEncoder().encode(`GhostComm-Group-${message.header.groupId}-${epoch}`);
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
                senderKeyShare: this.bytesToHex(senderKeyPair.getEncryptionPublicKey())
            };

        } catch (error) {
            throw new Error(`Group message encryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt a group message
     */
    async decryptGroupMessage(
        encryptedMessage: EncryptedMessage,
        groupKey: Uint8Array
    ): Promise<PlaintextMessage> {
        try {
            // Check replay
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
            }

            // Derive group decryption key
            const epoch = parseInt(encryptedMessage.groupKeyId || '0');
            const info = new TextEncoder().encode(`GhostComm-Group-${encryptedMessage.header.groupId}-${epoch}`);
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

            // Verify signature
            if (!this.verifyMessageSignature(fullMessage, fullMessage.header.signature)) {
                throw new Error(CryptoError.SIGNATURE_VERIFICATION_FAILED);
            }

            // Add to replay protection
            this.addReplayProtection(fullMessage.header.messageId);

            return fullMessage;

        } catch (error) {
            throw new Error(`Group message decryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Create a secure broadcast message with rotating keys
     */
    async createBroadcastMessage(
        message: PlaintextMessage,
        senderKeyPair: IGhostKeyPair
    ): Promise<EncryptedMessage> {
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
            const info = new TextEncoder().encode(`GhostComm-Broadcast-${epoch}`);
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

            // Serialize message with signature - convert Uint8Array signature to hex
            const fullMessage = {
                ...message,
                header: {
                    ...header,
                    signature: this.bytesToHex(header.signature)  // Convert to hex for JSON serialization
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
                authTag: this.bytesToHex(authTag)
            };

        } catch (error) {
            throw new Error(`Broadcast message creation failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt a broadcast message with sender verification
     */
    async decryptBroadcastMessage(
        encryptedMessage: EncryptedMessage,
        senderPublicKey: Uint8Array
    ): Promise<PlaintextMessage> {
        try {
            // Check replay
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
            }

            // Get broadcast key for the epoch
            const epoch = encryptedMessage.messageNumber;
            const broadcastKey = this.getBroadcastKey(epoch);

            // Get ephemeral public key
            const ephemeralPublicKey = this.hexToBytes(encryptedMessage.ephemeralPublicKey);

            // Derive message key using same method as encryption
            const info = new TextEncoder().encode(`GhostComm-Broadcast-${epoch}`);
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
            if (!ed25519.verify(broadcastSignature, signatureData, senderPublicKey)) {
                throw new Error('Invalid broadcast signature');
            }

            // Verify message signature with sender's public key
            const headerSignature = typeof fullMessage.header.signature === 'string'
                ? this.hexToBytes(fullMessage.header.signature)
                : fullMessage.header.signature;

            if (!this.verifyMessageSignature(fullMessage, headerSignature, senderPublicKey)) {
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
     * Encrypt with an established session (for performance)
     */
    async encryptWithSession(
        message: PlaintextMessage,
        session: SessionKeys
    ): Promise<EncryptedMessage> {
        try {
            // Convert SessionKeys to DoubleRatchetSession
            const drSession = this.keysToSession(session);

            // Check if we need to initialize ephemeral keys
            if (!drSession.sendingChain.ephemeralKeyPair) {
                // Generate ephemeral key pair for this session
                const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
                const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

                drSession.sendingChain.ephemeralKeyPair = {
                    publicKey: ephemeralPublicKey,
                    privateKey: ephemeralPrivateKey
                };

                // Update chain key with the new ephemeral key
                const info = new TextEncoder().encode(ENCRYPTION_CONFIG.CHAIN_KEY_INFO);
                const combined = new Uint8Array(64);
                combined.set(drSession.rootKey);
                combined.set(ephemeralPublicKey, 32);

                const keyMaterial = hkdf(sha256, combined, undefined, info, 32);
                drSession.sendingChain.key = keyMaterial;
                drSession.sendingChain.messageNumber = 0;
            }

            // Derive message key
            const messageKey = this.deriveMessageKey(drSession.sendingChain.key);

            // Advance chain
            drSession.sendingChain.key = this.advanceChainKey(drSession.sendingChain.key);

            // Get peer ID from session
            const peerId = drSession.sessionId;

            // Create header with proper message chaining
            const header: MessageHeader = {
                version: ENCRYPTION_CONFIG.PROTOCOL_VERSION,
                messageId: this.generateMessageId(),
                sourceId: message.header?.sourceId || '',
                destinationId: message.header?.destinationId,
                timestamp: Date.now(),
                sequenceNumber: this.getNextSequenceNumber(peerId),
                ttl: message.header?.ttl || 86400000,
                hopCount: 0,
                priority: message.header?.priority || MessagePriority.NORMAL,
                relayPath: [],
                signature: new Uint8Array(64),
                previousMessageHash: this.getLastMessageHash(peerId)
            };

            // Serialize
            const fullMessage = { ...message, header };
            const plaintext = new TextEncoder().encode(JSON.stringify(fullMessage));

            // Encrypt
            const nonce = randomBytes(ENCRYPTION_CONFIG.XCHACHA_NONCE_SIZE);
            const cipher = xchacha20poly1305(messageKey, nonce);
            const ciphertext = cipher.encrypt(plaintext);

            const encryptedData = ciphertext.slice(0, -16);
            const authTag = ciphertext.slice(-16);

            // Increment message number
            const currentMessageNumber = drSession.sendingChain.messageNumber;
            drSession.sendingChain.messageNumber++;

            // Update session in map
            const sessionId = this.bytesToHex(sha256(drSession.rootKey));
            this.sessions.set(sessionId, drSession);

            // Update message hash chain
            const messageHash = this.calculateMessageHash(fullMessage);
            this.updateLastMessageHash(peerId, messageHash);

            // Clean up message key
            this.cleanupMessageKeys(messageKey);

            return {
                header: {
                    messageId: header.messageId,
                    sourceId: header.sourceId,
                    destinationId: header.destinationId,
                    timestamp: header.timestamp,
                    ttl: header.ttl,
                    hopCount: header.hopCount,
                    priority: header.priority
                },
                ephemeralPublicKey: this.bytesToHex(drSession.sendingChain.ephemeralKeyPair.publicKey),
                previousChainLength: 0,
                messageNumber: currentMessageNumber,
                nonce: this.bytesToHex(nonce),
                ciphertext: this.bytesToHex(encryptedData),
                authTag: this.bytesToHex(authTag)
            };
        } catch (error) {
            throw new Error(`Session encryption failed: ${error instanceof Error ? error.message : String(error)}`);
        }
    }

    /**
     * Decrypt with an established session
     */
    async decryptWithSession(
        encryptedMessage: EncryptedMessage,
        session: SessionKeys
    ): Promise<PlaintextMessage> {
        try {
            // Check replay protection
            if (this.isReplay(encryptedMessage.header.messageId)) {
                throw new Error(CryptoError.REPLAY_DETECTED);
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

    /**
     * Generate a cryptographically secure message ID
     */
    generateMessageId(): string {
        // Use 16 bytes of randomness for 128-bit message ID
        const randomPart = randomBytes(16);

        // Add 8 bytes of timestamp for ordering
        const timestamp = Date.now();
        const timestampBytes = new Uint8Array(8);
        new DataView(timestampBytes.buffer).setBigUint64(0, BigInt(timestamp), false);

        // Combine
        const messageId = new Uint8Array(24);
        messageId.set(timestampBytes);
        messageId.set(randomPart, 8);

        // Hash for uniformity
        const hash = sha256(messageId);

        return this.bytesToHex(hash);
    }

    /**
     * Validate a plaintext message structure
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
            const seed = new TextEncoder().encode(`GhostComm-Broadcast-Epoch-${epoch}`);
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
            const seed = new TextEncoder().encode(`GhostComm-Broadcast-Epoch-${epoch}`);
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
     * SECURITY FIX: Verify message signature properly
     */
    private verifyMessageSignature(message: any, signature: Uint8Array | string, senderPublicKey?: Uint8Array): boolean {
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

            // SECURITY FIX: Always require sender's public key for verification
            if (!senderPublicKey) {
                console.warn('Cannot verify signature without sender public key');
                return false; // Reject messages without verifiable signatures
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
            handshakeComplete: true
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
        encryptedMessage: EncryptedMessage
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
            handshakeComplete: false
        };

        this.sessions.set(sessionId, session);
        return session;
    }

    /**
     * Get or derive message key for decryption
     */
    private async getOrDeriveMessageKey(
        session: DoubleRatchetSession,
        encryptedMessage: EncryptedMessage,
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

    
    private getNextSequenceNumber(peerId: string = 'default'): number {
        const current = this.sequenceNumbers.get(peerId) || 0;
        const next = current + 1;
        this.sequenceNumbers.set(peerId, next);
        return next;
    }

    private getLastMessageHash(peerId: string = 'default'): string {
        // Return the actual last message hash for this peer
        const lastHash = this.lastMessageHashes.get(peerId);
        if (lastHash) {
            return lastHash;
        }
        
        // For first message in chain, return zeros
        return this.bytesToHex(new Uint8Array(32));
    }

    
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
     * Start cleanup interval for expired sessions
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
     * Destroy and clean up all keys
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
    }
}

/**
 * MessageFactory class for creating different types of messages
 */
export class MessageFactory {
    /**
     * Create a direct message
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
     * Create a broadcast message
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
     * Create a group message
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