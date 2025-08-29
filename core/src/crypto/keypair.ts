// core/src/crypto/keypair.ts
// Enhanced GhostComm Key Pair Management with Double Ratchet Support

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
 * Constants for cryptographic operations
 */
const CONSTANTS = {
    // Protocol version
    PROTOCOL_VERSION: 2,

    // Key sizes (in bytes)
    ED25519_KEY_SIZE: 32,
    X25519_KEY_SIZE: 32,
    FINGERPRINT_SIZE: 32,  // 256-bit fingerprint

    // Derivation parameters
    KDF_SALT_SIZE: 32,
    KDF_INFO: 'GhostComm-v2-KeyDerivation',
    SESSION_INFO: 'GhostComm-v2-Session',

    // Pre-key settings
    DEFAULT_PREKEY_COUNT: 100,
    MAX_PREKEY_COUNT: 1000,
    PREKEY_ROTATION_INTERVAL: 7 * 24 * 60 * 60 * 1000, // 7 days

    // Security parameters
    MIN_PBKDF2_ITERATIONS: 100000,
    DEFAULT_PBKDF2_ITERATIONS: 250000,

    // Double Ratchet parameters
    MAX_SKIP_MESSAGES: 1000,  // Maximum messages to skip in a chain
    MESSAGE_KEY_SEED: 'GhostComm-MessageKeys',
    CHAIN_KEY_SEED: 'GhostComm-ChainKeys',
    ROOT_KEY_SEED: 'GhostComm-RootKeys'
};

/**
 * Enhanced GhostKeyPair with advanced cryptographic features
 * Implements Double Ratchet, pre-keys, and secure key management
 */
export class GhostKeyPair implements IGhostKeyPair {
    private signingKeyPair: KeyPair;
    private encryptionKeyPair: KeyPair;
    private preKeys: Map<number, PreKey>;
    private currentPreKeyId: number;
    private createdAt: number;
    private lastRotation: number;
    private version: number;

    // Session management for Double Ratchet
    private activeSessions: Map<string, SessionKeys>;
    private messageKeyCache: Map<string, Uint8Array>;

    constructor(
        signingKeyPair?: KeyPair,
        encryptionKeyPair?: KeyPair,
        preKeys?: PreKey[]
    ) {
        this.version = CONSTANTS.PROTOCOL_VERSION;
        this.createdAt = Date.now();
        this.lastRotation = Date.now();

        // Initialize or generate key pairs
        this.signingKeyPair = signingKeyPair || this.generateSigningKeyPair();
        this.encryptionKeyPair = encryptionKeyPair || this.generateEncryptionKeyPair();

        // Initialize pre-keys
        this.preKeys = new Map();
        this.currentPreKeyId = 0;

        if (preKeys && preKeys.length > 0) {
            preKeys.forEach(pk => this.preKeys.set(pk.keyId, pk));
            this.currentPreKeyId = Math.max(...preKeys.map(pk => pk.keyId)) + 1;
        } else {
            // Generate initial pre-keys
            this.generatePreKeys(CONSTANTS.DEFAULT_PREKEY_COUNT);
        }

        // Initialize session management
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

    /**
     * Generate a new Ed25519 key pair for message signing
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
     * Generate a new X25519 key pair for encryption
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

    /**
     * Generate pre-keys for asynchronous key exchange
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

            // Sign the pre-key with our identity key
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
     * Get an unused pre-key for key exchange
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
     * Mark a pre-key as used
     */
    markPreKeyUsed(keyId: number): void {
        const preKey = this.preKeys.get(keyId);
        if (preKey && !preKey.usedAt) {
            preKey.usedAt = Date.now();
        }
    }

    /**
     * Rotate encryption key for forward secrecy
     */
    rotateEncryptionKey(): KeyPair {
        // Store old key for decryption of past messages
        const oldKey = { ...this.encryptionKeyPair };

        // Generate new encryption key
        this.encryptionKeyPair = this.generateEncryptionKeyPair();
        this.lastRotation = Date.now();

        // Generate new pre-keys with the new encryption key
        this.generatePreKeys(CONSTANTS.DEFAULT_PREKEY_COUNT);

        return oldKey;
    }

    /**
     * Initialize a Double Ratchet session with a peer
     */
    initializeSession(theirPublicKey: Uint8Array): SessionKeys {
        const sessionId = this.getSessionId(theirPublicKey);

        // Check if session already exists
        const existingSession = this.activeSessions.get(sessionId);
        if (existingSession) {
            return existingSession;
        }

        // Perform initial ECDH
        const sharedSecret = this.performKeyExchange(theirPublicKey);

        // Derive initial root and chain keys using HKDF
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
     * Perform a Double Ratchet step
     */
    ratchetSession(session: SessionKeys, theirEphemeralKey?: Uint8Array): SessionKeys {
        if (!theirEphemeralKey) {
            // Symmetric ratchet (same chain)
            const info = new TextEncoder().encode(CONSTANTS.CHAIN_KEY_SEED);
            const newChainKey = hkdf(sha256, session.chainKey, undefined, info, 32);

            const updatedSession: SessionKeys = {
                ...session,
                chainKey: newChainKey,
                messageNumber: session.messageNumber + 1
            };

            // Update stored session
            const sessionId = this.bytesToHex(sha256(session.rootKey));
            this.activeSessions.set(sessionId, updatedSession);

            return updatedSession;
        }

        // Asymmetric ratchet (new chain)
        const sharedSecret = this.performKeyExchange(theirEphemeralKey);

        // Combine with root key
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

        // Update stored session with new ID (root key changed)
        const newSessionId = this.bytesToHex(sha256(newRootKey));
        this.activeSessions.set(newSessionId, updatedSession);

        // Remove old session if different
        const oldSessionId = this.bytesToHex(sha256(session.rootKey));
        if (oldSessionId !== newSessionId) {
            this.activeSessions.delete(oldSessionId);
        }

        return updatedSession;
    }

    /**
     * Derive a message key from a chain key
     */
    private deriveMessageKey(chainKey: Uint8Array): Uint8Array {
        const info = new TextEncoder().encode(CONSTANTS.MESSAGE_KEY_SEED);
        return hkdf(sha256, chainKey, undefined, info, 32);
    }

    /**
     * Get session ID for a peer
     */
    private getSessionId(theirPublicKey: Uint8Array): string {
        const combined = new Uint8Array(64);
        combined.set(this.encryptionKeyPair.publicKey);
        combined.set(theirPublicKey, 32);
        const hash = sha256(combined);
        return this.bytesToHex(hash);
    }

    /**
     * Create a GhostKeyPair from a seed phrase (deterministic)
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

    /**
     * Sign a message with the private signing key
     */
    sign(message: Uint8Array): Uint8Array {
        return ed25519.sign(message, this.signingKeyPair.privateKey);
    }

    /**
     * Sign a message string (convenience method)
     */
    signMessage(message: Uint8Array | string): Uint8Array {
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;
        return this.sign(messageBytes);
    }

    /**
     * Verify a signature against a public key
     */
    static verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
        try {
            return ed25519.verify(signature, message, publicKey);
        } catch {
            return false;
        }
    }

    /**
     * Verify a signature (instance method)
     */
    verifySignature(message: Uint8Array | string, signature: Uint8Array, publicKey: Uint8Array): boolean {
        const messageBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;
        return GhostKeyPair.verify(messageBytes, signature, publicKey);
    }

    /**
     * Perform ECDH key exchange with proper key derivation
     */
    performKeyExchange(peerPublicKey: Uint8Array, salt?: Uint8Array): Uint8Array {
        // Validate peer public key
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

    /**
     * Generate a secure 256-bit fingerprint for key verification
     */
    getFingerprint(): string {
        // Combine both public keys
        const combined = new Uint8Array(
            this.signingKeyPair.publicKey.length +
            this.encryptionKeyPair.publicKey.length
        );
        combined.set(this.signingKeyPair.publicKey);
        combined.set(this.encryptionKeyPair.publicKey, this.signingKeyPair.publicKey.length);

        // Use SHA-256 for consistent fingerprints (BLAKE3 might not be available)
        const hash = sha256(combined);

        // Return full 256-bit fingerprint as hex
        return this.bytesToHex(hash);
    }

    /**
     * Get a short fingerprint for display (first 16 bytes of full fingerprint)
     */
    getShortFingerprint(): string {
        const fullFingerprint = this.getFingerprint();
        return fullFingerprint.substring(0, 32); // 16 bytes = 32 hex chars
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

    /**
     * Clear sensitive data from memory
     */
    destroy(): void {
        // Clear private keys
        this.signingKeyPair.privateKey.fill(0);
        this.encryptionKeyPair.privateKey.fill(0);

        // Clear pre-keys
        for (const [_, preKey] of this.preKeys) {
            preKey.privateKey.fill(0);
        }
        this.preKeys.clear();

        // Clear sessions
        for (const [_, session] of this.activeSessions) {
            session.rootKey.fill(0);
            session.chainKey.fill(0);
            if (session.sendingKey) session.sendingKey.fill(0);
            if (session.receivingKey) session.receivingKey.fill(0);
        }
        this.activeSessions.clear();

        // Clear message key cache
        for (const [_, key] of this.messageKeyCache) {
            key.fill(0);
        }
        this.messageKeyCache.clear();
    }
}