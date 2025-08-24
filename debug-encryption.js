// debug-encryption.js - Debug version with detailed logging

const { GhostKeyPair } = require('./core/dist/crypto/keypair');
const { x25519 } = require('@noble/curves/ed25519');
const { randomBytes } = require('@noble/hashes/utils');
const { sha256 } = require('@noble/hashes/sha256');
const { hkdf } = require('@noble/hashes/hkdf');
const { chacha20poly1305 } = require('@noble/ciphers/chacha');

function bytesToHex(bytes) {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

function hexToBytes(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error('Invalid hex string length');
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

async function debugEncryptDecrypt() {
    console.log('🔍 Debug Encryption/Decryption Process');
    console.log('======================================');

    try {
        // Create test key pairs
        const alice = new GhostKeyPair();
        const bob = new GhostKeyPair();

        console.log('Alice fingerprint:', alice.getFingerprint());
        console.log('Bob fingerprint:', bob.getFingerprint());

        // Test message
        const message = {
            type: 'direct',
            senderId: alice.getFingerprint(),
            recipientId: bob.getFingerprint(),
            timestamp: Date.now(),
            payload: 'Hello Bob!',
            messageId: 'test123'
        };

        console.log('\n📝 Original message:', JSON.stringify(message, null, 2));

        // ENCRYPTION PROCESS
        console.log('\n🔒 ENCRYPTION PROCESS:');

        // 1. Generate ephemeral keys
        const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
        const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
        console.log('1. Ephemeral private key length:', ephemeralPrivateKey.length);
        console.log('1. Ephemeral public key length:', ephemeralPublicKey.length);
        console.log('1. Ephemeral public key hex:', bytesToHex(ephemeralPublicKey));

        // 2. ECDH
        const bobPublicKey = bob.getEncryptionPublicKey();
        const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, bobPublicKey);
        console.log('2. Bob public key length:', bobPublicKey.length);
        console.log('2. Shared secret length:', sharedSecret.length);
        console.log('2. Shared secret hex (first 16 bytes):', bytesToHex(sharedSecret.slice(0, 16)));

        // 3. Key derivation
        const info = new TextEncoder().encode('GhostComm-Message-v1');
        const salt = new Uint8Array(32);
        const derivedKey = hkdf(sha256, sharedSecret, salt, info, 32);
        console.log('3. Derived key length:', derivedKey.length);
        console.log('3. Derived key hex (first 16 bytes):', bytesToHex(derivedKey.slice(0, 16)));

        // 4. Nonce
        const nonce = randomBytes(12);
        console.log('4. Nonce length:', nonce.length);
        console.log('4. Nonce hex:', bytesToHex(nonce));

        // 5. Plaintext
        const plaintextBytes = new TextEncoder().encode(JSON.stringify(message));
        console.log('5. Plaintext length:', plaintextBytes.length);
        console.log('5. Plaintext preview:', new TextDecoder().decode(plaintextBytes.slice(0, 50)));

        // 6. Encryption
        const cipher = chacha20poly1305(derivedKey, nonce);
        const encryptedData = cipher.encrypt(plaintextBytes);
        console.log('6. Encrypted data length:', encryptedData.length);
        console.log('6. Expected length:', plaintextBytes.length + 16);

        const ciphertext = encryptedData.slice(0, -16);
        const authTag = encryptedData.slice(-16);
        console.log('6. Ciphertext length:', ciphertext.length);
        console.log('6. Auth tag length:', authTag.length);
        console.log('6. Auth tag hex:', bytesToHex(authTag));

        // DECRYPTION PROCESS
        console.log('\n🔓 DECRYPTION PROCESS:');

        // 1. Parse ephemeral key
        const receivedEphemeralKey = ephemeralPublicKey; // In real scenario, this comes from hex
        console.log('1. Received ephemeral key matches:', bytesToHex(receivedEphemeralKey) === bytesToHex(ephemeralPublicKey));

        // 2. ECDH (Bob's perspective)
        const bobSharedSecret = bob.performKeyExchange(receivedEphemeralKey);
        console.log('2. Bob shared secret length:', bobSharedSecret.length);
        console.log('2. Shared secrets match:', bytesToHex(sharedSecret) === bytesToHex(bobSharedSecret));

        // 3. Key derivation (Bob's perspective)
        const bobDerivedKey = hkdf(sha256, bobSharedSecret, salt, info, 32);
        console.log('3. Bob derived key matches:', bytesToHex(derivedKey) === bytesToHex(bobDerivedKey));

        // 4. Reconstruct encrypted data
        const reconstructedData = new Uint8Array(ciphertext.length + authTag.length);
        reconstructedData.set(ciphertext, 0);
        reconstructedData.set(authTag, ciphertext.length);
        console.log('4. Reconstructed length:', reconstructedData.length);
        console.log('4. Original encrypted length:', encryptedData.length);
        console.log('4. Data matches:', bytesToHex(reconstructedData) === bytesToHex(encryptedData));

        // 5. Decryption
        const bobCipher = chacha20poly1305(bobDerivedKey, nonce);
        const decryptedBytes = bobCipher.decrypt(reconstructedData);
        console.log('5. Decrypted length:', decryptedBytes.length);

        // 6. Parse result
        const decryptedJson = new TextDecoder().decode(decryptedBytes);
        const decryptedMessage = JSON.parse(decryptedJson);
        console.log('6. Decrypted message:', JSON.stringify(decryptedMessage, null, 2));

        console.log('\n✅ Debug encryption/decryption completed successfully!');

    } catch (error) {
        console.error('❌ Debug failed:', error.message);
        console.error(error.stack);
    }
}

debugEncryptDecrypt();