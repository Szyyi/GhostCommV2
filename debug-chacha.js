// debug-chacha.js - Test ChaCha20-Poly1305 encryption/decryption

const { randomBytes } = require('@noble/hashes/utils');
const { chacha20poly1305 } = require('@noble/ciphers/chacha');

console.log('🧪 Testing ChaCha20-Poly1305 Encryption/Decryption');
console.log('==================================================');

try {
    // Generate test data
    const key = randomBytes(32);
    const nonce = randomBytes(12);
    const plaintext = new TextEncoder().encode('Hello, GhostComm!');

    console.log('Key length:', key.length);
    console.log('Nonce length:', nonce.length);
    console.log('Plaintext:', new TextDecoder().decode(plaintext));

    // Encrypt
    const cipher = chacha20poly1305(key, nonce);
    const encrypted = cipher.encrypt(plaintext);

    console.log('Encrypted length:', encrypted.length);
    console.log('Expected length:', plaintext.length + 16); // +16 for auth tag

    // Decrypt
    const cipher2 = chacha20poly1305(key, nonce);
    const decrypted = cipher2.decrypt(encrypted);

    console.log('Decrypted:', new TextDecoder().decode(decrypted));
    console.log('Match:', new TextDecoder().decode(decrypted) === 'Hello, GhostComm!');

    console.log('\n✅ ChaCha20-Poly1305 test passed!');

} catch (error) {
    console.error('❌ ChaCha20-Poly1305 test failed:', error.message);
    console.error(error.stack);
}