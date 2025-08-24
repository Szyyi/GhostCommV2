// debug-encryption-class.js - Test the actual MessageEncryption class with debug logging

const { GhostKeyPair } = require('./core/dist/crypto/keypair');
const { MessageEncryption, MessageFactory } = require('./core/dist/crypto/encryption');

async function debugMessageEncryption() {
    console.log('🔍 Debug MessageEncryption Class');
    console.log('================================');

    try {
        // Create key pairs
        const alice = new GhostKeyPair();
        const bob = new GhostKeyPair();

        console.log('Alice fingerprint:', alice.getFingerprint());
        console.log('Bob fingerprint:', bob.getFingerprint());

        // Create a test message
        const message = MessageFactory.createDirectMessage(
            alice.getFingerprint(),
            bob.getFingerprint(),
            'Hello Bob from the MessageEncryption class!'
        );

        console.log('\n📝 Original message:');
        console.log('Type:', message.type);
        console.log('Sender:', message.senderId);
        console.log('Recipient:', message.recipientId);
        console.log('Payload:', message.payload);
        console.log('Message ID:', message.messageId);

        // Encrypt the message
        console.log('\n🔒 Encrypting message...');
        const encrypted = await MessageEncryption.encryptMessage(
            message,
            alice,
            bob.getEncryptionPublicKey()
        );

        console.log('✅ Encryption successful!');
        console.log('Ephemeral key length:', encrypted.ephemeralPublicKey.length);
        console.log('Nonce length:', encrypted.nonce.length);
        console.log('Ciphertext length:', encrypted.ciphertext.length);
        console.log('Auth tag length:', encrypted.authTag.length);
        console.log('Ephemeral key:', encrypted.ephemeralPublicKey.substring(0, 16) + '...');
        console.log('Nonce:', encrypted.nonce);
        console.log('Auth tag:', encrypted.authTag);

        // Try to decrypt
        console.log('\n🔓 Decrypting message...');
        const decrypted = await MessageEncryption.decryptMessage(encrypted, bob);

        console.log('✅ Decryption successful!');
        console.log('Decrypted type:', decrypted.type);
        console.log('Decrypted sender:', decrypted.senderId);
        console.log('Decrypted recipient:', decrypted.recipientId);
        console.log('Decrypted payload:', decrypted.payload);
        console.log('Decrypted message ID:', decrypted.messageId);

        // Verify everything matches
        const matches = {
            type: message.type === decrypted.type,
            senderId: message.senderId === decrypted.senderId,
            recipientId: message.recipientId === decrypted.recipientId,
            payload: message.payload === decrypted.payload,
            messageId: message.messageId === decrypted.messageId,
            timestamp: message.timestamp === decrypted.timestamp
        };

        console.log('\n📊 Verification:');
        for (const [field, match] of Object.entries(matches)) {
            console.log(`${match ? '✅' : '❌'} ${field}: ${match}`);
        }

        const allMatch = Object.values(matches).every(m => m);
        console.log(`\n${allMatch ? '🎉' : '💥'} Overall result: ${allMatch ? 'SUCCESS' : 'FAILURE'}`);

    } catch (error) {
        console.error('❌ Debug failed:', error.message);
        console.error('Stack trace:', error.stack);

        // Additional debug info
        console.log('\n🔍 Additional debug info:');
        console.log('Error name:', error.name);
        console.log('Error constructor:', error.constructor.name);
    }
}

debugMessageEncryption();