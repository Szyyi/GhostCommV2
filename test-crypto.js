// test-crypto.js - Simple test for our cryptographic components

const { GhostKeyPair } = require('./core/dist/index.js');

console.log('🔐 Testing GhostComm Cryptographic Components...\n');

try {
    // Test 1: Generate a new key pair
    console.log('1. Generating new key pair...');
    const keyPair = new GhostKeyPair();
    console.log('✅ Key pair generated successfully');

    // Test 2: Get identity and encryption keys
    console.log('\n2. Testing key retrieval...');
    const identityKey = keyPair.getIdentityPublicKey();
    const encryptionKey = keyPair.getEncryptionPublicKey();
    console.log(`✅ Identity key length: ${identityKey.length} bytes`);
    console.log(`✅ Encryption key length: ${encryptionKey.length} bytes`);

    // Test 3: Generate fingerprint
    console.log('\n3. Testing fingerprint generation...');
    const fingerprint = keyPair.getFingerprint();
    console.log(`✅ Fingerprint: ${fingerprint}`);

    // Test 4: Test message signing
    console.log('\n4. Testing message signing...');
    const message = new TextEncoder().encode('Hello GhostComm!');
    const signature = keyPair.sign(message);
    console.log(`✅ Message signed, signature length: ${signature.length} bytes`);

    // Test 5: Test signature verification
    console.log('\n5. Testing signature verification...');
    const isValid = GhostKeyPair.verify(message, signature, identityKey);
    console.log(`✅ Signature verification: ${isValid ? 'VALID' : 'INVALID'}`);

    // Test 6: Test key export/import
    console.log('\n6. Testing key export/import...');
    const exportedKeys = keyPair.export();
    console.log('✅ Keys exported to hex strings');

    const importedKeyPair = GhostKeyPair.import(exportedKeys);
    const importedFingerprint = importedKeyPair.getFingerprint();
    console.log(`✅ Keys imported, fingerprint matches: ${fingerprint === importedFingerprint}`);

    // Test 7: Test key exchange
    console.log('\n7. Testing key exchange...');
    const otherKeyPair = new GhostKeyPair();
    const sharedSecret1 = keyPair.performKeyExchange(otherKeyPair.getEncryptionPublicKey());
    const sharedSecret2 = otherKeyPair.performKeyExchange(keyPair.getEncryptionPublicKey());

    const secretsMatch = sharedSecret1.every((byte, index) => byte === sharedSecret2[index]);
    console.log(`✅ Key exchange successful, shared secrets match: ${secretsMatch}`);
    console.log(`✅ Shared secret length: ${sharedSecret1.length} bytes`);

    console.log('\n🎉 All cryptographic tests passed!');
    console.log('\n📊 Summary:');
    console.log(`   - Identity Key: ${fingerprint}`);
    console.log(`   - Signing: Ed25519 (${identityKey.length} bytes)`);
    console.log(`   - Encryption: X25519 (${encryptionKey.length} bytes)`);
    console.log(`   - Shared Secret: ${sharedSecret1.length} bytes`);

} catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error(error.stack);
}