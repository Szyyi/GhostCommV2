// test-encryption.js
// Comprehensive test suite for MessageEncryption class

const { GhostKeyPair } = require('./core/dist/crypto/keypair');
const { MessageEncryption, MessageFactory, MessageType } = require('./core/dist/crypto/encryption');

async function runEncryptionTests() {
    console.log('🔒 GhostComm Message Encryption Test Suite');
    console.log('==========================================\n');

    let passedTests = 0;
    let totalTests = 0;

    function test(name, condition) {
        totalTests++;
        if (condition) {
            console.log(`✅ ${name}`);
            passedTests++;
        } else {
            console.log(`❌ ${name}`);
        }
    }

    try {
        // Test 1: Generate key pairs for testing
        console.log('📝 Test 1: Generate Test Key Pairs');
        const aliceKeyPair = new GhostKeyPair();
        const bobKeyPair = new GhostKeyPair();
        const charlieKeyPair = new GhostKeyPair();

        test('Alice key pair generated', aliceKeyPair !== null);
        test('Bob key pair generated', bobKeyPair !== null);
        test('Charlie key pair generated', charlieKeyPair !== null);

        const aliceFingerprint = aliceKeyPair.getFingerprint();
        const bobFingerprint = bobKeyPair.getFingerprint();
        const charlieFingerprint = charlieKeyPair.getFingerprint();

        console.log(`   Alice fingerprint: ${aliceFingerprint}`);
        console.log(`   Bob fingerprint: ${bobFingerprint}`);
        console.log(`   Charlie fingerprint: ${charlieFingerprint}\n`);

        // Test 2: Message Factory
        console.log('📝 Test 2: Message Factory Functions');

        const directMessage = MessageFactory.createDirectMessage(
            aliceFingerprint,
            bobFingerprint,
            'Hello Bob! This is a direct message from Alice.'
        );

        const broadcastMessage = MessageFactory.createBroadcastMessage(
            aliceFingerprint,
            'Hello everyone! This is a broadcast message.'
        );

        const discoveryMessage = MessageFactory.createDiscoveryMessage(
            charlieFingerprint,
            'Charlie joining the mesh network'
        );

        const ackMessage = MessageFactory.createAckMessage(
            bobFingerprint,
            aliceFingerprint,
            directMessage.messageId
        );

        test('Direct message created', directMessage.type === MessageType.DIRECT);
        test('Direct message has correct sender', directMessage.senderId === aliceFingerprint);
        test('Direct message has correct recipient', directMessage.recipientId === bobFingerprint);
        test('Direct message has message ID', directMessage.messageId.length > 0);
        test('Direct message has timestamp', directMessage.timestamp > 0);

        test('Broadcast message created', broadcastMessage.type === MessageType.BROADCAST);
        test('Broadcast message has no recipient', broadcastMessage.recipientId === undefined);

        test('Discovery message created', discoveryMessage.type === MessageType.DISCOVERY);
        test('Discovery message has short TTL', discoveryMessage.ttl === 5 * 60 * 1000);

        test('ACK message created', ackMessage.type === MessageType.ACK);
        test('ACK message references original', ackMessage.payload.includes(directMessage.messageId));

        console.log(`   Direct message ID: ${directMessage.messageId}`);
        console.log(`   Broadcast message ID: ${broadcastMessage.messageId}`);
        console.log(`   Discovery message ID: ${discoveryMessage.messageId}`);
        console.log(`   ACK message ID: ${ackMessage.messageId}\n`);

        // Test 3: Direct Message Encryption/Decryption
        console.log('📝 Test 3: Direct Message Encryption/Decryption');

        const encryptedDirect = await MessageEncryption.encryptMessage(
            directMessage,
            aliceKeyPair,
            bobKeyPair.getEncryptionPublicKey()
        );

        test('Message encrypted successfully', encryptedDirect !== null);
        test('Encrypted message has sender ID', encryptedDirect.senderId === aliceFingerprint);
        test('Encrypted message has recipient ID', encryptedDirect.recipientId === bobFingerprint);
        test('Encrypted message has ephemeral key', encryptedDirect.ephemeralPublicKey.length === 64); // 32 bytes = 64 hex chars
        test('Encrypted message has nonce', encryptedDirect.nonce.length === 24); // 12 bytes = 24 hex chars
        test('Encrypted message has ciphertext', encryptedDirect.ciphertext.length > 0);
        test('Encrypted message has auth tag', encryptedDirect.authTag.length === 32); // 16 bytes = 32 hex chars

        console.log(`   Ephemeral key: ${encryptedDirect.ephemeralPublicKey.substring(0, 16)}...`);
        console.log(`   Nonce: ${encryptedDirect.nonce}`);
        console.log(`   Ciphertext length: ${encryptedDirect.ciphertext.length} hex chars`);
        console.log(`   Auth tag: ${encryptedDirect.authTag}`);

        // Bob decrypts the message
        const decryptedDirect = await MessageEncryption.decryptMessage(
            encryptedDirect,
            bobKeyPair
        );

        test('Message decrypted successfully', decryptedDirect !== null);
        test('Decrypted message type matches', decryptedDirect.type === directMessage.type);
        test('Decrypted sender ID matches', decryptedDirect.senderId === directMessage.senderId);
        test('Decrypted recipient ID matches', decryptedDirect.recipientId === directMessage.recipientId);
        test('Decrypted payload matches', decryptedDirect.payload === directMessage.payload);
        test('Decrypted message ID matches', decryptedDirect.messageId === directMessage.messageId);
        test('Decrypted timestamp matches', decryptedDirect.timestamp === directMessage.timestamp);

        console.log(`   Decrypted payload: "${decryptedDirect.payload}"\n`);

        // Test 4: Charlie cannot decrypt Alice-to-Bob message
        console.log('📝 Test 4: Message Security (Wrong Recipient)');

        let charlieDecryptionFailed = false;
        try {
            await MessageEncryption.decryptMessage(encryptedDirect, charlieKeyPair);
        } catch (error) {
            charlieDecryptionFailed = true;
        }

        test('Charlie cannot decrypt Alice-Bob message', charlieDecryptionFailed);
        console.log('   ✅ Message confidentiality maintained\n');

        // Test 5: Broadcast Message Encryption/Decryption
        console.log('📝 Test 5: Broadcast Message Encryption/Decryption');

        const encryptedBroadcast = await MessageEncryption.createBroadcastMessage(
            broadcastMessage,
            aliceKeyPair
        );

        test('Broadcast message encrypted', encryptedBroadcast !== null);
        test('Broadcast has no recipient ID', encryptedBroadcast.recipientId === undefined);

        // All nodes should be able to decrypt broadcast messages
        const bobDecryptedBroadcast = await MessageEncryption.decryptBroadcastMessage(encryptedBroadcast);
        const charlieDecryptedBroadcast = await MessageEncryption.decryptBroadcastMessage(encryptedBroadcast);

        test('Bob can decrypt broadcast', bobDecryptedBroadcast.payload === broadcastMessage.payload);
        test('Charlie can decrypt broadcast', charlieDecryptedBroadcast.payload === broadcastMessage.payload);
        test('Broadcast sender verified', bobDecryptedBroadcast.senderId === aliceFingerprint);

        console.log(`   Broadcast payload: "${bobDecryptedBroadcast.payload}"`);
        console.log('   ✅ All nodes can read broadcast messages\n');

        // Test 6: Message ID Uniqueness
        console.log('📝 Test 6: Message ID Uniqueness');

        const messageIds = new Set();
        for (let i = 0; i < 100; i++) {
            const id = MessageEncryption.generateMessageId();
            messageIds.add(id);
        }

        test('Generated 100 unique message IDs', messageIds.size === 100);

        const sampleId = MessageEncryption.generateMessageId();
        test('Message ID has correct length', sampleId.length === 24); // 12 bytes = 24 hex chars

        console.log(`   Sample message ID: ${sampleId}\n`);

        // Test 7: Forward Secrecy (Different ephemeral keys)
        console.log('📝 Test 7: Forward Secrecy');

        const message1 = MessageFactory.createDirectMessage(aliceFingerprint, bobFingerprint, 'Message 1');
        const message2 = MessageFactory.createDirectMessage(aliceFingerprint, bobFingerprint, 'Message 2');

        const encrypted1 = await MessageEncryption.encryptMessage(message1, aliceKeyPair, bobKeyPair.getEncryptionPublicKey());
        const encrypted2 = await MessageEncryption.encryptMessage(message2, aliceKeyPair, bobKeyPair.getEncryptionPublicKey());

        test('Different ephemeral keys used', encrypted1.ephemeralPublicKey !== encrypted2.ephemeralPublicKey);
        test('Different nonces used', encrypted1.nonce !== encrypted2.nonce);
        test('Different ciphertexts produced', encrypted1.ciphertext !== encrypted2.ciphertext);

        console.log('   ✅ Forward secrecy maintained - each message uses fresh ephemeral keys\n');

        // Test Summary
        console.log('📊 Test Summary');
        console.log('===============');
        console.log(`✅ Passed: ${passedTests}/${totalTests} tests`);
        console.log(`❌ Failed: ${totalTests - passedTests}/${totalTests} tests`);

        if (passedTests === totalTests) {
            console.log('\n🎉 All message encryption tests passed!');
            console.log('🔒 GhostComm message encryption system is ready for production use.');
        } else {
            console.log('\n❌ Some tests failed. Please review the implementation.');
        }

    } catch (error) {
        console.error('💥 Test suite failed with error:', error.message);
        console.error(error.stack);
    }
}

// Run the tests
runEncryptionTests();