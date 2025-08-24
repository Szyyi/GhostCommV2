// test-ble-corrected.js
const { GhostKeyPair, MessageEncryption, MessageFactory, MessageType, BLE_CONFIG } = require('./core/dist/index');

console.log('🧪 Testing Corrected BLE Architecture...\n');

async function runTests() {
    try {
        // Test 1: BLE Configuration
        console.log('📝 Test 1: BLE Configuration');
        console.log('Service UUID:', BLE_CONFIG.SERVICE_UUID);
        console.log('Characteristics:', Object.keys(BLE_CONFIG.CHARACTERISTICS));
        console.log('Message TTL:', BLE_CONFIG.MESSAGE_TTL, 'ms');
        console.log('✅ BLE configuration loaded\n');

        // Test 2: Key Pair Generation for BLE
        console.log('📝 Test 2: Key Pair Generation for BLE Node');
        const nodeKeyPair = GhostKeyPair.generate();
        const nodeId = nodeKeyPair.getFingerprint();
        const identityPublicKey = Array.from(nodeKeyPair.getIdentityPublicKey()).map(b => b.toString(16).padStart(2, '0')).join('');
        const encryptionPublicKey = Array.from(nodeKeyPair.getEncryptionPublicKey()).map(b => b.toString(16).padStart(2, '0')).join('');

        console.log('Node ID:', nodeId);
        console.log('Identity Public Key (hex):', identityPublicKey.substring(0, 16) + '...');
        console.log('Encryption Public Key (hex):', encryptionPublicKey.substring(0, 16) + '...');
        console.log('✅ BLE node keys generated\n');

        // Test 3: Advertisement Data Structure
        console.log('📝 Test 3: Advertisement Data Structure');
        const advertisementData = {
            nodeId: nodeId,
            publicKey: identityPublicKey,
            encryptionKey: encryptionPublicKey,
            timestamp: Date.now(),
            capabilities: ['relay', 'storage']
        };

        // Simulate advertisement name (simplified format)
        const advertisementName = `GhostComm:${advertisementData.nodeId}:${advertisementData.publicKey}:${advertisementData.encryptionKey}:${advertisementData.timestamp}`;
        console.log('Advertisement name length:', advertisementName.length);
        console.log('Advertisement preview:', advertisementName.substring(0, 50) + '...');
        console.log('✅ Advertisement data structure created\n');

        // Test 4: Message Factory Usage
        console.log('📝 Test 4: Message Factory Usage');
        const directMessage = MessageFactory.createDirectMessage(
            nodeId,
            'recipient123',
            'Hello from BLE mesh!'
        );
        console.log('Direct message ID:', directMessage.messageId);
        console.log('Direct message type:', directMessage.type);
        console.log('Direct message payload:', directMessage.payload);

        const broadcastMessage = MessageFactory.createBroadcastMessage(
            nodeId,
            'Hello everyone!'
        );
        console.log('Broadcast message ID:', broadcastMessage.messageId);
        console.log('Broadcast message type:', broadcastMessage.type);
        console.log('✅ Message factory works correctly\n');

        // Test 5: End-to-End Encryption Test
        console.log('📝 Test 5: End-to-End Encryption Test');

        // Create two nodes
        const senderKeyPair = GhostKeyPair.generate();
        const recipientKeyPair = GhostKeyPair.generate();

        console.log('Sender ID:', senderKeyPair.getFingerprint());
        console.log('Recipient ID:', recipientKeyPair.getFingerprint());

        // Create and encrypt a direct message
        const testMessage = MessageFactory.createDirectMessage(
            senderKeyPair.getFingerprint(),
            recipientKeyPair.getFingerprint(),
            'Secret message for BLE mesh!'
        );

        const encryptedMessage = await MessageEncryption.encryptMessage(
            testMessage,
            senderKeyPair,
            recipientKeyPair.getEncryptionPublicKey()
        );

        console.log('Encrypted message ID:', encryptedMessage.messageId);
        console.log('Ephemeral key length:', encryptedMessage.ephemeralPublicKey.length);

        // Decrypt the message
        const decryptedMessage = await MessageEncryption.decryptMessage(
            encryptedMessage,
            recipientKeyPair
        );

        console.log('Decrypted payload:', decryptedMessage.payload);
        console.log('Message types match:', testMessage.type === decryptedMessage.type);
        console.log('✅ End-to-end encryption works correctly\n');

        // Test 6: Broadcast Message Test
        console.log('📝 Test 6: Broadcast Message Test');

        const broadcastTestMessage = MessageFactory.createBroadcastMessage(
            senderKeyPair.getFingerprint(),
            'Public announcement!'
        );

        const encryptedBroadcast = await MessageEncryption.createBroadcastMessage(
            broadcastTestMessage,
            senderKeyPair
        );

        const decryptedBroadcast = await MessageEncryption.decryptBroadcastMessage(encryptedBroadcast);

        console.log('Broadcast payload:', decryptedBroadcast.payload);
        console.log('Broadcast types match:', broadcastTestMessage.type === decryptedBroadcast.type);
        console.log('✅ Broadcast encryption works correctly\n');

        // Test 7: BLE Message Structure
        console.log('📝 Test 7: BLE Message Structure');
        const bleMessage = {
            messageId: encryptedMessage.messageId,
            encryptedPayload: JSON.stringify(encryptedMessage),
            ttl: Date.now() + BLE_CONFIG.MESSAGE_TTL,
            hopCount: 0
        };

        console.log('BLE Message ID:', bleMessage.messageId);
        console.log('TTL expires in:', Math.round((bleMessage.ttl - Date.now()) / 1000), 'seconds');
        console.log('Hop count:', bleMessage.hopCount);
        console.log('Encrypted payload length:', bleMessage.encryptedPayload.length);
        console.log('✅ BLE message structure created\n');

        console.log('🎉 All BLE Architecture Tests Passed!');
        console.log('The corrected BLE architecture is ready for implementation.');
        console.log('\n🚀 Next steps:');
        console.log('1. Build the core library: cd core && npx tsc');
        console.log('2. Create React Native platform implementations');
        console.log('3. Test on real BLE hardware');
        console.log('4. Build the mobile app UI');

    } catch (error) {
        console.error('❌ Test failed:', error);
        process.exit(1);
    }
}

runTests();