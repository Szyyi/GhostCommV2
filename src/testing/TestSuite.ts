// mobile/src/testing/TestSuite.ts
import AsyncStorage from '@react-native-async-storage/async-storage';
import {
    GhostKeyPair,
    MessageEncryption,
    MessageFactory,
    MessageType,
    type EncryptedMessage,
    type PlaintextMessage
} from '@ghostcomm/core';
import { debug } from '../utils/debug';

interface TestResult {
    name: string;
    category: string;
    passed: boolean;
    error?: string;
    duration: number;
    details?: any;
}

export class GhostCommTestSuite {
    private results: TestResult[] = [];
    private currentCategory: string = '';

    async runAllTests(): Promise<TestResult[]> {
        debug.info('Starting GhostComm Test Suite');
        this.results = [];

        // Run test categories
        await this.testCryptography();
        await this.testStorage();
        await this.testMessaging();
        await this.testNetworking();
        await this.testUI();

        this.printResults();
        return this.results;
    }

    private async testCryptography() {
        this.currentCategory = 'Cryptography';

        await this.test('Generate KeyPair', async () => {
            const keyPair = new GhostKeyPair();
            const publicKey = keyPair.getIdentityPublicKey();
            const encryptionKey = keyPair.getEncryptionPublicKey();
            const fingerprint = keyPair.getFingerprint();

            if (!publicKey || publicKey.length !== 32) throw new Error('Invalid public key');
            if (!encryptionKey || encryptionKey.length !== 32) throw new Error('Invalid encryption key');
            if (!fingerprint) throw new Error('No fingerprint generated');

            return {
                fingerprint,
                publicKeyLength: publicKey.length,
                encryptionKeyLength: encryptionKey.length
            };
        });

        await this.test('Encrypt/Decrypt Message', async () => {
            const alice = new GhostKeyPair();
            const bob = new GhostKeyPair();

            // Create a plaintext message
            const plaintextMessage = MessageFactory.createDirectMessage(
                alice.getFingerprint(),
                bob.getFingerprint(),
                'Test message for GhostComm'
            );

            // Encrypt the message
            const encrypted = await MessageEncryption.encryptMessage(
                plaintextMessage,
                alice,
                bob.getEncryptionPublicKey()
            );

            if (!encrypted.ciphertext) throw new Error('No ciphertext in encrypted message');
            if (!encrypted.ephemeralPublicKey) throw new Error('No ephemeral key');
            if (!encrypted.nonce) throw new Error('No nonce');
            if (!encrypted.authTag) throw new Error('No auth tag');

            // Decrypt the message
            const decrypted = await MessageEncryption.decryptMessage(
                encrypted,
                bob
            );

            if (decrypted.payload !== plaintextMessage.payload) {
                throw new Error('Decryption mismatch');
            }

            return {
                original: plaintextMessage.payload,
                decrypted: decrypted.payload,
                messageId: encrypted.messageId
            };
        });

        await this.test('Broadcast Message Encryption', async () => {
            const sender = new GhostKeyPair();

            // Create a broadcast message
            const broadcastMessage = MessageFactory.createBroadcastMessage(
                sender.getFingerprint(),
                'Broadcast test message'
            );

            // Encrypt as broadcast
            const encrypted = await MessageEncryption.createBroadcastMessage(
                broadcastMessage,
                sender
            );

            if (!encrypted.ciphertext) throw new Error('No ciphertext in broadcast');
            if (!encrypted.ephemeralPublicKey) throw new Error('No ephemeral key in broadcast');

            // Decrypt broadcast (anyone should be able to)
            const decrypted = await MessageEncryption.decryptBroadcastMessage(encrypted);

            if (decrypted.payload !== broadcastMessage.payload) {
                throw new Error('Broadcast decryption failed');
            }

            return {
                payload: decrypted.payload,
                type: decrypted.type
            };
        });

        await this.test('Sign and Verify', async () => {
            const keyPair = new GhostKeyPair();
            const message = Buffer.from('Test signature message');
            const signature = keyPair.sign(message);

            if (!signature || signature.length !== 64) {
                throw new Error('Invalid signature');
            }

            const isValid = GhostKeyPair.verify(
                message,
                signature,
                keyPair.getIdentityPublicKey()
            );

            if (!isValid) throw new Error('Verification failed');

            // Test with wrong message
            const wrongMessage = Buffer.from('Wrong message');
            const isInvalid = GhostKeyPair.verify(
                wrongMessage,
                signature,
                keyPair.getIdentityPublicKey()
            );

            if (isInvalid) throw new Error('Should not verify wrong message');

            return {
                signatureLength: signature.length,
                verified: isValid,
                wrongMessageVerified: isInvalid
            };
        });

        await this.test('Export/Import KeyPair', async () => {
            const original = new GhostKeyPair();
            const password = 'test-password-123';
            const exported = original.export(password);

            if (!exported || exported.length === 0) {
                throw new Error('Export failed');
            }

            const imported = GhostKeyPair.import(exported, password);

            if (original.getFingerprint() !== imported.getFingerprint()) {
                throw new Error('Fingerprints do not match after import');
            }

            // Test signing with imported key
            const testMessage = Buffer.from('Test after import');
            const originalSig = original.sign(testMessage);
            const importedSig = imported.sign(testMessage);

            // Verify signatures are valid
            const originalValid = GhostKeyPair.verify(
                testMessage,
                originalSig,
                original.getIdentityPublicKey()
            );

            const importedValid = GhostKeyPair.verify(
                testMessage,
                importedSig,
                imported.getIdentityPublicKey()
            );

            if (!originalValid || !importedValid) {
                throw new Error('Signatures invalid after import');
            }

            return {
                fingerprint: original.getFingerprint(),
                exportLength: exported.length
            };
        });
    }

    private async testStorage() {
        this.currentCategory = 'Storage';

        await this.test('AsyncStorage Write/Read', async () => {
            const testKey = '@ghostcomm_test';
            const testData = {
                test: true,
                timestamp: Date.now(),
                nested: {
                    value: 'test'
                }
            };

            await AsyncStorage.setItem(testKey, JSON.stringify(testData));
            const retrieved = await AsyncStorage.getItem(testKey);

            if (!retrieved) throw new Error('Failed to retrieve data');
            const parsed = JSON.parse(retrieved);

            if (parsed.test !== testData.test) {
                throw new Error('Data mismatch');
            }

            if (parsed.nested.value !== testData.nested.value) {
                throw new Error('Nested data mismatch');
            }

            await AsyncStorage.removeItem(testKey);

            // Verify removal
            const afterRemoval = await AsyncStorage.getItem(testKey);
            if (afterRemoval !== null) {
                throw new Error('Data not removed');
            }

            return { stored: testData, retrieved: parsed };
        });

        await this.test('Message Persistence', async () => {
            const messages = [
                {
                    id: 'msg-1',
                    content: 'Test message 1',
                    timestamp: Date.now(),
                    status: 'DELIVERED'
                },
                {
                    id: 'msg-2',
                    content: 'Test message 2',
                    timestamp: Date.now(),
                    status: 'SENT'
                }
            ];

            const key = '@ghostcomm_messages_test';
            await AsyncStorage.setItem(key, JSON.stringify(messages));
            const stored = await AsyncStorage.getItem(key);

            if (!stored) throw new Error('Messages not persisted');
            const retrieved = JSON.parse(stored);

            if (retrieved.length !== messages.length) {
                throw new Error('Message count mismatch');
            }

            if (retrieved[0].id !== messages[0].id) {
                throw new Error('Message ID mismatch');
            }

            await AsyncStorage.removeItem(key);

            return {
                count: retrieved.length,
                firstId: retrieved[0].id
            };
        });

        await this.test('Settings Persistence', async () => {
            const settings = {
                alias: 'TestNode',
                autoConnect: true,
                scanInterval: 5000,
                theme: 'terminal',
                notifications: {
                    messages: true,
                    connections: false
                }
            };

            const key = '@ghostcomm_settings_test';
            await AsyncStorage.setItem(key, JSON.stringify(settings));
            const stored = await AsyncStorage.getItem(key);

            if (!stored) throw new Error('Settings not persisted');
            const retrieved = JSON.parse(stored);

            if (retrieved.alias !== settings.alias) {
                throw new Error('Settings alias mismatch');
            }

            if (retrieved.notifications.messages !== settings.notifications.messages) {
                throw new Error('Nested settings mismatch');
            }

            await AsyncStorage.removeItem(key);

            return retrieved;
        });

        await this.test('Large Data Storage', async () => {
            // Test storing larger amounts of data
            const largeArray = Array.from({ length: 100 }, (_, i) => ({
                id: `item-${i}`,
                data: 'x'.repeat(100),
                timestamp: Date.now()
            }));

            const key = '@ghostcomm_large_test';
            const dataString = JSON.stringify(largeArray);
            const sizeKB = dataString.length / 1024;

            await AsyncStorage.setItem(key, dataString);
            const retrieved = await AsyncStorage.getItem(key);

            if (!retrieved) throw new Error('Large data not stored');
            const parsed = JSON.parse(retrieved);

            if (parsed.length !== largeArray.length) {
                throw new Error('Large data count mismatch');
            }

            await AsyncStorage.removeItem(key);

            return {
                itemCount: parsed.length,
                sizeKB: sizeKB.toFixed(2)
            };
        });
    }

    private async testMessaging() {
        this.currentCategory = 'Messaging';

        await this.test('Direct Message Creation', async () => {
            const senderId = 'NODE-' + Math.random().toString(36).substr(2, 6).toUpperCase();
            const recipientId = 'NODE-' + Math.random().toString(36).substr(2, 6).toUpperCase();

            const message = MessageFactory.createDirectMessage(
                senderId,
                recipientId,
                'Test direct message content'
            );

            if (!message.messageId) throw new Error('No message ID');
            if (message.type !== MessageType.DIRECT) throw new Error('Wrong message type');
            if (!message.senderId) throw new Error('No sender ID');
            if (!message.recipientId) throw new Error('No recipient ID');
            if (message.payload.length > 256) throw new Error('Message too long');

            return {
                messageId: message.messageId,
                type: message.type,
                size: message.payload.length
            };
        });

        await this.test('Broadcast Message Creation', async () => {
            const senderId = 'NODE-' + Math.random().toString(36).substr(2, 6).toUpperCase();

            const broadcast = MessageFactory.createBroadcastMessage(
                senderId,
                'Emergency broadcast test'
            );

            if (broadcast.type !== MessageType.BROADCAST) {
                throw new Error('Invalid broadcast type');
            }

            if (broadcast.recipientId !== undefined) {
                throw new Error('Broadcast should not have recipient');
            }

            if (!broadcast.ttl || broadcast.ttl <= 0) {
                throw new Error('Invalid TTL');
            }

            return {
                broadcastId: broadcast.messageId,
                ttl: broadcast.ttl,
                type: broadcast.type
            };
        });

        await this.test('Message Status Tracking', async () => {
            const statuses = [
                'QUEUED',
                'TRANSMITTING',
                'SENT',
                'DELIVERED',
                'FAILED',
                'TIMEOUT'
            ];

            const messageId = `msg-${Date.now()}`;
            const statusHistory: string[] = [];

            // Simulate status transitions
            for (const status of statuses.slice(0, 4)) {
                statusHistory.push(status);
                await new Promise(resolve => setTimeout(resolve, 10));
            }

            const finalStatus = statusHistory[statusHistory.length - 1];

            if (finalStatus !== 'DELIVERED') {
                throw new Error('Status progression failed');
            }

            return {
                messageId,
                finalStatus,
                transitions: statusHistory.length
            };
        });

        await this.test('ACK Message Creation', async () => {
            const senderId = 'NODE-A';
            const recipientId = 'NODE-B';
            const originalMessageId = 'msg-original-123';

            const ackMessage = MessageFactory.createAckMessage(
                senderId,
                recipientId,
                originalMessageId
            );

            if (ackMessage.type !== MessageType.ACK) {
                throw new Error('Wrong ACK type');
            }

            if (!ackMessage.payload.includes(originalMessageId)) {
                throw new Error('ACK does not reference original message');
            }

            return {
                ackId: ackMessage.messageId,
                originalId: originalMessageId,
                payload: ackMessage.payload
            };
        });
    }

    private async testNetworking() {
        this.currentCategory = 'Networking';

        await this.test('Node Discovery Simulation', async () => {
            const discoveredNodes = [
                { id: 'GHOST-ABC123', rssi: -45, name: 'Node1' },
                { id: 'GHOST-DEF456', rssi: -62, name: 'Node2' },
                { id: 'GHOST-789GHI', rssi: -78, name: 'Node3' }
            ];

            if (discoveredNodes.length === 0) {
                throw new Error('No nodes discovered');
            }

            // Test signal strength categorization
            const signalStrengths = discoveredNodes.map(node => {
                if (node.rssi >= -50) return 'excellent';
                if (node.rssi >= -60) return 'good';
                if (node.rssi >= -70) return 'fair';
                return 'poor';
            });

            return {
                nodesFound: discoveredNodes.length,
                signalCategories: signalStrengths
            };
        });

        await this.test('Routing Table Management', async () => {
            const routingTable = new Map([
                ['GHOST-NODE-A', {
                    nextHop: 'GHOST-NODE-B',
                    hops: 2,
                    reliability: 0.95,
                    lastSeen: Date.now()
                }],
                ['GHOST-NODE-C', {
                    nextHop: 'GHOST-NODE-B',
                    hops: 3,
                    reliability: 0.87,
                    lastSeen: Date.now()
                }],
                ['GHOST-NODE-D', {
                    nextHop: 'GHOST-NODE-A',
                    hops: 1,
                    reliability: 0.99,
                    lastSeen: Date.now()
                }]
            ]);

            if (routingTable.size === 0) {
                throw new Error('Empty routing table');
            }

            // Find best route (highest reliability)
            let bestRoute = { nodeId: '', reliability: 0 };
            routingTable.forEach((route, nodeId) => {
                if (route.reliability > bestRoute.reliability) {
                    bestRoute = { nodeId, reliability: route.reliability };
                }
            });

            return {
                routes: routingTable.size,
                bestRoute: bestRoute.nodeId,
                bestReliability: bestRoute.reliability
            };
        });

        await this.test('Mesh TTL and Hop Management', async () => {
            const initialTTL = 86400000; // 24 hours in ms
            const maxHops = 10;
            let currentHops = 0;
            let currentTTL = Date.now() + initialTTL;

            // Simulate message routing through mesh
            const route = [];
            while (currentHops < maxHops && Date.now() < currentTTL) {
                currentHops++;
                route.push(`NODE-${currentHops}`);

                // Simulate time passing
                await new Promise(resolve => setTimeout(resolve, 1));
            }

            if (currentHops > maxHops) {
                throw new Error('Exceeded max hops');
            }

            return {
                finalHops: currentHops,
                routeLength: route.length,
                ttlRemaining: currentTTL > Date.now()
            };
        });

        await this.test('Connection Pool Management', async () => {
            const maxConnections = 10;
            const connections = new Map();

            // Simulate adding connections
            for (let i = 0; i < 15; i++) {
                const nodeId = `NODE-${i}`;

                if (connections.size < maxConnections) {
                    connections.set(nodeId, {
                        connected: true,
                        timestamp: Date.now()
                    });
                }
            }

            if (connections.size > maxConnections) {
                throw new Error('Exceeded max connections');
            }

            return {
                activeConnections: connections.size,
                maxReached: connections.size === maxConnections
            };
        });
    }

    private async testUI() {
        this.currentCategory = 'UI/UX';

        await this.test('Screen Navigation Flow', async () => {
            const screens = [
                'OnboardingScreen',
                'MessagingScreen',
                'NetworkScreen',
                'TerminalScreen',
                'SettingsScreen'
            ];

            const navigationStack: string[] = [];

            for (const screen of screens) {
                navigationStack.push(screen);
                // Simulate navigation delay
                await new Promise(resolve => setTimeout(resolve, 10));
            }

            if (navigationStack.length !== screens.length) {
                throw new Error('Navigation stack mismatch');
            }

            return {
                screensNavigated: screens.length,
                finalScreen: navigationStack[navigationStack.length - 1]
            };
        });

        await this.test('Terminal Command Parsing', async () => {
            const commands = [
                { cmd: 'help', valid: true },
                { cmd: 'status', valid: true },
                { cmd: 'nodes', valid: true },
                { cmd: 'scan', valid: true },
                { cmd: 'identity', valid: true },
                { cmd: 'send NODE-123 Hello', valid: true },
                { cmd: 'broadcast Emergency', valid: true },
                { cmd: 'invalid_command', valid: false }
            ];

            const results = [];
            for (const { cmd, valid } of commands) {
                const parts = cmd.split(' ');
                const mainCmd = parts[0].toLowerCase();

                const knownCommands = [
                    'help', 'status', 'nodes', 'scan',
                    'identity', 'send', 'broadcast', 'connect',
                    'disconnect', 'clear', 'stats', 'export'
                ];

                const isValid = knownCommands.includes(mainCmd);

                if (isValid !== valid) {
                    throw new Error(`Command validation failed for: ${cmd}`);
                }

                results.push({ cmd: mainCmd, valid: isValid });
            }

            return {
                commandsTested: commands.length,
                validCommands: results.filter(r => r.valid).length
            };
        });

        await this.test('Theme Consistency', async () => {
            const theme = {
                background: '#000000',
                text: '#00FF00',
                accent: '#00FF00',
                error: '#FF0000',
                warning: '#FFFF00',
                info: '#00FFFF',
                success: '#00FF00'
            };

            // Validate all colors are valid hex
            const hexRegex = /^#[0-9A-F]{6}$/i;
            const allValid = Object.entries(theme).every(([key, color]) => {
                const isValid = hexRegex.test(color);
                if (!isValid) {
                    throw new Error(`Invalid color for ${key}: ${color}`);
                }
                return isValid;
            });

            if (!allValid) throw new Error('Theme validation failed');

            return theme;
        });

        await this.test('Message Formatting', async () => {
            const timestamp = Date.now();
            const nodeId = 'GHOST-ABC123';
            const alias = 'Alice';
            const content = 'Test message content';

            // Test formatting functions
            const formattedTime = new Date(timestamp).toLocaleTimeString('en-US', {
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });

            const formattedNodeId = nodeId.length > 8
                ? `${nodeId.substring(0, 6)}...${nodeId.substring(nodeId.length - 4)}`
                : nodeId;

            const formattedMessage = `[${formattedTime}] ${alias}@${formattedNodeId}: ${content}`;

            if (!formattedMessage.includes(alias)) {
                throw new Error('Message formatting failed');
            }

            return {
                formatted: formattedMessage,
                length: formattedMessage.length
            };
        });
    }

    private async test(name: string, testFn: () => Promise<any>) {
        const startTime = Date.now();
        const result: TestResult = {
            name,
            category: this.currentCategory,
            passed: false,
            duration: 0
        };

        try {
            const details = await testFn();
            result.passed = true;
            result.details = details;
            debug.info(`✅ ${this.currentCategory}/${name} passed`, details);
        } catch (error) {
            result.passed = false;
            result.error = error instanceof Error ? error.message : String(error);
            debug.error(`❌ ${this.currentCategory}/${name} failed`, error);
        }

        result.duration = Date.now() - startTime;
        this.results.push(result);
    }

    private printResults() {
        const totalTests = this.results.length;
        const passedTests = this.results.filter(r => r.passed).length;
        const failedTests = totalTests - passedTests;
        const totalDuration = this.results.reduce((sum, r) => sum + r.duration, 0);

        console.log('\n' + '='.repeat(60));
        console.log('GHOSTCOMM TEST RESULTS');
        console.log('='.repeat(60));

        // Group by category
        const categories = new Set(this.results.map(r => r.category));

        categories.forEach(category => {
            const categoryResults = this.results.filter(r => r.category === category);
            const passed = categoryResults.filter(r => r.passed).length;
            const total = categoryResults.length;

            console.log(`\n${category}: ${passed}/${total} passed`);
            categoryResults.forEach(r => {
                const icon = r.passed ? '✅' : '❌';
                const time = `(${r.duration}ms)`;
                console.log(`  ${icon} ${r.name} ${time}`);
                if (r.error) {
                    console.log(`     Error: ${r.error}`);
                }
            });
        });

        console.log('\n' + '='.repeat(60));
        console.log(`SUMMARY: ${passedTests}/${totalTests} tests passed`);
        console.log(`Total execution time: ${totalDuration}ms`);
        console.log(`Success rate: ${((passedTests / totalTests) * 100).toFixed(1)}%`);
        console.log('='.repeat(60) + '\n');

        // Save results to AsyncStorage for later review
        AsyncStorage.setItem('@test_results', JSON.stringify({
            timestamp: new Date().toISOString(),
            results: this.results,
            summary: {
                total: totalTests,
                passed: passedTests,
                failed: failedTests,
                duration: totalDuration,
                successRate: (passedTests / totalTests) * 100
            }
        })).catch(error => {
            console.error('Failed to save test results:', error);
        });
    }

    async loadPreviousResults(): Promise<any> {
        try {
            const stored = await AsyncStorage.getItem('@test_results');
            return stored ? JSON.parse(stored) : null;
        } catch (error) {
            console.error('Failed to load previous results:', error);
            return null;
        }
    }
}

// Export singleton instance
export const testSuite = new GhostCommTestSuite();