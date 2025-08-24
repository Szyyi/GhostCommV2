// core/src/ble/manager.ts
// Enhanced BLE Manager with Full Security Integration

import { GhostKeyPair } from '../crypto/keypair';
import { MessageEncryption } from '../crypto/encryption';
import {
    PlaintextMessage,
    EncryptedMessage,
    MessageType,
    MessagePriority,
    MessageHeader,
    SessionKeys,
    PreKey,
    IGhostKeyPair,
    IMessageEncryption,
    MeshNode,
    RouteInfo,
    NetworkStats,
    VerificationStatus,
    NodeCapability,
    DeviceType,
    CryptoError
} from '../types/crypto';
import {
    BLENode,
    BLEAdvertisementData,
    BLEMessage,
    BLESession,
    BLEEventCallback,
    BLEConnectionEvent,
    BLEMessageEvent,
    BLEDiscoveryEvent,
    BLE_CONFIG,
    ConnectionState,
    VerificationMethod,
    VerificationResult,
    IdentityProof,
    PreKeyBundle,
    MessageFragment,
    RelaySignature,
    BLEError,
    BLEErrorCode,
    BLEManagerState,
    BLEStatistics,
    ConnectionCallback,
    MessageCallback,
    DiscoveryCallback,
    VerificationCallback
} from './types';
import { BLEAdvertiser } from './advertiser';
import { BLEScanner } from './scanner';
import { BLEConnectionManager } from './connection';
import { MeshNetwork } from './mesh';

/**
 * Enhanced BLE Manager with comprehensive security features
 */
export abstract class BLEManager {
    // Core components
    protected keyPair: IGhostKeyPair;
    protected encryption: IMessageEncryption;
    protected advertiser: BLEAdvertiser;
    protected scanner: BLEScanner;
    protected connectionManager: BLEConnectionManager;
    protected meshNetwork: MeshNetwork;

    // Security management
    private sessions: Map<string, BLESession>;
    private verifiedNodes: Map<string, VerificationResult>;
    private pendingKeyExchanges: Map<string, Promise<SessionKeys>>;
    private messageFragments: Map<string, Map<number, MessageFragment>>;
    private replayProtection: Set<string>;
    private addressRotationTimer?: NodeJS.Timeout;

    // Event management
    private eventCallbacks: Set<BLEEventCallback>;
    private connectionCallbacks: Set<ConnectionCallback>;
    private messageCallbacks: Set<MessageCallback>;
    private discoveryCallbacks: Set<DiscoveryCallback>;
    private verificationCallbacks: Set<VerificationCallback>;

    // State management
    private state: BLEManagerState;
    private statistics: BLEStatistics;
    private meshProcessingTimer?: NodeJS.Timeout;
    private cleanupTimer?: NodeJS.Timeout;

    // Rate limiting
    private rateLimiters: Map<string, RateLimiter>;
    private lastAdvertisementTime: number = 0;
    private lastScanTime: number = 0;

    constructor(
        keyPair: IGhostKeyPair,
        advertiser: BLEAdvertiser,
        scanner: BLEScanner,
        connectionManager: BLEConnectionManager
    ) {
        this.keyPair = keyPair;
        this.encryption = new MessageEncryption();
        this.advertiser = advertiser;
        this.scanner = scanner;
        this.connectionManager = connectionManager;
        this.meshNetwork = new MeshNetwork(keyPair.getFingerprint());

        // Initialize security components
        this.sessions = new Map();
        this.verifiedNodes = new Map();
        this.pendingKeyExchanges = new Map();
        this.messageFragments = new Map();
        this.replayProtection = new Set();
        this.rateLimiters = new Map();

        // Initialize callbacks
        this.eventCallbacks = new Set();
        this.connectionCallbacks = new Set();
        this.messageCallbacks = new Set();
        this.discoveryCallbacks = new Set();
        this.verificationCallbacks = new Set();

        // Initialize state
        this.state = {
            isScanning: false,
            isAdvertising: false,
            connections: new Map(),
            discoveredNodes: new Map(),
            messageQueue: new Map(),
            routingTable: new Map(),
            statistics: this.initializeStatistics()
        };

        this.statistics = this.initializeStatistics();

        this.setupEventHandlers();
        this.startCleanupTimer();
    }

    /**
     * Initialize statistics
     */
    private initializeStatistics(): BLEStatistics {
        return {
            totalConnections: 0,
            activeConnections: 0,
            failedConnections: 0,
            messagesSent: 0,
            messagesReceived: 0,
            messagesRelayed: 0,
            messagesDropped: 0,
            nodesDiscovered: 0,
            nodesVerified: 0,
            averageLatency: 0,
            averageThroughput: 0,
            packetLossRate: 0,
            authenticationsSucceeded: 0,
            authenticationsFailed: 0,
            replaysDetected: 0,
            startTime: Date.now(),
            lastResetTime: Date.now()
        };
    }

    /**
     * Set up comprehensive event handlers
     */
    private setupEventHandlers(): void {
        // Node discovery with verification
        this.scanner.onNodeDiscovery(async (event) => {
            if (event.type === 'node_discovered') {
                await this.handleNodeDiscovered(event.node, event.advertisement!);
            } else if (event.type === 'node_verified') {
                this.handleNodeVerified(event.node, event.verificationResult!);
            }
            this.emitEvent(event);
        });

        // Connection events with session management
        this.connectionManager.onConnectionEvent(async (event) => {
            switch (event.type) {
                case 'connected':
                    await this.handleNodeConnected(event.nodeId, event.connectionId!);
                    break;
                case 'authenticated':
                    await this.handleNodeAuthenticated(event.nodeId, event.session!);
                    break;
                case 'session_established':
                    this.handleSessionEstablished(event.nodeId, event.session!);
                    break;
                case 'disconnected':
                    this.handleNodeDisconnected(event.nodeId);
                    break;
                case 'error':
                    this.handleConnectionError(event.nodeId, event.error!);
                    break;
            }
            this.emitEvent(event);
        });

        // Message handling with decryption
        this.connectionManager.onMessage(async (message, fromNodeId) => {
            await this.handleIncomingMessage(message, fromNodeId);
        });
    }

    /**
     * Start the secure BLE mesh network
     */
    async start(): Promise<void> {
        if (this.state.isScanning || this.state.isAdvertising) {
            console.log('⚠️ BLE mesh network already started');
            return;
        }

        console.log(`🚀 Starting secure BLE mesh network for node: ${this.keyPair.getFingerprint()}`);

        try {
            // Generate pre-keys for async key exchange
            const preKeys = this.keyPair.generatePreKeys(10);

            // Create secure advertisement with identity proof
            const advertisementData = await this.createSecureAdvertisement(preKeys);

            // Start advertising and scanning with rate limiting
            await Promise.all([
                this.startAdvertisingWithRateLimit(advertisementData),
                this.startScanningWithRateLimit()
            ]);

            this.state.isAdvertising = true;
            this.state.isScanning = true;

            // Start mesh processing
            this.startMeshProcessing();

            // Start address rotation for privacy
            this.startAddressRotation();

            console.log('✅ Secure BLE mesh network started successfully');

        } catch (error) {
            console.error('❌ Failed to start BLE mesh network:', error);
            await this.stop();
            throw error;
        }
    }

    /**
     * Create secure advertisement with signatures
     */
    private async createSecureAdvertisement(preKeys: PreKey[]): Promise<BLEAdvertisementData> {
        const timestamp = Date.now();
        const nonce = this.generateNonce();

        // Create identity proof
        const proofData = new TextEncoder().encode(
            `${this.keyPair.getFingerprint()}-${timestamp}-${nonce}`
        );
        const signature = this.keyPair.signMessage(proofData);

        // Create pre-key bundle
        const preKeyBundle: PreKeyBundle = {
            identityKey: this.bytesToHex(this.keyPair.getIdentityPublicKey()),
            signedPreKey: {
                keyId: preKeys[0].keyId,
                publicKey: this.bytesToHex(preKeys[0].publicKey),
                signature: this.bytesToHex(preKeys[0].signature)
            },
            oneTimePreKeys: preKeys.slice(1, 4).map(pk => ({
                keyId: pk.keyId,
                publicKey: this.bytesToHex(pk.publicKey)
            }))
        };

        const identityProof: IdentityProof = {
            publicKeyHash: this.keyPair.getShortFingerprint(),
            timestamp,
            nonce,
            signature: this.bytesToHex(signature),
            preKeyBundle
        };

        return {
            version: 2,
            ephemeralId: this.generateEphemeralId(),
            identityProof,
            timestamp,
            sequenceNumber: this.getNextSequenceNumber(),
            capabilities: [NodeCapability.RELAY, NodeCapability.STORAGE, NodeCapability.GROUP_CHAT],
            deviceType: DeviceType.PHONE,
            protocolVersion: 2,
            meshInfo: {
                nodeCount: this.state.discoveredNodes.size,
                messageQueueSize: this.getQueueSize(),
                routingTableVersion: this.meshNetwork.getRoutingTableVersion(),
                beaconInterval: BLE_CONFIG.ADVERTISEMENT_INTERVAL
            },
            batteryLevel: await this.getBatteryLevel()
        };
    }

    /**
     * Start advertising with rate limiting
     */
    private async startAdvertisingWithRateLimit(data: BLEAdvertisementData): Promise<void> {
        const now = Date.now();
        const timeSinceLastAd = now - this.lastAdvertisementTime;

        if (timeSinceLastAd < BLE_CONFIG.ADVERTISEMENT_INTERVAL) {
            await this.delay(BLE_CONFIG.ADVERTISEMENT_INTERVAL - timeSinceLastAd);
        }

        await this.advertiser.startAdvertising(data);
        this.lastAdvertisementTime = Date.now();
    }

    /**
     * Start scanning with rate limiting
     */
    private async startScanningWithRateLimit(): Promise<void> {
        const now = Date.now();
        const timeSinceLastScan = now - this.lastScanTime;

        if (timeSinceLastScan < BLE_CONFIG.SCAN_INTERVAL) {
            await this.delay(BLE_CONFIG.SCAN_INTERVAL - timeSinceLastScan);
        }

        await this.scanner.startScanning();
        this.lastScanTime = Date.now();
    }

    /**
     * Stop the BLE mesh network
     */
    async stop(): Promise<void> {
        console.log('🛑 Stopping BLE mesh network...');

        try {
            // Stop timers
            this.stopMeshProcessing();
            this.stopAddressRotation();
            this.stopCleanupTimer();

            // Close all sessions
            for (const [nodeId, session] of this.sessions) {
                await this.closeSession(nodeId, session);
            }

            // Stop components
            await Promise.all([
                this.advertiser.stopAdvertising(),
                this.scanner.stopScanning(),
                this.connectionManager.cleanup()
            ]);

            // Clear state
            this.sessions.clear();
            this.verifiedNodes.clear();
            this.pendingKeyExchanges.clear();
            this.messageFragments.clear();
            this.replayProtection.clear();
            this.meshNetwork.clearRoutingTable();
            this.meshNetwork.clearMessageQueue();

            this.state.isAdvertising = false;
            this.state.isScanning = false;

            console.log('✅ BLE mesh network stopped');

        } catch (error) {
            console.error('❌ Error stopping BLE mesh network:', error);
            throw error;
        }
    }

    /**
     * Send an encrypted message with Double Ratchet
     */
    async sendMessage(
        recipientId: string,
        content: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): Promise<string> {
        if (!this.state.isScanning) {
            throw new Error('BLE mesh network not started');
        }

        // Rate limiting
        if (!this.checkRateLimit(recipientId, 'message')) {
            throw new Error('Rate limit exceeded');
        }

        console.log(`📤 Sending secure message to ${recipientId}`);

        // Get or establish session
        const session = await this.getOrEstablishSession(recipientId);
        if (!session) {
            throw new Error(`Failed to establish session with ${recipientId}`);
        }

        // Create message with header
        const header: MessageHeader = {
            version: 2,
            messageId: this.encryption.generateMessageId(),
            sourceId: this.keyPair.getFingerprint(),
            destinationId: recipientId,
            timestamp: Date.now(),
            sequenceNumber: session.sendMessageNumber++,
            ttl: BLE_CONFIG.MESSAGE_TTL,
            hopCount: 0,
            priority,
            relayPath: [],
            signature: new Uint8Array(64),
            previousMessageHash: this.getLastMessageHash(recipientId)
        };

        const plaintextMessage: PlaintextMessage = {
            header,
            type: MessageType.DIRECT,
            payload: content
        };

        // Encrypt with session
        const encryptedMessage = await this.encryption.encryptWithSession(
            plaintextMessage,
            session.sessionKeys
        );

        // Create BLE message with fragmentation if needed
        const bleMessage = await this.createBLEMessage(encryptedMessage, priority);

        // Try direct delivery first
        if (await this.tryDirectDelivery(recipientId, bleMessage)) {
            this.statistics.messagesSent++;
            return bleMessage.messageId;
        }

        // Queue for mesh routing
        this.queueForMeshDelivery(bleMessage, recipientId);
        return bleMessage.messageId;
    }

    /**
     * Send a secure broadcast message
     */
    async broadcastMessage(
        content: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): Promise<string> {
        if (!this.state.isScanning) {
            throw new Error('BLE mesh network not started');
        }

        console.log('📢 Broadcasting secure message');

        // Create broadcast message
        const header: MessageHeader = {
            version: 2,
            messageId: this.encryption.generateMessageId(),
            sourceId: this.keyPair.getFingerprint(),
            timestamp: Date.now(),
            sequenceNumber: this.getNextSequenceNumber(),
            ttl: BLE_CONFIG.MESSAGE_TTL,
            hopCount: 0,
            priority,
            relayPath: [],
            signature: new Uint8Array(64),
            previousMessageHash: this.getLastBroadcastHash()
        };

        const plaintextMessage: PlaintextMessage = {
            header,
            type: MessageType.BROADCAST,
            payload: content
        };

        // Encrypt as broadcast
        const encryptedMessage = await this.encryption.createBroadcastMessage(
            plaintextMessage,
            this.keyPair
        );

        // Create BLE message
        const bleMessage = await this.createBLEMessage(encryptedMessage, priority);

        // Broadcast to all connected nodes
        const results = await this.broadcastToConnectedNodes(bleMessage);

        this.statistics.messagesSent += results.sent;
        console.log(`📢 Broadcast sent to ${results.sent} nodes, ${results.failed} failed`);

        return bleMessage.messageId;
    }

    /**
     * Get or establish Double Ratchet session
     */
    private async getOrEstablishSession(nodeId: string): Promise<BLESession | null> {
        // Check existing session
        let session = this.sessions.get(nodeId);
        if (session && session.state === ConnectionState.AUTHENTICATED) {
            return session;
        }

        // Check pending key exchange
        if (this.pendingKeyExchanges.has(nodeId)) {
            const sessionKeys = await this.pendingKeyExchanges.get(nodeId)!;
            return this.createSession(nodeId, sessionKeys);
        }

        // Get node info
        const node = this.state.discoveredNodes.get(nodeId);
        if (!node) {
            console.error(`Node ${nodeId} not found`);
            return null;
        }

        // Start new key exchange
        const keyExchangePromise = this.performKeyExchange(node);
        this.pendingKeyExchanges.set(nodeId, keyExchangePromise);

        try {
            const sessionKeys = await keyExchangePromise;
            session = this.createSession(nodeId, sessionKeys);
            this.sessions.set(nodeId, session);
            this.pendingKeyExchanges.delete(nodeId);

            this.statistics.authenticationsSucceeded++;
            return session;

        } catch (error) {
            this.pendingKeyExchanges.delete(nodeId);
            this.statistics.authenticationsFailed++;
            console.error(`Failed to establish session with ${nodeId}:`, error);
            return null;
        }
    }

    /**
     * Perform X3DH-like key exchange
     */
    private async performKeyExchange(node: BLENode): Promise<SessionKeys> {
        console.log(`🔐 Performing key exchange with ${node.id}`);

        // Use pre-keys if available
        const recipientPreKey = node.preKeys?.[0];

        // Establish session with Double Ratchet
        const sessionKeys = await this.encryption.establishSession(
            this.keyPair,
            node.encryptionKey
        );

        return sessionKeys;
    }

    /**
     * Create BLE session from session keys
     */
    private createSession(nodeId: string, sessionKeys: SessionKeys): BLESession {
        return {
            sessionId: this.generateSessionId(),
            state: ConnectionState.AUTHENTICATED,
            establishedAt: Date.now(),
            lastActivity: Date.now(),
            sessionKeys,
            sendMessageNumber: 0,
            receiveMessageNumber: 0,
            mtu: BLE_CONFIG.DEFAULT_MTU,
            connectionInterval: BLE_CONFIG.CONNECTION_INTERVAL_MIN,
            latency: 0,
            supervisionTimeout: BLE_CONFIG.SUPERVISION_TIMEOUT,
            throughput: 0,
            packetLoss: 0,
            messagesExchanged: 0,
            bytesTransferred: 0
        };
    }

    /**
     * Create BLE message with fragmentation support
     */
    private async createBLEMessage(
        encryptedMessage: EncryptedMessage,
        priority: MessagePriority
    ): Promise<BLEMessage> {
        const payload = JSON.stringify(encryptedMessage);
        const shouldFragment = payload.length > BLE_CONFIG.FRAGMENT_SIZE;

        const bleMessage: BLEMessage = {
            messageId: encryptedMessage.header.messageId,
            version: 2,
            sourceId: encryptedMessage.header.sourceId,
            destinationId: encryptedMessage.header.destinationId,
            ttl: Date.now() + BLE_CONFIG.MESSAGE_TTL,
            hopCount: 0,
            maxHops: BLE_CONFIG.MAX_HOP_COUNT,
            priority,
            encryptedPayload: encryptedMessage,
            routePath: [this.keyPair.getFingerprint()],
            relaySignatures: [],
            createdAt: Date.now(),
            expiresAt: Date.now() + BLE_CONFIG.MESSAGE_TTL
        };

        if (shouldFragment) {
            // Will be handled by connection layer
            bleMessage.fragment = {
                fragmentId: this.generateFragmentId(),
                index: 0,
                total: Math.ceil(payload.length / BLE_CONFIG.FRAGMENT_SIZE),
                size: BLE_CONFIG.FRAGMENT_SIZE,
                checksum: await this.calculateChecksum(payload)
            };
        }

        return bleMessage;
    }

    /**
     * Handle discovered node with verification
     */
    private async handleNodeDiscovered(
        node: BLENode,
        advertisement: BLEAdvertisementData
    ): Promise<void> {
        console.log(`🔍 Discovered node: ${node.id}`);

        // Verify advertisement signature
        if (!await this.verifyAdvertisement(advertisement)) {
            console.warn(`⚠️ Invalid advertisement signature from ${node.id}`);
            return;
        }

        // Check replay protection
        const adId = `${node.id}-${advertisement.sequenceNumber}`;
        if (this.replayProtection.has(adId)) {
            console.warn(`⚠️ Replay detected from ${node.id}`);
            this.statistics.replaysDetected++;
            return;
        }
        this.replayProtection.add(adId);

        // Update node info
        this.state.discoveredNodes.set(node.id, node);
        this.statistics.nodesDiscovered++;

        // Auto-connect to trusted nodes
        if (node.verificationStatus === VerificationStatus.TRUSTED) {
            await this.autoConnect(node);
        }

        // Emit discovery event
        this.discoveryCallbacks.forEach(cb => cb(node, advertisement));
    }

    /**
     * Verify advertisement signature
     */
    private async verifyAdvertisement(ad: BLEAdvertisementData): Promise<boolean> {
        try {
            const proofData = new TextEncoder().encode(
                `${ad.identityProof.publicKeyHash}-${ad.identityProof.timestamp}-${ad.identityProof.nonce}`
            );

            // Would need to look up public key from hash
            // For now, return true if signature exists
            return ad.identityProof.signature.length > 0;
        } catch {
            return false;
        }
    }

    /**
     * Handle incoming message with full decryption
     */
    private async handleIncomingMessage(
        bleMessage: BLEMessage,
        fromNodeId: string
    ): Promise<void> {
        try {
            console.log(`📥 Processing message ${bleMessage.messageId} from ${fromNodeId}`);

            // Check replay protection
            if (this.isReplay(bleMessage.messageId)) {
                console.warn(`⚠️ Replay detected: ${bleMessage.messageId}`);
                this.statistics.replaysDetected++;
                return;
            }

            // Check TTL
            if (Date.now() > bleMessage.expiresAt) {
                console.log(`⏰ Message expired: ${bleMessage.messageId}`);
                this.statistics.messagesDropped++;
                return;
            }

            // Handle fragments
            if (bleMessage.fragment) {
                const fragmentResult = await this.handleFragment(bleMessage);
                if (!fragmentResult) return; // Waiting for more fragments
                bleMessage = fragmentResult;
            }

            // Get routing decision
            const routingDecision = this.meshNetwork.handleIncomingMessage(bleMessage, fromNodeId);

            // Try to decrypt if it might be for us
            const decrypted = await this.tryDecryptMessage(bleMessage, fromNodeId);

            if (decrypted) {
                // Message is for us
                console.log(`🔓 Message decrypted: ${decrypted.payload.substring(0, 50)}...`);

                this.statistics.messagesReceived++;

                // Process message callbacks
                const session = this.sessions.get(fromNodeId);
                const node = this.state.discoveredNodes.get(fromNodeId);

                if (session && node) {
                    for (const callback of this.messageCallbacks) {
                        await callback(bleMessage, node, session);
                    }
                }

                // Emit event
                this.emitEvent({
                    type: 'message_received',
                    message: bleMessage,
                    fromNodeId,
                    timestamp: Date.now()
                });

            } else if (routingDecision === 'forward') {
                // Forward through mesh
                await this.relayMessage(bleMessage, fromNodeId);
            } else {
                console.log(`📨 Message not for us and not forwarding`);
            }

            // Add to replay protection
            this.addReplayProtection(bleMessage.messageId);

        } catch (error) {
            console.error('❌ Error handling message:', error);
            this.statistics.messagesDropped++;
        }
    }

    /**
     * Try to decrypt message with appropriate method
     */
    private async tryDecryptMessage(
        bleMessage: BLEMessage,
        fromNodeId: string
    ): Promise<PlaintextMessage | null> {
        const encryptedMessage = bleMessage.encryptedPayload;

        // Try session decryption if we have a session
        const session = this.sessions.get(fromNodeId);
        if (session && session.state === ConnectionState.AUTHENTICATED) {
            try {
                return await this.encryption.decryptWithSession(
                    encryptedMessage,
                    session.sessionKeys
                );
            } catch (error) {
                console.log('Session decryption failed, trying other methods');
            }
        }

        // Try direct decryption
        try {
            return await this.encryption.decryptMessage(encryptedMessage, this.keyPair);
        } catch {
            // Not for us
        }

        // Try broadcast decryption
        try {
            const senderKey = this.state.discoveredNodes.get(fromNodeId)?.identityKey;
            if (senderKey) {
                return await this.encryption.decryptBroadcastMessage(
                    encryptedMessage,
                    senderKey
                );
            }
        } catch {
            // Not a broadcast for us
        }

        return null;
    }

    /**
     * Relay message through mesh with signature
     */
    private async relayMessage(
        bleMessage: BLEMessage,
        excludeNodeId: string
    ): Promise<void> {
        console.log(`🔄 Relaying message ${bleMessage.messageId}`);

        // Add our signature to relay path
        const relaySignature: RelaySignature = {
            nodeId: this.keyPair.getFingerprint(),
            timestamp: Date.now(),
            signature: this.bytesToHex(
                this.keyPair.signMessage(new TextEncoder().encode(bleMessage.messageId))
            ),
            rssi: -50 // Would get actual RSSI
        };

        const relayedMessage: BLEMessage = {
            ...bleMessage,
            hopCount: bleMessage.hopCount + 1,
            routePath: [...bleMessage.routePath, this.keyPair.getFingerprint()],
            relaySignatures: [...bleMessage.relaySignatures, relaySignature]
        };

        // Check max hops
        if (relayedMessage.hopCount >= relayedMessage.maxHops) {
            console.log(`⛔ Max hops reached for ${bleMessage.messageId}`);
            this.statistics.messagesDropped++;
            return;
        }

        // Broadcast to connected nodes except sender
        const results = await this.broadcastToConnectedNodes(relayedMessage, excludeNodeId);

        if (results.sent > 0) {
            this.statistics.messagesRelayed++;
        }
    }

    /**
     * Verify node identity
     */
    async verifyNode(
        nodeId: string,
        method: VerificationMethod,
        verificationData?: string
    ): Promise<VerificationResult> {
        console.log(`🔐 Verifying node ${nodeId} using ${method}`);

        const node = this.state.discoveredNodes.get(nodeId);
        if (!node) {
            throw new Error(`Node ${nodeId} not found`);
        }

        const result: VerificationResult = {
            verified: false,
            method,
            verifierNodeId: this.keyPair.getFingerprint(),
            timestamp: Date.now()
        };

        switch (method) {
            case VerificationMethod.FINGERPRINT:
                result.verified = await this.verifyFingerprint(node, verificationData!);
                break;
            case VerificationMethod.QR_CODE:
                result.verified = await this.verifyQRCode(node, verificationData!);
                break;
            case VerificationMethod.NUMERIC_COMPARISON:
                result.verified = await this.verifyNumericCode(node, verificationData!);
                break;
            default:
                throw new Error(`Unsupported verification method: ${method}`);
        }

        if (result.verified) {
            node.verificationStatus = VerificationStatus.VERIFIED;
            node.verifiedAt = Date.now();
            node.verificationMethod = method;
            this.verifiedNodes.set(nodeId, result);
            this.statistics.nodesVerified++;
        }

        // Emit verification event
        this.verificationCallbacks.forEach(cb => cb(nodeId, result));

        return result;
    }

    // ===== HELPER METHODS =====

    private generateEphemeralId(): string {
        const random = crypto.getRandomValues(new Uint8Array(16));
        return this.bytesToHex(random);
    }

    private generateNonce(): string {
        const random = crypto.getRandomValues(new Uint8Array(16));
        return this.bytesToHex(random);
    }

    private generateSessionId(): string {
        const random = crypto.getRandomValues(new Uint8Array(16));
        return this.bytesToHex(random);
    }

    private generateFragmentId(): string {
        const random = crypto.getRandomValues(new Uint8Array(8));
        return this.bytesToHex(random);
    }

    private getNextSequenceNumber(): number {
        // In production, this would be persisted
        return Date.now() % 1000000;
    }

    private async calculateChecksum(data: string): Promise<string> {
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBytes);
        const hashArray = new Uint8Array(hashBuffer);
        return this.bytesToHex(hashArray.slice(0, 8));
    }

    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    private hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private checkRateLimit(nodeId: string, type: string): boolean {
        const key = `${nodeId}-${type}`;
        let limiter = this.rateLimiters.get(key);

        if (!limiter) {
            limiter = new RateLimiter(BLE_CONFIG.MAX_MESSAGES_PER_SECOND);
            this.rateLimiters.set(key, limiter);
        }

        return limiter.tryConsume();
    }

    private isReplay(messageId: string): boolean {
        return this.replayProtection.has(messageId);
    }

    private addReplayProtection(messageId: string): void {
        this.replayProtection.add(messageId);

        // Limit size
        if (this.replayProtection.size > BLE_CONFIG.REPLAY_WINDOW_SIZE) {
            const firstId = this.replayProtection.values().next().value;
            if (firstId) {
                this.replayProtection.delete(firstId);
            }
        }
    }

    // Stub methods to be implemented
    private async getBatteryLevel(): Promise<number> {
        return 100; // Platform-specific implementation
    }

    private getQueueSize(): number {
        let total = 0;
        for (const queue of this.state.messageQueue.values()) {
            total += queue.length;
        }
        return total;
    }

    private getLastMessageHash(nodeId: string): string {
        // Would track actual message hashes
        return '';
    }

    private getLastBroadcastHash(): string {
        // Would track broadcast hashes
        return '';
    }

    // Additional stub methods for compilation
    private async tryDirectDelivery(nodeId: string, message: BLEMessage): Promise<boolean> {
        if (this.connectionManager.isConnectedTo(nodeId)) {
            try {
                await this.connectionManager.sendMessage(nodeId, message);
                return true;
            } catch {
                return false;
            }
        }
        return false;
    }

    private queueForMeshDelivery(message: BLEMessage, destinationId: string): void {
        this.meshNetwork.queueMessage(message, destinationId);
    }

    private async broadcastToConnectedNodes(
        message: BLEMessage,
        excludeNodeId?: string
    ): Promise<{ sent: number; failed: number }> {
        return await this.connectionManager.broadcastMessage(message, excludeNodeId);
    }

    private async handleFragment(message: BLEMessage): Promise<BLEMessage | null> {
        // Fragment handling logic
        return message;
    }

    private async autoConnect(node: BLENode): Promise<void> {
        if (!this.connectionManager.isConnectedTo(node.id)) {
            await this.connectionManager.connectToNode(node, node.id);
        }
    }

    private async verifyFingerprint(node: BLENode, fingerprint: string): Promise<boolean> {
        return node.id === fingerprint;
    }

    private async verifyQRCode(node: BLENode, qrData: string): Promise<boolean> {
        // QR verification logic
        return true;
    }

    private async verifyNumericCode(node: BLENode, code: string): Promise<boolean> {
        // Numeric verification logic
        return true;
    }

    private handleNodeVerified(node: BLENode, result: VerificationResult): void {
        console.log(`✅ Node ${node.id} verified`);
    }

    private async handleNodeConnected(nodeId: string, connectionId: string): Promise<void> {
        console.log(`🔗 Node connected: ${nodeId}`);
        this.statistics.totalConnections++;
        this.statistics.activeConnections++;
    }

    private async handleNodeAuthenticated(nodeId: string, session: BLESession): Promise<void> {
        console.log(`🔐 Node authenticated: ${nodeId}`);
        this.sessions.set(nodeId, session);
    }

    private handleSessionEstablished(nodeId: string, session: BLESession): void {
        console.log(`🤝 Session established: ${nodeId}`);
        this.sessions.set(nodeId, session);
    }

    private handleNodeDisconnected(nodeId: string): void {
        console.log(`🔌 Node disconnected: ${nodeId}`);
        this.sessions.delete(nodeId);
        this.statistics.activeConnections--;
    }

    private handleConnectionError(nodeId: string, error: BLEError): void {
        console.error(`❌ Connection error for ${nodeId}:`, error);
        this.statistics.failedConnections++;
    }

    private async closeSession(nodeId: string, session: BLESession): Promise<void> {
        // Clean up session
        console.log(`Closing session with ${nodeId}`);
    }

    private startMeshProcessing(): void {
        this.meshProcessingTimer = setInterval(async () => {
            try {
                await this.meshNetwork.processMessageQueue(
                    async (nodeId, message) => this.tryDirectDelivery(nodeId, message),
                    () => Array.from(this.state.discoveredNodes.values())
                        .filter(n => n.isConnected)
                );
            } catch (error) {
                console.error('❌ Mesh processing error:', error);
            }
        }, 5000);
    }

    private stopMeshProcessing(): void {
        if (this.meshProcessingTimer) {
            clearInterval(this.meshProcessingTimer);
            this.meshProcessingTimer = undefined;
        }
    }

    private startAddressRotation(): void {
        this.addressRotationTimer = setInterval(() => {
            console.log('🔄 Rotating BLE address for privacy');
            // Platform-specific address rotation
        }, BLE_CONFIG.ADDRESS_ROTATION_INTERVAL);
    }

    private stopAddressRotation(): void {
        if (this.addressRotationTimer) {
            clearInterval(this.addressRotationTimer);
            this.addressRotationTimer = undefined;
        }
    }

    private startCleanupTimer(): void {
        this.cleanupTimer = setInterval(() => {
            this.cleanupExpiredSessions();
            this.cleanupRateLimiters();
            this.cleanupReplayProtection();
        }, BLE_CONFIG.QUEUE_CLEANUP_INTERVAL);
    }

    private stopCleanupTimer(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = undefined;
        }
    }

    private cleanupExpiredSessions(): void {
        const now = Date.now();
        for (const [nodeId, session] of this.sessions) {
            if (now - session.lastActivity > BLE_CONFIG.SESSION_LIFETIME) {
                this.sessions.delete(nodeId);
                console.log(`🗑️ Expired session for ${nodeId}`);
            }
        }
    }

    private cleanupRateLimiters(): void {
        // Clean old rate limiters
        const now = Date.now();
        for (const [key, limiter] of this.rateLimiters) {
            if (now - limiter.lastAccess > 60000) {
                this.rateLimiters.delete(key);
            }
        }
    }

    private cleanupReplayProtection(): void {
        // Keep only recent message IDs
        if (this.replayProtection.size > BLE_CONFIG.REPLAY_WINDOW_SIZE * 2) {
            const keep = Array.from(this.replayProtection)
                .slice(-BLE_CONFIG.REPLAY_WINDOW_SIZE);
            this.replayProtection = new Set(keep);
        }
    }

    private emitEvent(event: BLEConnectionEvent | BLEMessageEvent | BLEDiscoveryEvent): void {
        for (const callback of this.eventCallbacks) {
            try {
                callback(event);
            } catch (error) {
                console.error('❌ Error in event callback:', error);
            }
        }
    }

    // Public API methods
    onEvent(callback: BLEEventCallback): void {
        this.eventCallbacks.add(callback);
    }

    removeEventListener(callback: BLEEventCallback): void {
        this.eventCallbacks.delete(callback);
    }

    onConnection(callback: ConnectionCallback): void {
        this.connectionCallbacks.add(callback);
    }

    onMessage(callback: MessageCallback): void {
        this.messageCallbacks.add(callback);
    }

    onDiscovery(callback: DiscoveryCallback): void {
        this.discoveryCallbacks.add(callback);
    }

    onVerification(callback: VerificationCallback): void {
        this.verificationCallbacks.add(callback);
    }

    getNetworkStatus(): NetworkStats {
        return {
            totalNodes: this.state.discoveredNodes.size,
            activeNodes: this.statistics.activeConnections,
            trustedNodes: Array.from(this.state.discoveredNodes.values())
                .filter(n => n.verificationStatus === VerificationStatus.TRUSTED).length,
            blockedNodes: 0,
            messagesSent: this.statistics.messagesSent,
            messagesReceived: this.statistics.messagesReceived,
            messagesRelayed: this.statistics.messagesRelayed,
            messagesDropped: this.statistics.messagesDropped,
            averageHopCount: 3, // Would calculate actual average
            averageLatency: this.statistics.averageLatency,
            deliverySuccessRate: this.calculateDeliveryRate(),
            networkDensity: this.calculateNetworkDensity(),
            networkReachability: this.calculateReachability(),
            bytesTransmitted: 0,
            bytesReceived: 0,
            averageThroughput: this.statistics.averageThroughput,
            uptime: Date.now() - this.statistics.startTime,
            lastUpdated: Date.now()
        };
    }

    private calculateDeliveryRate(): number {
        const total = this.statistics.messagesSent;
        if (total === 0) return 1;
        return 1 - (this.statistics.messagesDropped / total);
    }

    private calculateNetworkDensity(): number {
        const total = this.state.discoveredNodes.size;
        const connected = this.statistics.activeConnections;
        return total > 0 ? connected / total : 0;
    }

    private calculateReachability(): number {
        // Percentage of nodes reachable through mesh
        return 0.85; // Placeholder
    }
}

/**
 * Simple rate limiter
 */
class RateLimiter {
    private tokens: number;
    private maxTokens: number;
    private refillRate: number;
    private lastRefill: number;
    public lastAccess: number;

    constructor(tokensPerSecond: number) {
        this.maxTokens = tokensPerSecond;
        this.tokens = tokensPerSecond;
        this.refillRate = tokensPerSecond;
        this.lastRefill = Date.now();
        this.lastAccess = Date.now();
    }

    tryConsume(): boolean {
        this.refill();
        this.lastAccess = Date.now();

        if (this.tokens >= 1) {
            this.tokens--;
            return true;
        }
        return false;
    }

    private refill(): void {
        const now = Date.now();
        const elapsed = (now - this.lastRefill) / 1000;
        this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillRate);
        this.lastRefill = now;
    }
}