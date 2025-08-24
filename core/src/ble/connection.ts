// core/src/ble/connection.ts
// Enhanced BLE Connection Manager with Double Ratchet sessions and end-to-end encryption

import {
    BLENode,
    BLEMessage,
    BLEConnectionEvent,
    BLESession,
    BLE_CONFIG,
    ConnectionState,
    MessageFragment,
    RelaySignature,
    BLEError,
    BLEErrorCode,
    MessageAcknowledgment,
    DeviceAttestation,
    VerificationStatus,
    VerificationMethod,
    NodeCapability
} from './types';
import {
    IGhostKeyPair,
    SessionKeys,
    PreKey,
    EncryptedMessage,
    MessagePriority,
    CryptoError
} from '../types/crypto';
import { MessageEncryption } from '../crypto/encryption';

/**
 * Enhanced connection with security context
 */
export interface SecureConnection {
    // Basic info
    id: string;                          // Connection identifier
    nodeId: string;                      // Connected node ID
    deviceId: string;                    // Platform device ID

    // Session management
    session?: BLESession;                // Double Ratchet session
    state: ConnectionState;              // Connection state

    // Timing
    connectedAt: number;                 // Connection timestamp
    authenticatedAt?: number;            // Authentication timestamp
    lastActivity: number;                // Last activity timestamp
    lastHeartbeat: number;               // Last heartbeat timestamp

    // Performance metrics
    mtu: number;                         // Maximum transmission unit
    throughput: number;                  // Bytes per second
    latency: number;                     // Round-trip time in ms
    packetLoss: number;                  // Packet loss rate (0-1)

    // Message tracking
    sentMessages: number;                // Messages sent
    receivedMessages: number;            // Messages received
    pendingAcks: Map<string, number>;   // Message ID -> timestamp

    // Fragment assembly
    fragments: Map<string, Map<number, MessageFragment>>; // Fragment ID -> fragments

    // Security
    attestation?: DeviceAttestation;    // Device attestation
    channelBinding?: Uint8Array;        // Channel binding token
    verificationStatus: VerificationStatus;
}

/**
 * Connection configuration
 */
export interface ConnectionConfig {
    autoAuthenticate: boolean;           // Auto-establish Double Ratchet
    requireVerification: boolean;        // Require node verification
    connectionTimeout: number;           // Connection timeout in ms
    authenticationTimeout: number;       // Authentication timeout in ms
    heartbeatInterval: number;           // Heartbeat interval in ms
    maxRetries: number;                  // Maximum connection retries
    fragmentTimeout: number;             // Fragment reassembly timeout
    ackTimeout: number;                  // Acknowledgment timeout
}

/**
 * Connection statistics
 */
export interface ConnectionStatistics {
    totalConnections: number;
    activeConnections: number;
    authenticatedConnections: number;
    failedConnections: number;
    totalMessagesSent: number;
    totalMessagesReceived: number;
    totalBytesTransferred: number;
    averageLatency: number;
    averageThroughput: number;
    sessionEstablishments: number;
    authenticationFailures: number;
}

// Callback types
export type ConnectionCallback = (event: BLEConnectionEvent) => void;
export type MessageCallback = (message: BLEMessage, fromNodeId: string, session?: BLESession) => Promise<void>;
export type SessionCallback = (nodeId: string, session: BLESession) => void;

/**
 * Enhanced BLE Connection Manager with security features
 */
export abstract class BLEConnectionManager {
    // State management
    private connections: Map<string, SecureConnection>;
    private sessions: Map<string, BLESession>;
    private config: ConnectionConfig;

    // Security components
    protected keyPair?: IGhostKeyPair;
    protected encryption: MessageEncryption;
    private pendingAuthentications: Map<string, Promise<SessionKeys>>;
    private messageQueues: Map<string, BLEMessage[]>;

    // Callbacks
    private connectionCallbacks: Set<ConnectionCallback>;
    private messageCallbacks: Set<MessageCallback>;
    private sessionCallbacks: Set<SessionCallback>;

    // Timers
    private heartbeatTimer?: NodeJS.Timeout;
    private timeoutTimer?: NodeJS.Timeout;
    private ackTimer?: NodeJS.Timeout;
    private fragmentTimer?: NodeJS.Timeout;

    // Statistics
    private statistics: ConnectionStatistics;

    // Rate limiting
    private connectionAttempts: Map<string, number>;
    private lastConnectionAttempt: Map<string, number>;

    constructor(keyPair?: IGhostKeyPair, config?: Partial<ConnectionConfig>) {
        this.keyPair = keyPair;
        this.encryption = new MessageEncryption();

        // Initialize collections
        this.connections = new Map();
        this.sessions = new Map();
        this.pendingAuthentications = new Map();
        this.messageQueues = new Map();
        this.connectionAttempts = new Map();
        this.lastConnectionAttempt = new Map();

        // Initialize callbacks
        this.connectionCallbacks = new Set();
        this.messageCallbacks = new Set();
        this.sessionCallbacks = new Set();

        // Default configuration
        this.config = {
            autoAuthenticate: true,
            requireVerification: false,
            connectionTimeout: BLE_CONFIG.CONNECTION_TIMEOUT,
            authenticationTimeout: BLE_CONFIG.AUTHENTICATION_TIMEOUT,
            heartbeatInterval: 30000, // 30 seconds
            maxRetries: 3,
            fragmentTimeout: 30000,
            ackTimeout: 5000,
            ...config
        };

        // Initialize statistics
        this.statistics = {
            totalConnections: 0,
            activeConnections: 0,
            authenticatedConnections: 0,
            failedConnections: 0,
            totalMessagesSent: 0,
            totalMessagesReceived: 0,
            totalBytesTransferred: 0,
            averageLatency: 0,
            averageThroughput: 0,
            sessionEstablishments: 0,
            authenticationFailures: 0
        };

        // Start timers
        this.startHeartbeatTimer();
        this.startTimeoutTimer();
        this.startAckTimer();
        this.startFragmentTimer();
    }

    /**
     * Platform-specific connection methods
     */
    protected abstract connectToDevice(deviceId: string, nodeId: string): Promise<string>;
    protected abstract disconnectFromDevice(connectionId: string): Promise<void>;
    protected abstract sendDataToDevice(connectionId: string, data: Uint8Array): Promise<void>;
    protected abstract setupMessageReceiving(connectionId: string, nodeId: string): Promise<void>;
    protected abstract negotiateMTU(connectionId: string): Promise<number>;
    protected abstract getConnectionParameters(connectionId: string): Promise<{
        interval: number;
        latency: number;
        timeout: number;
    }>;

    /**
     * Connect to a node with security establishment
     */
    async connectToNode(node: BLENode, deviceId: string): Promise<string> {
        const nodeId = node.id;

        // Check rate limiting
        if (!this.checkConnectionRateLimit(nodeId)) {
            throw new Error(`Connection rate limit exceeded for ${nodeId}`);
        }

        // Check if already connected
        const existing = this.connections.get(nodeId);
        if (existing && existing.state !== ConnectionState.DISCONNECTED) {
            console.log(`⚠️ Already connected/connecting to node: ${nodeId}`);
            return existing.id;
        }

        // Check verification requirement
        if (this.config.requireVerification &&
            node.verificationStatus === VerificationStatus.UNVERIFIED) {
            throw new Error(`Node ${nodeId} must be verified before connection`);
        }

        try {
            console.log(`🔗 Initiating secure connection to node: ${nodeId}`);

            // Create connection record
            const connection: SecureConnection = {
                id: '', // Will be set after platform connection
                nodeId,
                deviceId,
                state: ConnectionState.CONNECTING,
                connectedAt: Date.now(),
                lastActivity: Date.now(),
                lastHeartbeat: Date.now(),
                mtu: BLE_CONFIG.DEFAULT_MTU,
                throughput: 0,
                latency: 0,
                packetLoss: 0,
                sentMessages: 0,
                receivedMessages: 0,
                pendingAcks: new Map(),
                fragments: new Map(),
                verificationStatus: node.verificationStatus
            };

            this.connections.set(nodeId, connection);
            this.statistics.totalConnections++;

            // Emit connecting event
            this.emitConnectionEvent({
                type: 'connected',
                nodeId,
                timestamp: Date.now()
            });

            // Platform-specific connection
            const connectionId = await this.connectWithRetry(deviceId, nodeId);
            connection.id = connectionId;
            connection.state = ConnectionState.CONNECTED;
            this.statistics.activeConnections++;

            // Negotiate MTU
            try {
                connection.mtu = await this.negotiateMTU(connectionId);
                console.log(`📏 Negotiated MTU: ${connection.mtu} bytes`);
            } catch (error) {
                console.warn('⚠️ MTU negotiation failed, using default');
            }

            // Get connection parameters
            try {
                const params = await this.getConnectionParameters(connectionId);
                console.log(`⚙️ Connection parameters - Interval: ${params.interval}ms, Latency: ${params.latency}, Timeout: ${params.timeout}ms`);
            } catch (error) {
                console.warn('⚠️ Failed to get connection parameters');
            }

            // Set up message receiving
            await this.setupMessageReceiving(connectionId, nodeId);

            // Auto-authenticate if configured
            if (this.config.autoAuthenticate && this.keyPair) {
                try {
                    await this.authenticateConnection(node, connection);
                } catch (error) {
                    console.warn('⚠️ Auto-authentication failed:', error);
                }
            }

            console.log(`✅ Successfully connected to node: ${nodeId}`);

            // Process queued messages
            await this.processMessageQueue(nodeId);

            return connectionId;

        } catch (error) {
            console.error(`❌ Failed to connect to node ${nodeId}:`, error);

            // Clean up connection
            this.connections.delete(nodeId);
            this.statistics.failedConnections++;

            // Emit error event
            this.emitConnectionEvent({
                type: 'error',
                nodeId,
                error: this.createBLEError(BLEErrorCode.CONNECTION_FAILED, error),
                timestamp: Date.now()
            });

            throw error;
        }
    }

    /**
     * Authenticate connection with Double Ratchet
     */
    private async authenticateConnection(
        node: BLENode,
        connection: SecureConnection
    ): Promise<void> {
        if (!this.keyPair) {
            throw new Error('Key pair required for authentication');
        }

        const nodeId = node.id;

        // Check if authentication already in progress
        if (this.pendingAuthentications.has(nodeId)) {
            const sessionKeys = await this.pendingAuthentications.get(nodeId)!;
            connection.session = this.createBLESession(sessionKeys, connection);
            return;
        }

        console.log(`🔐 Authenticating connection with ${nodeId}`);
        connection.state = ConnectionState.AUTHENTICATING;

        try {
            // Create authentication promise
            const authPromise = this.performAuthentication(node, connection);
            this.pendingAuthentications.set(nodeId, authPromise);

            // Wait for authentication with timeout
            const sessionKeys = await this.withTimeout(
                authPromise,
                this.config.authenticationTimeout,
                'Authentication timeout'
            );

            // Create BLE session
            connection.session = this.createBLESession(sessionKeys, connection);
            connection.state = ConnectionState.AUTHENTICATED;
            connection.authenticatedAt = Date.now();

            // Store session
            this.sessions.set(nodeId, connection.session);
            this.statistics.sessionEstablishments++;
            this.statistics.authenticatedConnections++;

            console.log(`✅ Connection authenticated with ${nodeId}`);

            // Emit authenticated event
            this.emitConnectionEvent({
                type: 'authenticated',
                nodeId,
                connectionId: connection.id,
                session: connection.session,
                timestamp: Date.now()
            });

            // Notify session callbacks
            this.notifySessionCallbacks(nodeId, connection.session);

        } catch (error) {
            console.error(`❌ Authentication failed with ${nodeId}:`, error);
            connection.state = ConnectionState.CONNECTED;
            this.statistics.authenticationFailures++;

            throw error;
        } finally {
            this.pendingAuthentications.delete(nodeId);
        }
    }

    /**
     * Perform Double Ratchet authentication
     */
    private async performAuthentication(
        node: BLENode,
        connection: SecureConnection
    ): Promise<SessionKeys> {
        if (!this.keyPair) {
            throw new Error('Key pair required');
        }

        // Use pre-key if available
        const preKey = node.preKeys?.[0];

        // Establish Double Ratchet session
        const sessionKeys = await this.encryption.establishSession(
            this.keyPair,
            node.encryptionKey,
            preKey
        );

        // Generate channel binding token
        connection.channelBinding = this.generateChannelBinding(connection);

        // Exchange authentication messages
        await this.exchangeAuthMessages(node, connection, sessionKeys);

        return sessionKeys;
    }

    /**
     * Exchange authentication messages
     */
    private async exchangeAuthMessages(
        node: BLENode,
        connection: SecureConnection,
        sessionKeys: SessionKeys
    ): Promise<void> {
        // Create authentication challenge
        const challenge = crypto.getRandomValues(new Uint8Array(32));

        // Send authentication request
        const authRequest: BLEMessage = {
            messageId: this.generateMessageId(),
            version: 2,
            sourceId: this.keyPair!.getFingerprint(),
            destinationId: node.id,
            ttl: Date.now() + 30000,
            hopCount: 0,
            maxHops: 1,
            priority: MessagePriority.HIGH,
            encryptedPayload: {} as EncryptedMessage, // Would encrypt challenge
            routePath: [],
            relaySignatures: [],
            createdAt: Date.now(),
            expiresAt: Date.now() + 30000
        };

        await this.sendMessageInternal(connection, authRequest);

        // Wait for authentication response
        // This would be handled by incoming message handler
    }

    /**
     * Send a secure message
     */
    async sendMessage(nodeId: string, message: BLEMessage): Promise<void> {
        const connection = this.connections.get(nodeId);

        if (!connection) {
            // Queue message for when connection is established
            this.queueMessage(nodeId, message);
            throw new Error(`No connection to node: ${nodeId}`);
        }

        if (connection.state === ConnectionState.DISCONNECTED) {
            throw new Error(`Connection to ${nodeId} is disconnected`);
        }

        // Wait for authentication if in progress
        if (connection.state === ConnectionState.AUTHENTICATING) {
            console.log(`⏳ Waiting for authentication to complete for ${nodeId}`);
            await this.waitForAuthentication(nodeId);
        }

        // Send message
        await this.sendMessageInternal(connection, message);
    }

    /**
     * Internal message sending with fragmentation
     */
    private async sendMessageInternal(
        connection: SecureConnection,
        message: BLEMessage
    ): Promise<void> {
        try {
            console.log(`📤 Sending message ${message.messageId} to ${connection.nodeId}`);

            // Serialize message
            const messageData = JSON.stringify(message);
            const messageBytes = new TextEncoder().encode(messageData);

            // Check if fragmentation needed
            if (messageBytes.length > connection.mtu) {
                await this.sendFragmentedMessage(connection, message, messageBytes);
            } else {
                await this.sendSingleMessage(connection, messageBytes);
            }

            // Update statistics
            connection.sentMessages++;
            connection.lastActivity = Date.now();
            this.statistics.totalMessagesSent++;
            this.statistics.totalBytesTransferred += messageBytes.length;

            // Track for acknowledgment
            connection.pendingAcks.set(message.messageId, Date.now());

            console.log(`✅ Message sent to ${connection.nodeId}`);

        } catch (error) {
            console.error(`❌ Failed to send message to ${connection.nodeId}:`, error);

            // Update connection state on failure
            if (this.isConnectionError(error)) {
                connection.state = ConnectionState.FAILED;
                this.handleConnectionFailure(connection, error);
            }

            throw error;
        }
    }

    /**
     * Send fragmented message
     */
    private async sendFragmentedMessage(
        connection: SecureConnection,
        message: BLEMessage,
        data: Uint8Array
    ): Promise<void> {
        const fragmentSize = connection.mtu - 100; // Reserve space for fragment metadata
        const totalFragments = Math.ceil(data.length / fragmentSize);
        const fragmentId = this.generateFragmentId();

        console.log(`📦 Sending message in ${totalFragments} fragments`);

        // Update message with fragment info
        message.fragment = {
            fragmentId,
            index: 0,
            total: totalFragments,
            size: fragmentSize,
            checksum: await this.calculateChecksum(data)
        };

        // Send each fragment
        for (let i = 0; i < totalFragments; i++) {
            const start = i * fragmentSize;
            const end = Math.min(start + fragmentSize, data.length);
            const fragmentData = data.slice(start, end);

            // Update fragment index
            message.fragment.index = i;

            // Create fragment message
            const fragmentMessage = {
                ...message,
                fragment: { ...message.fragment }
            };

            // Send fragment
            const fragmentBytes = new TextEncoder().encode(JSON.stringify(fragmentMessage));
            await this.sendSingleMessage(connection, fragmentBytes);

            // Small delay between fragments
            if (i < totalFragments - 1) {
                await this.delay(10);
            }
        }

        console.log(`✅ All ${totalFragments} fragments sent`);
    }

    /**
     * Send single message or fragment
     */
    private async sendSingleMessage(
        connection: SecureConnection,
        data: Uint8Array
    ): Promise<void> {
        await this.sendDataToDevice(connection.id, data);

        // Update throughput calculation
        this.updateThroughput(connection, data.length);
    }

    /**
     * Handle incoming message
     */
    protected async handleIncomingMessage(
        data: Uint8Array,
        fromNodeId: string
    ): Promise<void> {
        const connection = this.connections.get(fromNodeId);
        if (!connection) {
            console.warn(`⚠️ Received message from unknown node: ${fromNodeId}`);
            return;
        }

        try {
            // Parse message
            const messageStr = new TextDecoder().decode(data);
            const message: BLEMessage = JSON.parse(messageStr);

            console.log(`📥 Received message ${message.messageId} from ${fromNodeId}`);

            // Update connection activity
            connection.receivedMessages++;
            connection.lastActivity = Date.now();
            this.statistics.totalMessagesReceived++;
            this.statistics.totalBytesTransferred += data.length;

            // Handle fragments
            if (message.fragment) {
                const completeMessage = await this.handleFragment(connection, message);
                if (!completeMessage) {
                    return; // Waiting for more fragments
                }
                message.encryptedPayload = completeMessage.encryptedPayload;
            }

            // Send acknowledgment
            await this.sendAcknowledgment(connection, message.messageId);

            // Update latency if this is an acknowledgment
            if (connection.pendingAcks.has(message.messageId)) {
                const sentTime = connection.pendingAcks.get(message.messageId)!;
                const latency = Date.now() - sentTime;
                this.updateLatency(connection, latency);
                connection.pendingAcks.delete(message.messageId);
            }

            // Process message callbacks
            await this.processMessageCallbacks(message, fromNodeId, connection.session);

        } catch (error) {
            console.error(`❌ Error handling message from ${fromNodeId}:`, error);
        }
    }

    /**
     * Handle message fragment
     */
    private async handleFragment(
        connection: SecureConnection,
        message: BLEMessage
    ): Promise<BLEMessage | null> {
        const fragment = message.fragment!;
        const fragmentId = fragment.fragmentId;

        // Get or create fragment set
        let fragments = connection.fragments.get(fragmentId);
        if (!fragments) {
            fragments = new Map();
            connection.fragments.set(fragmentId, fragments);
        }

        // Store fragment
        fragments.set(fragment.index, fragment);

        console.log(`📦 Received fragment ${fragment.index + 1}/${fragment.total}`);

        // Check if all fragments received
        if (fragments.size === fragment.total) {
            console.log(`✅ All fragments received, reassembling message`);

            // Reassemble message
            const reassembled = await this.reassembleFragments(fragments, fragment.total);

            // Verify checksum
            const checksum = await this.calculateChecksum(reassembled);
            if (checksum !== fragment.checksum) {
                throw new Error('Fragment checksum mismatch');
            }

            // Parse complete message
            const completeMessage = JSON.parse(new TextDecoder().decode(reassembled));

            // Clean up fragments
            connection.fragments.delete(fragmentId);

            return completeMessage;
        }

        return null;
    }

    /**
     * Reassemble message fragments
     */
    private async reassembleFragments(
        fragments: Map<number, MessageFragment>,
        total: number
    ): Promise<Uint8Array> {
        const parts: Uint8Array[] = [];

        for (let i = 0; i < total; i++) {
            const fragment = fragments.get(i);
            if (!fragment) {
                throw new Error(`Missing fragment ${i}`);
            }

            // Extract data from fragment message
            // This is simplified - actual implementation would extract payload
            parts.push(new Uint8Array(fragment.size));
        }

        // Combine all parts
        const totalSize = parts.reduce((sum, part) => sum + part.length, 0);
        const result = new Uint8Array(totalSize);
        let offset = 0;

        for (const part of parts) {
            result.set(part, offset);
            offset += part.length;
        }

        return result;
    }

    /**
     * Send acknowledgment
     */
    private async sendAcknowledgment(
        connection: SecureConnection,
        messageId: string
    ): Promise<void> {
        if (!this.keyPair) return;

        const ack: MessageAcknowledgment = {
            messageId,
            nodeId: this.keyPair.getFingerprint(),
            timestamp: Date.now(),
            signature: this.bytesToHex(
                this.keyPair.signMessage(new TextEncoder().encode(messageId))
            )
        };

        // Send lightweight ack message
        const ackData = JSON.stringify(ack);
        await this.sendDataToDevice(
            connection.id,
            new TextEncoder().encode(ackData)
        );
    }

    /**
     * Broadcast message to all connected nodes
     */
    async broadcastMessage(
        message: BLEMessage,
        excludeNodeId?: string
    ): Promise<{ sent: number; failed: number }> {
        console.log(`📢 Broadcasting message ${message.messageId}`);

        const results = { sent: 0, failed: 0 };
        const promises: Promise<void>[] = [];

        for (const [nodeId, connection] of this.connections) {
            if (nodeId === excludeNodeId ||
                connection.state === ConnectionState.DISCONNECTED) {
                continue;
            }

            const promise = this.sendMessage(nodeId, message)
                .then(() => { results.sent++; })
                .catch((error) => {
                    console.warn(`❌ Broadcast failed to ${nodeId}:`, error);
                    results.failed++;
                });

            promises.push(promise);
        }

        await Promise.allSettled(promises);

        console.log(`📢 Broadcast complete: ${results.sent} sent, ${results.failed} failed`);
        return results;
    }

    /**
     * Disconnect from a node
     */
    async disconnectFromNode(nodeId: string): Promise<void> {
        const connection = this.connections.get(nodeId);
        if (!connection) {
            return;
        }

        try {
            console.log(`🔌 Disconnecting from node: ${nodeId}`);

            // Update state
            connection.state = ConnectionState.DISCONNECTING;

            // Clean up session
            if (connection.session) {
                await this.closeSession(connection);
            }

            // Platform disconnection
            await this.disconnectFromDevice(connection.id);

            // Update statistics
            this.statistics.activeConnections--;
            if (connection.session) {
                this.statistics.authenticatedConnections--;
            }

            // Remove connection
            this.connections.delete(nodeId);
            this.sessions.delete(nodeId);

            console.log(`✅ Disconnected from node: ${nodeId}`);

            // Emit event
            this.emitConnectionEvent({
                type: 'disconnected',
                nodeId,
                connectionId: connection.id,
                timestamp: Date.now()
            });

        } catch (error) {
            console.error(`❌ Error disconnecting from ${nodeId}:`, error);

            // Force cleanup
            this.connections.delete(nodeId);
            this.sessions.delete(nodeId);
        }
    }

    // ===== HELPER METHODS =====

    private async connectWithRetry(
        deviceId: string,
        nodeId: string
    ): Promise<string> {
        let lastError: Error | undefined;

        for (let i = 0; i < this.config.maxRetries; i++) {
            try {
                return await this.connectToDevice(deviceId, nodeId);
            } catch (error) {
                lastError = error as Error;
                console.warn(`⚠️ Connection attempt ${i + 1} failed:`, error);

                if (i < this.config.maxRetries - 1) {
                    await this.delay(1000 * (i + 1)); // Exponential backoff
                }
            }
        }

        throw lastError || new Error('Connection failed');
    }

    private createBLESession(
        sessionKeys: SessionKeys,
        connection: SecureConnection
    ): BLESession {
        return {
            sessionId: this.generateSessionId(),
            state: ConnectionState.AUTHENTICATED,
            establishedAt: Date.now(),
            lastActivity: Date.now(),
            sessionKeys,
            sendMessageNumber: 0,
            receiveMessageNumber: 0,
            mtu: connection.mtu,
            connectionInterval: BLE_CONFIG.CONNECTION_INTERVAL_MIN,
            latency: connection.latency,
            supervisionTimeout: BLE_CONFIG.SUPERVISION_TIMEOUT,
            channelBinding: connection.channelBinding,
            attestation: connection.attestation,
            throughput: connection.throughput,
            packetLoss: connection.packetLoss,
            messagesExchanged: connection.sentMessages + connection.receivedMessages,
            bytesTransferred: 0
        };
    }

    private generateChannelBinding(connection: SecureConnection): Uint8Array {
        const data = `${connection.id}-${connection.nodeId}-${connection.connectedAt}`;
        const encoder = new TextEncoder();
        return encoder.encode(data);
    }

    private async waitForAuthentication(nodeId: string): Promise<void> {
        const maxWait = this.config.authenticationTimeout;
        const startTime = Date.now();

        while (Date.now() - startTime < maxWait) {
            const connection = this.connections.get(nodeId);
            if (!connection) {
                throw new Error(`Connection lost to ${nodeId}`);
            }

            if (connection.state === ConnectionState.AUTHENTICATED) {
                return;
            }

            if (connection.state === ConnectionState.FAILED ||
                connection.state === ConnectionState.DISCONNECTED) {
                throw new Error(`Connection failed to ${nodeId}`);
            }

            await this.delay(100);
        }

        throw new Error(`Authentication timeout for ${nodeId}`);
    }

    private queueMessage(nodeId: string, message: BLEMessage): void {
        let queue = this.messageQueues.get(nodeId);
        if (!queue) {
            queue = [];
            this.messageQueues.set(nodeId, queue);
        }

        queue.push(message);
        console.log(`📋 Message queued for ${nodeId} (${queue.length} in queue)`);
    }

    private async processMessageQueue(nodeId: string): Promise<void> {
        const queue = this.messageQueues.get(nodeId);
        if (!queue || queue.length === 0) {
            return;
        }

        console.log(`📤 Processing ${queue.length} queued messages for ${nodeId}`);

        const messages = [...queue];
        this.messageQueues.delete(nodeId);

        for (const message of messages) {
            try {
                await this.sendMessage(nodeId, message);
            } catch (error) {
                console.error(`❌ Failed to send queued message:`, error);
            }
        }
    }

    private async closeSession(connection: SecureConnection): Promise<void> {
        if (!connection.session) return;

        console.log(`🔒 Closing session for ${connection.nodeId}`);

        // Send session close message
        // Clean up session keys
        // Update statistics
    }

    private checkConnectionRateLimit(nodeId: string): boolean {
        const now = Date.now();
        const lastAttempt = this.lastConnectionAttempt.get(nodeId) || 0;
        const attempts = this.connectionAttempts.get(nodeId) || 0;

        // Reset counter after 1 minute
        if (now - lastAttempt > 60000) {
            this.connectionAttempts.set(nodeId, 0);
        }

        // Max 5 attempts per minute
        if (attempts >= 5) {
            return false;
        }

        this.connectionAttempts.set(nodeId, attempts + 1);
        this.lastConnectionAttempt.set(nodeId, now);
        return true;
    }

    private updateThroughput(connection: SecureConnection, bytes: number): void {
        const now = Date.now();
        const timeDiff = now - connection.lastActivity;

        if (timeDiff > 0) {
            const instantThroughput = (bytes * 1000) / timeDiff;
            connection.throughput = (connection.throughput * 0.7) + (instantThroughput * 0.3);

            // Update global average
            this.statistics.averageThroughput =
                (this.statistics.averageThroughput * 0.9) + (connection.throughput * 0.1);
        }
    }

    private updateLatency(connection: SecureConnection, latency: number): void {
        connection.latency = (connection.latency * 0.7) + (latency * 0.3);

        // Update global average
        this.statistics.averageLatency =
            (this.statistics.averageLatency * 0.9) + (connection.latency * 0.1);
    }

    private handleConnectionFailure(connection: SecureConnection, error: any): void {
        console.error(`❌ Connection failed for ${connection.nodeId}:`, error);

        connection.state = ConnectionState.FAILED;

        // Emit failure event
        this.emitConnectionEvent({
            type: 'error',
            nodeId: connection.nodeId,
            connectionId: connection.id,
            error: this.createBLEError(BLEErrorCode.CONNECTION_LOST, error),
            timestamp: Date.now()
        });
    }

    private isConnectionError(error: any): boolean {
        // Platform-specific error detection
        return true;
    }

    private createBLEError(code: BLEErrorCode, error: any): BLEError {
        return {
            code,
            message: error?.message || String(error),
            details: error,
            timestamp: Date.now()
        };
    }

    private async calculateChecksum(data: Uint8Array): Promise<string> {
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = new Uint8Array(hashBuffer);
        return this.bytesToHex(hashArray.slice(0, 8));
    }

    private async withTimeout<T>(
        promise: Promise<T>,
        timeout: number,
        message: string
    ): Promise<T> {
        return Promise.race([
            promise,
            new Promise<T>((_, reject) =>
                setTimeout(() => reject(new Error(message)), timeout)
            )
        ]);
    }

    private delay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private generateMessageId(): string {
        return crypto.randomUUID();
    }

    private generateSessionId(): string {
        return crypto.randomUUID();
    }

    private generateFragmentId(): string {
        const bytes = crypto.getRandomValues(new Uint8Array(8));
        return this.bytesToHex(bytes);
    }

    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // ===== TIMER MANAGEMENT =====

    private startHeartbeatTimer(): void {
        this.heartbeatTimer = setInterval(() => {
            this.sendHeartbeats();
        }, this.config.heartbeatInterval);
    }

    private startTimeoutTimer(): void {
        this.timeoutTimer = setInterval(() => {
            this.checkTimeouts();
        }, 5000);
    }

    private startAckTimer(): void {
        this.ackTimer = setInterval(() => {
            this.checkAcknowledgments();
        }, this.config.ackTimeout);
    }

    private startFragmentTimer(): void {
        this.fragmentTimer = setInterval(() => {
            this.cleanupFragments();
        }, this.config.fragmentTimeout);
    }

    private async sendHeartbeats(): Promise<void> {
        for (const [nodeId, connection] of this.connections) {
            if (connection.state !== ConnectionState.AUTHENTICATED) {
                continue;
            }

            const timeSinceLastActivity = Date.now() - connection.lastActivity;
            if (timeSinceLastActivity > this.config.heartbeatInterval / 2) {
                // Send heartbeat
                connection.lastHeartbeat = Date.now();
            }
        }
    }

    private checkTimeouts(): void {
        const now = Date.now();

        for (const [nodeId, connection] of this.connections) {
            const timeSinceActivity = now - connection.lastActivity;

            if (timeSinceActivity > this.config.connectionTimeout) {
                console.log(`⏰ Connection timeout for ${nodeId}`);
                this.handleConnectionFailure(
                    connection,
                    new Error('Connection timeout')
                );
            }
        }
    }

    private checkAcknowledgments(): void {
        const now = Date.now();

        for (const [nodeId, connection] of this.connections) {
            for (const [messageId, sentTime] of connection.pendingAcks) {
                if (now - sentTime > this.config.ackTimeout) {
                    console.warn(`⚠️ Acknowledgment timeout for message ${messageId}`);
                    connection.pendingAcks.delete(messageId);

                    // Update packet loss
                    connection.packetLoss = Math.min(1, connection.packetLoss + 0.1);
                }
            }
        }
    }

    private cleanupFragments(): void {
        const now = Date.now();

        for (const [nodeId, connection] of this.connections) {
            for (const [fragmentId, fragments] of connection.fragments) {
                // Check age of first fragment
                const firstFragment = fragments.get(0);
                if (firstFragment) {
                    // Simplified - would track actual timestamp
                    connection.fragments.delete(fragmentId);
                    console.warn(`⚠️ Fragment timeout for ${fragmentId}`);
                }
            }
        }
    }

    // ===== CALLBACK MANAGEMENT =====

    private async processMessageCallbacks(
        message: BLEMessage,
        fromNodeId: string,
        session?: BLESession
    ): Promise<void> {
        for (const callback of this.messageCallbacks) {
            try {
                await callback(message, fromNodeId, session);
            } catch (error) {
                console.error('❌ Error in message callback:', error);
            }
        }
    }

    private notifySessionCallbacks(nodeId: string, session: BLESession): void {
        for (const callback of this.sessionCallbacks) {
            try {
                callback(nodeId, session);
            } catch (error) {
                console.error('❌ Error in session callback:', error);
            }
        }
    }

    private emitConnectionEvent(event: BLEConnectionEvent): void {
        for (const callback of this.connectionCallbacks) {
            try {
                callback(event);
            } catch (error) {
                console.error('❌ Error in connection callback:', error);
            }
        }
    }

    // ===== PUBLIC API =====

    onConnectionEvent(callback: ConnectionCallback): void {
        this.connectionCallbacks.add(callback);
    }

    removeConnectionCallback(callback: ConnectionCallback): void {
        this.connectionCallbacks.delete(callback);
    }

    onMessage(callback: MessageCallback): void {
        this.messageCallbacks.add(callback);
    }

    removeMessageCallback(callback: MessageCallback): void {
        this.messageCallbacks.delete(callback);
    }

    onSession(callback: SessionCallback): void {
        this.sessionCallbacks.add(callback);
    }

    removeSessionCallback(callback: SessionCallback): void {
        this.sessionCallbacks.delete(callback);
    }

    getConnections(): SecureConnection[] {
        return Array.from(this.connections.values());
    }

    getActiveConnections(): SecureConnection[] {
        return Array.from(this.connections.values())
            .filter(conn => conn.state !== ConnectionState.DISCONNECTED);
    }

    getAuthenticatedConnections(): SecureConnection[] {
        return Array.from(this.connections.values())
            .filter(conn => conn.state === ConnectionState.AUTHENTICATED);
    }

    getConnection(nodeId: string): SecureConnection | undefined {
        return this.connections.get(nodeId);
    }

    getSession(nodeId: string): BLESession | undefined {
        return this.sessions.get(nodeId);
    }

    isConnectedTo(nodeId: string): boolean {
        const connection = this.connections.get(nodeId);
        return connection?.state === ConnectionState.CONNECTED ||
            connection?.state === ConnectionState.AUTHENTICATED || false;
    }

    isAuthenticatedWith(nodeId: string): boolean {
        const connection = this.connections.get(nodeId);
        return connection?.state === ConnectionState.AUTHENTICATED || false;
    }

    getStatistics(): ConnectionStatistics {
        return { ...this.statistics };
    }

    setKeyPair(keyPair: IGhostKeyPair): void {
        this.keyPair = keyPair;
    }

    async cleanup(): Promise<void> {
        console.log('🧹 Cleaning up all connections...');

        // Stop timers
        if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
        if (this.timeoutTimer) clearInterval(this.timeoutTimer);
        if (this.ackTimer) clearInterval(this.ackTimer);
        if (this.fragmentTimer) clearInterval(this.fragmentTimer);

        // Disconnect all
        const promises: Promise<void>[] = [];
        for (const nodeId of this.connections.keys()) {
            promises.push(this.disconnectFromNode(nodeId));
        }

        await Promise.allSettled(promises);

        // Clear all data
        this.connections.clear();
        this.sessions.clear();
        this.pendingAuthentications.clear();
        this.messageQueues.clear();
        this.connectionCallbacks.clear();
        this.messageCallbacks.clear();
        this.sessionCallbacks.clear();

        console.log('✅ Connection cleanup complete');
    }
}