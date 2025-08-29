// core/src/ble/connection.ts
// Enhanced BLE Connection Manager with Protocol v2 Security

import {
    BLENode,
    BLEMessage,
    BLEConnectionEvent,
    BLESession,
    BLE_CONFIG,
    BLE_SECURITY_CONFIG,
    ConnectionState,
    MessageFragment,
    RelaySignature,
    BLEError,
    BLEErrorCode,
    MessageAcknowledgment,
    DeviceAttestation,
    VerificationStatus,
    VerificationMethod,
    NodeCapability,
    MessageVerificationContext,
    ProtocolHandshake
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
 * Enhanced connection with Protocol v2 security context
 */
export interface SecureConnection {
    // Basic info
    id: string;                          // Connection identifier
    nodeId: string;                      // Connected node ID
    deviceId: string;                    // Platform device ID

    // Protocol version tracking (v2)
    protocolVersion: number;             // Peer's protocol version
    requiresSignatureVerification: boolean; // v2 requirement

    // Session management with chain tracking
    session?: BLESession;                // Double Ratchet session with chain state
    state: ConnectionState;              // Connection state

    // Message chain tracking (Protocol v2)
    messageChain: {
        lastSentHash: string;
        lastReceivedHash: string;
        sentSequence: number;
        receivedSequence: number;
    };

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
    
    // Public key cache (Protocol v2)
    peerPublicKeys?: {
        identity: Uint8Array;            // Ed25519 public key for verification
        encryption: Uint8Array;          // X25519 public key
    };
}

/**
 * Connection configuration with Protocol v2 settings
 */
export interface ConnectionConfig {
    autoAuthenticate: boolean;           // Auto-establish Double Ratchet
    requireVerification: boolean;        // Require node verification
    requireProtocolV2: boolean;         // Require Protocol v2 (default: true)
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
    signatureVerificationFailures: number; // Protocol v2
    messageChainBreaks: number;            // Protocol v2
}

// Callback types with Protocol v2 verification
export type ConnectionCallback = (event: BLEConnectionEvent) => void;
export type MessageCallback = (
    message: BLEMessage, 
    fromNodeId: string, 
    session?: BLESession,
    verificationResult?: { verified: boolean; error?: string }
) => Promise<void>;
export type SessionCallback = (nodeId: string, session: BLESession) => void;

/**
 * Enhanced BLE Connection Manager with Protocol v2 security
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

        // Default configuration with Protocol v2
        this.config = {
            autoAuthenticate: true,
            requireVerification: false,
            requireProtocolV2: BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION,
            connectionTimeout: BLE_CONFIG.CONNECTION_TIMEOUT,
            authenticationTimeout: BLE_CONFIG.AUTHENTICATION_TIMEOUT,
            heartbeatInterval: 30000,
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
            authenticationFailures: 0,
            signatureVerificationFailures: 0,
            messageChainBreaks: 0
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
     * Connect to a node with Protocol v2 security establishment
     */
    async connectToNode(node: BLENode, deviceId: string): Promise<string> {
        const nodeId = node.id;

        // Check protocol version compatibility
        if (this.config.requireProtocolV2 && node.protocolVersion < BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            throw new Error(`Node ${nodeId} uses incompatible protocol version ${node.protocolVersion}. Required: v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}`);
        }

        // Check rate limiting
        if (!this.checkConnectionRateLimit(nodeId)) {
            throw new Error(`Connection rate limit exceeded for ${nodeId}`);
        }

        // Check if already connected
        const existing = this.connections.get(nodeId);
        if (existing && existing.state !== ConnectionState.DISCONNECTED) {
            console.log(`Already connected/connecting to node: ${nodeId}`);
            return existing.id;
        }

        // Check verification requirement
        if (this.config.requireVerification &&
            node.verificationStatus === VerificationStatus.UNVERIFIED) {
            throw new Error(`Node ${nodeId} must be verified before connection`);
        }

        try {
            console.log(`Initiating secure connection to node: ${nodeId} (Protocol v${node.protocolVersion})`);

            // Create connection record with Protocol v2 fields
            const connection: SecureConnection = {
                id: '', // Will be set after platform connection
                nodeId,
                deviceId,
                protocolVersion: node.protocolVersion,
                requiresSignatureVerification: node.protocolVersion >= 2,
                state: ConnectionState.CONNECTING,
                messageChain: {
                    lastSentHash: '',
                    lastReceivedHash: '',
                    sentSequence: 0,
                    receivedSequence: 0
                },
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

            // Cache peer's public keys if available
            if (node.identityKey && node.encryptionKey) {
                connection.peerPublicKeys = {
                    identity: node.identityKey,
                    encryption: node.encryptionKey
                };
            }

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
                console.log(`Negotiated MTU: ${connection.mtu} bytes`);
            } catch (error) {
                console.warn('MTU negotiation failed, using default');
            }

            // Get connection parameters
            try {
                const params = await this.getConnectionParameters(connectionId);
                console.log(`Connection parameters - Interval: ${params.interval}ms, Latency: ${params.latency}, Timeout: ${params.timeout}ms`);
            } catch (error) {
                console.warn('Failed to get connection parameters');
            }

            // Set up message receiving
            await this.setupMessageReceiving(connectionId, nodeId);

            // Perform Protocol v2 handshake if required
            if (connection.requiresSignatureVerification) {
                await this.performProtocolHandshake(node, connection);
            }

            // Auto-authenticate if configured
            if (this.config.autoAuthenticate && this.keyPair) {
                try {
                    await this.authenticateConnection(node, connection);
                } catch (error) {
                    console.warn('Auto-authentication failed:', error);
                }
            }

            console.log(`Successfully connected to node: ${nodeId} (Protocol v${connection.protocolVersion})`);

            // Process queued messages
            await this.processMessageQueue(nodeId);

            return connectionId;

        } catch (error) {
            console.error(`Failed to connect to node ${nodeId}:`, error);

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
     * Perform Protocol v2 handshake
     */
    private async performProtocolHandshake(
        node: BLENode,
        connection: SecureConnection
    ): Promise<void> {
        if (!this.keyPair) {
            throw new Error('Key pair required for Protocol v2 handshake');
        }

        console.log(`Performing Protocol v2 handshake with ${node.id}`);

        const handshake: ProtocolHandshake = {
            protocolVersion: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
            supportedVersions: [2],
            identityKey: this.bytesToHex(this.keyPair.getIdentityPublicKey()),
            encryptionKey: this.bytesToHex(this.keyPair.getEncryptionPublicKey()),
            timestamp: Date.now(),
            nonce: this.generateNonce(),
            signature: '',
            capabilities: [NodeCapability.RELAY, NodeCapability.STORAGE],
            requireSignatureVerification: BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION
        };

        // Sign handshake
        const handshakeData = JSON.stringify(handshake);
        const signature = this.keyPair.signMessage(handshakeData);
        handshake.signature = this.bytesToHex(signature);

        // Send handshake message
        const handshakeMessage: BLEMessage = {
            messageId: this.generateMessageId(),
            version: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
            sourceId: this.keyPair.getFingerprint(),
            destinationId: node.id,
            senderPublicKey: this.bytesToHex(this.keyPair.getIdentityPublicKey()),
            messageSignature: handshake.signature,
            messageHash: await this.calculateHash(handshakeData),
            previousMessageHash: '',
            sequenceNumber: 0,
            ttl: Date.now() + 30000,
            hopCount: 0,
            maxHops: 1,
            priority: MessagePriority.HIGH,
            encryptedPayload: {} as EncryptedMessage, // Handshake is not encrypted
            routePath: [],
            relaySignatures: [],
            createdAt: Date.now(),
            expiresAt: Date.now() + 30000
        };

        await this.sendMessageInternal(connection, handshakeMessage);
        console.log(`Protocol v2 handshake sent to ${node.id}`);
    }

    /**
     * Authenticate connection with Double Ratchet and Protocol v2
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

        console.log(`Authenticating connection with ${nodeId} (Protocol v${connection.protocolVersion})`);
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

            // Create BLE session with Protocol v2 fields
            connection.session = this.createBLESession(sessionKeys, connection);
            connection.state = ConnectionState.AUTHENTICATED;
            connection.authenticatedAt = Date.now();

            // Store session
            this.sessions.set(nodeId, connection.session);
            this.statistics.sessionEstablishments++;
            this.statistics.authenticatedConnections++;

            console.log(`Connection authenticated with ${nodeId}`);

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
            console.error(`Authentication failed with ${nodeId}:`, error);
            connection.state = ConnectionState.CONNECTED;
            this.statistics.authenticationFailures++;

            throw error;
        } finally {
            this.pendingAuthentications.delete(nodeId);
        }
    }

    /**
     * Create BLE session with Protocol v2 chain tracking
     */
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
            // Protocol v2 chain tracking
            lastSentMessageHash: connection.messageChain.lastSentHash,
            lastReceivedMessageHash: connection.messageChain.lastReceivedHash,
            sentSequenceNumber: connection.messageChain.sentSequence,
            receivedSequenceNumber: connection.messageChain.receivedSequence,
            // Cached peer keys
            peerIdentityKey: connection.peerPublicKeys?.identity,
            peerEncryptionKey: connection.peerPublicKeys?.encryption,
            // Connection parameters
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

    /**
     * Send a secure message with Protocol v2 requirements
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

        // Verify message has Protocol v2 required fields
        if (connection.requiresSignatureVerification) {
            if (!message.senderPublicKey) {
                throw new Error('Protocol v2 requires senderPublicKey in message');
            }
            if (!message.messageSignature) {
                throw new Error('Protocol v2 requires messageSignature in message');
            }
        }

        // Wait for authentication if in progress
        if (connection.state === ConnectionState.AUTHENTICATING) {
            console.log(`Waiting for authentication to complete for ${nodeId}`);
            await this.waitForAuthentication(nodeId);
        }

        // Update message chain
        message.previousMessageHash = connection.messageChain.lastSentHash;
        message.sequenceNumber = connection.messageChain.sentSequence++;

        // Calculate and store message hash
        const messageHash = await this.calculateMessageHash(message);
        message.messageHash = messageHash;
        connection.messageChain.lastSentHash = messageHash;

        // Update session chain state if authenticated
        if (connection.session) {
            connection.session.lastSentMessageHash = messageHash;
            connection.session.sentSequenceNumber = connection.messageChain.sentSequence;
        }

        // Send message
        await this.sendMessageInternal(connection, message);
    }

    /**
     * Handle incoming message with Protocol v2 verification
     */
    protected async handleIncomingMessage(
        data: Uint8Array,
        fromNodeId: string
    ): Promise<void> {
        const connection = this.connections.get(fromNodeId);
        if (!connection) {
            console.warn(`Received message from unknown node: ${fromNodeId}`);
            return;
        }

        try {
            // Parse message
            const messageStr = new TextDecoder().decode(data);
            const message: BLEMessage = JSON.parse(messageStr);

            console.log(`Received message ${message.messageId} from ${fromNodeId} (Protocol v${message.version})`);

            // Protocol v2: Verify signature if required
            let verificationResult: { verified: boolean; error?: string } | undefined;
            
            if (connection.requiresSignatureVerification || message.version >= 2) {
                verificationResult = await this.verifyMessageSignature(message, connection);
                
                if (!verificationResult.verified) {
                    console.error(`Signature verification failed: ${verificationResult.error}`);
                    this.statistics.signatureVerificationFailures++;
                    
                    // Emit signature verification failure
                    this.emitConnectionEvent({
                        type: 'error',
                        nodeId: fromNodeId,
                        connectionId: connection.id,
                        error: this.createBLEError(
                            BLEErrorCode.SIGNATURE_VERIFICATION_FAILED,
                            verificationResult.error
                        ),
                        timestamp: Date.now()
                    });
                    
                    return; // Reject message
                }
            }

            // Verify message chain if we have history
            if (connection.messageChain.lastReceivedHash && BLE_SECURITY_CONFIG.REQUIRE_MESSAGE_CHAINING) {
                if (!this.verifyMessageChain(message, connection)) {
                    console.error('Message chain verification failed');
                    this.statistics.messageChainBreaks++;
                    // Continue processing but note the break
                }
            }

            // Update connection activity
            connection.receivedMessages++;
            connection.lastActivity = Date.now();
            this.statistics.totalMessagesReceived++;
            this.statistics.totalBytesTransferred += data.length;

            // Update message chain
            connection.messageChain.lastReceivedHash = message.messageHash;
            connection.messageChain.receivedSequence = message.sequenceNumber;

            // Update session chain state if authenticated
            if (connection.session) {
                connection.session.lastReceivedMessageHash = message.messageHash;
                connection.session.receivedSequenceNumber = message.sequenceNumber;
            }

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

            // Process message callbacks with verification result
            await this.processMessageCallbacks(message, fromNodeId, connection.session, verificationResult);

        } catch (error) {
            console.error(`Error handling message from ${fromNodeId}:`, error);
        }
    }

    /**
     * Verify message signature with Protocol v2 requirements
     */
    private async verifyMessageSignature(
        message: BLEMessage,
        connection: SecureConnection
    ): Promise<{ verified: boolean; error?: string }> {
        // Check for required fields
        if (!message.senderPublicKey) {
            return { verified: false, error: BLEErrorCode.NO_SENDER_KEY };
        }

        if (!message.messageSignature) {
            return { verified: false, error: 'Missing message signature' };
        }

        try {
            // Get sender's public key
            const senderPublicKey = connection.peerPublicKeys?.identity || 
                                   this.hexToBytes(message.senderPublicKey);

            // Verify the signature
            const messageHashBytes = new TextEncoder().encode(message.messageHash);
            const signatureBytes = this.hexToBytes(message.messageSignature);

            if (!this.keyPair) {
                return { verified: false, error: 'No key pair for verification' };
            }

            const verified = this.keyPair.verifySignature(
                messageHashBytes,
                signatureBytes,
                senderPublicKey // Protocol v2: Third parameter required
            );

            return { verified, error: verified ? undefined : 'Invalid signature' };

        } catch (error) {
            return { verified: false, error: String(error) };
        }
    }

    /**
     * Verify message chain integrity
     */
    private verifyMessageChain(
        message: BLEMessage,
        connection: SecureConnection
    ): boolean {
        // Check sequence number
        if (BLE_SECURITY_CONFIG.REQUIRE_SEQUENCE_NUMBERS) {
            const expectedSequence = connection.messageChain.receivedSequence + 1;
            if (message.sequenceNumber !== expectedSequence) {
                console.warn(`Sequence mismatch: expected ${expectedSequence}, got ${message.sequenceNumber}`);
                // Allow some gap for network issues
                if (Math.abs(message.sequenceNumber - expectedSequence) > BLE_SECURITY_CONFIG.MAX_SEQUENCE_NUMBER_GAP) {
                    return false;
                }
            }
        }

        // Check message chain hash
        if (message.previousMessageHash !== connection.messageChain.lastReceivedHash) {
            console.warn(`Chain break: expected ${connection.messageChain.lastReceivedHash}, got ${message.previousMessageHash}`);
            return false;
        }

        return true;
    }

    /**
     * Internal message sending with fragmentation
     */
    private async sendMessageInternal(
        connection: SecureConnection,
        message: BLEMessage
    ): Promise<void> {
        try {
            console.log(`Sending message ${message.messageId} to ${connection.nodeId}`);

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

            console.log(`Message sent to ${connection.nodeId}`);

        } catch (error) {
            console.error(`Failed to send message to ${connection.nodeId}:`, error);

            // Update connection state on failure
            if (this.isConnectionError(error)) {
                connection.state = ConnectionState.FAILED;
                this.handleConnectionFailure(connection, error);
            }

            throw error;
        }
    }

    /**
     * Process message callbacks with Protocol v2 verification result
     */
    private async processMessageCallbacks(
        message: BLEMessage,
        fromNodeId: string,
        session?: BLESession,
        verificationResult?: { verified: boolean; error?: string }
    ): Promise<void> {
        for (const callback of this.messageCallbacks) {
            try {
                await callback(message, fromNodeId, session, verificationResult);
            } catch (error) {
                console.error('Error in message callback:', error);
            }
        }
    }

    // ... [Keep all other existing methods] ...

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

    private async exchangeAuthMessages(
        node: BLENode,
        connection: SecureConnection,
        sessionKeys: SessionKeys
    ): Promise<void> {
        if (!this.keyPair) return;

        // Create authentication challenge
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        const challengeHash = await this.calculateHash(this.bytesToHex(challenge));

        // Sign the challenge
        const signature = this.keyPair.signMessage(challenge);

        // Send authentication request with Protocol v2 fields
        const authRequest: BLEMessage = {
            messageId: this.generateMessageId(),
            version: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
            sourceId: this.keyPair.getFingerprint(),
            destinationId: node.id,
            senderPublicKey: this.bytesToHex(this.keyPair.getIdentityPublicKey()),
            messageSignature: this.bytesToHex(signature),
            messageHash: challengeHash,
            previousMessageHash: '',
            sequenceNumber: 0,
            ttl: Date.now() + 30000,
            hopCount: 0,
            maxHops: 1,
            priority: MessagePriority.HIGH,
            encryptedPayload: {} as EncryptedMessage,
            routePath: [],
            relaySignatures: [],
            createdAt: Date.now(),
            expiresAt: Date.now() + 30000
        };

        await this.sendMessageInternal(connection, authRequest);
    }

    // Utility methods
    private async calculateMessageHash(message: BLEMessage): Promise<string> {
        const messageData = JSON.stringify({
            messageId: message.messageId,
            sourceId: message.sourceId,
            destinationId: message.destinationId,
            sequenceNumber: message.sequenceNumber,
            encryptedPayload: message.encryptedPayload
        });
        return this.calculateHash(messageData);
    }

    private async calculateHash(data: string): Promise<string> {
        const encoder = new TextEncoder();
        const dataBytes = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBytes);
        return this.bytesToHex(new Uint8Array(hashBuffer));
    }

    private generateNonce(): string {
        return this.bytesToHex(crypto.getRandomValues(new Uint8Array(16)));
    }

    private hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    // ... [Include all other existing methods unchanged] ...

    private async sendFragmentedMessage(
        connection: SecureConnection,
        message: BLEMessage,
        data: Uint8Array
    ): Promise<void> {
        const fragmentSize = connection.mtu - 100;
        const totalFragments = Math.ceil(data.length / fragmentSize);
        const fragmentId = this.generateFragmentId();

        console.log(`Sending message in ${totalFragments} fragments`);

        message.fragment = {
            fragmentId,
            index: 0,
            total: totalFragments,
            size: fragmentSize,
            checksum: await this.calculateChecksum(data)
        };

        for (let i = 0; i < totalFragments; i++) {
            const start = i * fragmentSize;
            const end = Math.min(start + fragmentSize, data.length);
            const fragmentData = data.slice(start, end);

            message.fragment.index = i;

            const fragmentMessage = {
                ...message,
                fragment: { ...message.fragment }
            };

            const fragmentBytes = new TextEncoder().encode(JSON.stringify(fragmentMessage));
            await this.sendSingleMessage(connection, fragmentBytes);

            if (i < totalFragments - 1) {
                await this.delay(10);
            }
        }

        console.log(`All ${totalFragments} fragments sent`);
    }

    private async sendSingleMessage(
        connection: SecureConnection,
        data: Uint8Array
    ): Promise<void> {
        await this.sendDataToDevice(connection.id, data);
        this.updateThroughput(connection, data.length);
    }

    private async handleFragment(
        connection: SecureConnection,
        message: BLEMessage
    ): Promise<BLEMessage | null> {
        const fragment = message.fragment!;
        const fragmentId = fragment.fragmentId;

        let fragments = connection.fragments.get(fragmentId);
        if (!fragments) {
            fragments = new Map();
            connection.fragments.set(fragmentId, fragments);
        }

        fragments.set(fragment.index, fragment);

        console.log(`Received fragment ${fragment.index + 1}/${fragment.total}`);

        if (fragments.size === fragment.total) {
            console.log(`All fragments received, reassembling message`);

            const reassembled = await this.reassembleFragments(fragments, fragment.total);

            const checksum = await this.calculateChecksum(reassembled);
            if (checksum !== fragment.checksum) {
                throw new Error('Fragment checksum mismatch');
            }

            const completeMessage = JSON.parse(new TextDecoder().decode(reassembled));

            connection.fragments.delete(fragmentId);

            return completeMessage;
        }

        return null;
    }

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
            parts.push(new Uint8Array(fragment.size));
        }

        const totalSize = parts.reduce((sum, part) => sum + part.length, 0);
        const result = new Uint8Array(totalSize);
        let offset = 0;

        for (const part of parts) {
            result.set(part, offset);
            offset += part.length;
        }

        return result;
    }

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

        const ackData = JSON.stringify(ack);
        await this.sendDataToDevice(
            connection.id,
            new TextEncoder().encode(ackData)
        );
    }

    async broadcastMessage(
        message: BLEMessage,
        excludeNodeId?: string
    ): Promise<{ sent: number; failed: number }> {
        console.log(`Broadcasting message ${message.messageId}`);

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
                    console.warn(`Broadcast failed to ${nodeId}:`, error);
                    results.failed++;
                });

            promises.push(promise);
        }

        await Promise.allSettled(promises);

        console.log(`Broadcast complete: ${results.sent} sent, ${results.failed} failed`);
        return results;
    }

    async disconnectFromNode(nodeId: string): Promise<void> {
        const connection = this.connections.get(nodeId);
        if (!connection) {
            return;
        }

        try {
            console.log(`Disconnecting from node: ${nodeId}`);

            connection.state = ConnectionState.DISCONNECTING;

            if (connection.session) {
                await this.closeSession(connection);
            }

            await this.disconnectFromDevice(connection.id);

            this.statistics.activeConnections--;
            if (connection.session) {
                this.statistics.authenticatedConnections--;
            }

            this.connections.delete(nodeId);
            this.sessions.delete(nodeId);

            console.log(`Disconnected from node: ${nodeId}`);

            this.emitConnectionEvent({
                type: 'disconnected',
                nodeId,
                connectionId: connection.id,
                timestamp: Date.now()
            });

        } catch (error) {
            console.error(`Error disconnecting from ${nodeId}:`, error);
            this.connections.delete(nodeId);
            this.sessions.delete(nodeId);
        }
    }

    // Helper methods
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
                console.warn(`Connection attempt ${i + 1} failed:`, error);

                if (i < this.config.maxRetries - 1) {
                    await this.delay(1000 * (i + 1));
                }
            }
        }

        throw lastError || new Error('Connection failed');
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
        console.log(`Message queued for ${nodeId} (${queue.length} in queue)`);
    }

    private async processMessageQueue(nodeId: string): Promise<void> {
        const queue = this.messageQueues.get(nodeId);
        if (!queue || queue.length === 0) {
            return;
        }

        console.log(`Processing ${queue.length} queued messages for ${nodeId}`);

        const messages = [...queue];
        this.messageQueues.delete(nodeId);

        for (const message of messages) {
            try {
                await this.sendMessage(nodeId, message);
            } catch (error) {
                console.error(`Failed to send queued message:`, error);
            }
        }
    }

    private async closeSession(connection: SecureConnection): Promise<void> {
        if (!connection.session) return;
        console.log(`Closing session for ${connection.nodeId}`);
    }

    private checkConnectionRateLimit(nodeId: string): boolean {
        const now = Date.now();
        const lastAttempt = this.lastConnectionAttempt.get(nodeId) || 0;
        const attempts = this.connectionAttempts.get(nodeId) || 0;

        if (now - lastAttempt > 60000) {
            this.connectionAttempts.set(nodeId, 0);
        }

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

            this.statistics.averageThroughput =
                (this.statistics.averageThroughput * 0.9) + (connection.throughput * 0.1);
        }
    }

    private updateLatency(connection: SecureConnection, latency: number): void {
        connection.latency = (connection.latency * 0.7) + (latency * 0.3);

        this.statistics.averageLatency =
            (this.statistics.averageLatency * 0.9) + (connection.latency * 0.1);
    }

    private handleConnectionFailure(connection: SecureConnection, error: any): void {
        console.error(`Connection failed for ${connection.nodeId}:`, error);

        connection.state = ConnectionState.FAILED;

        this.emitConnectionEvent({
            type: 'error',
            nodeId: connection.nodeId,
            connectionId: connection.id,
            error: this.createBLEError(BLEErrorCode.CONNECTION_LOST, error),
            timestamp: Date.now()
        });
    }

    private isConnectionError(error: any): boolean {
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

    // Timer management
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
                connection.lastHeartbeat = Date.now();
            }
        }
    }

    private checkTimeouts(): void {
        const now = Date.now();

        for (const [nodeId, connection] of this.connections) {
            const timeSinceActivity = now - connection.lastActivity;

            if (timeSinceActivity > this.config.connectionTimeout) {
                console.log(`Connection timeout for ${nodeId}`);
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
                    console.warn(`Acknowledgment timeout for message ${messageId}`);
                    connection.pendingAcks.delete(messageId);
                    connection.packetLoss = Math.min(1, connection.packetLoss + 0.1);
                }
            }
        }
    }

    private cleanupFragments(): void {
        for (const [nodeId, connection] of this.connections) {
            for (const [fragmentId, fragments] of connection.fragments) {
                connection.fragments.delete(fragmentId);
                console.warn(`Fragment timeout for ${fragmentId}`);
            }
        }
    }

    private emitConnectionEvent(event: BLEConnectionEvent): void {
        for (const callback of this.connectionCallbacks) {
            try {
                callback(event);
            } catch (error) {
                console.error('Error in connection callback:', error);
            }
        }
    }

    private notifySessionCallbacks(nodeId: string, session: BLESession): void {
        for (const callback of this.sessionCallbacks) {
            try {
                callback(nodeId, session);
            } catch (error) {
                console.error('Error in session callback:', error);
            }
        }
    }

    // Public API
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
        console.log('Cleaning up all connections...');

        if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
        if (this.timeoutTimer) clearInterval(this.timeoutTimer);
        if (this.ackTimer) clearInterval(this.ackTimer);
        if (this.fragmentTimer) clearInterval(this.fragmentTimer);

        const promises: Promise<void>[] = [];
        for (const nodeId of this.connections.keys()) {
            promises.push(this.disconnectFromNode(nodeId));
        }

        await Promise.allSettled(promises);

        this.connections.clear();
        this.sessions.clear();
        this.pendingAuthentications.clear();
        this.messageQueues.clear();
        this.connectionCallbacks.clear();
        this.messageCallbacks.clear();
        this.sessionCallbacks.clear();

        console.log('Connection cleanup complete');
    }
}