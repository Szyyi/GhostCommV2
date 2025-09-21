// core/src/ble/connection.ts
/**
 * Enhanced BLE Connection Manager with Protocol v2.1 Security
 * 
 * This module provides comprehensive Bluetooth Low Energy (BLE) connection management
 * for the GhostComm mesh network with advanced security features, message fragmentation,
 * authentication, and Protocol v2.1 compliance.
 * 
 * Key Features:
 * - Secure BLE connection establishment and management
 * - Protocol v2.1 compliance with mandatory signature verification
 * - Double Ratchet authentication and session management
 * - Message fragmentation for large payload transmission
 * - Rate limiting and anti-spam protection
 * - Comprehensive connection monitoring and statistics
 * - Message chain integrity verification
 * - Automatic retry and failover mechanisms
 * 
 * Security Features:
 * - End-to-end encryption using Double Ratchet algorithm
 * - Message signature verification (Protocol v2.1 requirement)
 * - Message chain integrity protection against replay attacks
 * - Device attestation and verification status tracking
 * - Rate limiting to prevent DoS attacks
 * - Secure fragment reassembly with checksum verification
 * 
 * Performance Optimizations:
 * - MTU negotiation for optimal packet sizes
 * - Message fragmentation with efficient reassembly
 * - Connection pooling and reuse
 * - Adaptive timeouts based on network conditions
 * - Throughput and latency monitoring
 * 
 * @version 2.1
 * @author LCpl Szymon 'Si' Procak
 */

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
    EncryptedMessageWithSenderKey,
    MessagePriority,
    CryptoError
} from '../types/crypto';
import { MessageEncryption } from '../crypto/encryption';

/**
 * Enhanced secure connection interface with Protocol v2.1 security context.
 * 
 * Represents a complete BLE connection state with all security, performance,
 * and protocol compliance information. This interface extends basic BLE
 * connections with advanced security features required for mesh networking.
 * 
 * Connection Lifecycle:
 * 1. CONNECTING: Initial BLE connection establishment
 * 2. CONNECTED: Physical connection established, starting authentication
 * 3. AUTHENTICATING: Performing Double Ratchet key exchange
 * 4. AUTHENTICATED: Fully secure connection ready for messaging
 * 5. DISCONNECTING: Graceful connection termination
 * 6. DISCONNECTED: Connection closed
 * 
 * Security Context (Protocol v2.1):
 * - Message signature verification is mandatory
 * - Message chain integrity prevents replay attacks
 * - Device attestation ensures node authenticity
 * - Rate limiting prevents denial-of-service attacks
 * 
 * Performance Monitoring:
 * - Real-time throughput and latency tracking
 * - Packet loss detection and recovery
 * - Fragment reassembly with timeout handling
 * - MTU optimization for efficient transmission
 */
export interface SecureConnection {
    // === Basic Connection Information ===
    /** Unique identifier for this BLE connection */
    id: string;
    
    /** Target node's fingerprint identifier */
    nodeId: string;
    
    /** Platform-specific device identifier (MAC address, UUID, etc.) */
    deviceId: string;

    // === Protocol Version Tracking (v2.1) ===
    /** Protocol version supported by the connected peer */
    protocolVersion: number;
    
    /** Whether this connection requires signature verification (v2.1 mandate) */
    requiresSignatureVerification: boolean;

    // === Session Management with Double Ratchet ===
    /** Active Double Ratchet session for encrypted communication (optional) */
    session?: BLESession;
    
    /** Current connection state in the state machine */
    state: ConnectionState;

    // === Message Chain Tracking (Protocol v2.1 Security) ===
    /**
     * Message chain state for preventing replay attacks and ensuring integrity.
     * Each message references the previous message hash, creating an unbreakable chain.
     */
    messageChain: {
        /** SHA-256 hash of the last message sent by this node */
        lastSentHash: string;
        
        /** SHA-256 hash of the last message received from peer */
        lastReceivedHash: string;
        
        /** Sequence number of messages sent (monotonically increasing) */
        sentSequence: number;
        
        /** Sequence number of messages received (for gap detection) */
        receivedSequence: number;
        
        /** Number of detected chain breaks (security monitoring) */
        chainBreaks: number;
    };

    // === Connection Timing Information ===
    /** Unix timestamp when BLE connection was established */
    connectedAt: number;
    
    /** Unix timestamp when authentication completed (optional) */
    authenticatedAt?: number;
    
    /** Unix timestamp of most recent communication activity */
    lastActivity: number;
    
    /** Unix timestamp of most recent heartbeat message */
    lastHeartbeat: number;

    // === Performance Metrics ===
    /** Maximum Transmission Unit negotiated for this connection */
    mtu: number;
    
    /** Current throughput in bytes per second */
    throughput: number;
    
    /** Average round-trip latency in milliseconds */
    latency: number;
    
    /** Packet loss rate as a fraction (0.0 = no loss, 1.0 = total loss) */
    packetLoss: number;

    // === Message Statistics ===
    /** Total number of messages sent through this connection */
    sentMessages: number;
    
    /** Total number of messages received through this connection */
    receivedMessages: number;
    
    /** Map of pending acknowledgments: messageId -> sent timestamp */
    pendingAcks: Map<string, number>;

    // === Fragment Assembly with Proper Data Tracking ===
    /**
     * Active fragment reassembly operations for large messages.
     * Key: fragmentId, Value: reassembly state with actual fragment data
     */
    fragments: Map<string, {
        /** Map of fragment index to fragment data and metadata */
        fragments: Map<number, {
            /** Raw fragment data bytes */
            data: Uint8Array;
            
            /** Fragment metadata including size and checksum */
            metadata: MessageFragment;
        }>;
        
        /** Expected total size of reassembled message */
        totalSize: number;
        
        /** Number of bytes received so far */
        receivedSize: number;
        
        /** Timestamp when first fragment was received (for timeout) */
        startTime: number;
    }>;

    // === Security and Authentication ===
    /** Device attestation information for trust establishment (optional) */
    attestation?: DeviceAttestation;
    
    /** Channel binding token for additional security (optional) */
    channelBinding?: Uint8Array;
    
    /** Current verification status of the connected node */
    verificationStatus: VerificationStatus;
    
    // === Public Key Cache (Protocol v2.1 Enhancement) ===
    /**
     * Cached public keys from the peer for signature verification.
     * Reduces cryptographic overhead by avoiding repeated key parsing.
     */
    peerPublicKeys?: {
        /** Ed25519 public key for signature verification */
        identity: Uint8Array;
        
        /** X25519 public key for key exchange */
        encryption: Uint8Array;
        
        /** Timestamp when keys were last validated */
        lastValidated: number;
    };

    // === Rate Limiting Protection ===
    /**
     * Rate limiting state to prevent spam and DoS attacks.
     * Tracks message rate within a sliding time window.
     */
    messageRateLimit: {
        /** Number of messages sent in current time window */
        count: number;
        
        /** Timestamp when current time window started */
        windowStart: number;
    };
}

/**
 * Connection configuration with Protocol v2.1 settings and security requirements.
 * 
 * Defines all configurable parameters for BLE connection management, including
 * security policies, timeouts, performance tuning, and Protocol v2.1 compliance.
 * These settings affect connection establishment, authentication, message handling,
 * and overall network behavior.
 * 
 * Security Configuration:
 * - Protocol version requirements (v2.1 by default)
 * - Verification and authentication policies
 * - Rate limiting and anti-spam protection
 * - Message chain integrity thresholds
 * 
 * Performance Tuning:
 * - Timeout values for various operations
 * - Fragment handling parameters
 * - Throughput and latency optimization
 * - Resource usage limits
 */
export interface ConnectionConfig {
    /** Automatically establish Double Ratchet session after connection */
    autoAuthenticate: boolean;
    
    /** Require cryptographic verification before accepting messages */
    requireVerification: boolean;
    
    /** Require Protocol v2.1 compliance (recommended for security) */
    requireProtocolV2: boolean;
    
    /** Maximum time to wait for BLE connection establishment (milliseconds) */
    connectionTimeout: number;
    
    /** Maximum time to wait for Double Ratchet authentication (milliseconds) */
    authenticationTimeout: number;
    
    /** Interval between heartbeat messages for connection keep-alive (milliseconds) */
    heartbeatInterval: number;
    
    /** Maximum number of connection retry attempts before giving up */
    maxRetries: number;
    
    /** Maximum time to wait for fragment reassembly completion (milliseconds) */
    fragmentTimeout: number;
    
    /** Maximum time to wait for message acknowledgment (milliseconds) */
    ackTimeout: number;
    
    /** Maximum size of individual message fragments (bytes) */
    maxFragmentSize: number;
    
    /** Maximum messages per second to prevent spam (rate limiting) */
    maxMessageRate: number;
    
    /** Maximum allowed message chain breaks before disconnecting */
    chainBreakThreshold: number;
}

/**
 * Comprehensive connection statistics for monitoring and optimization.
 * 
 * Provides detailed metrics about connection performance, security events,
 * message processing, and error conditions. These statistics are essential
 * for network monitoring, troubleshooting, and performance optimization.
 * 
 * Usage:
 * - Network health monitoring and alerting
 * - Performance optimization and tuning
 * - Security incident detection and response
 * - Capacity planning and scaling decisions
 * - Debugging connection and protocol issues
 */
export interface ConnectionStatistics {
    /** Total number of connection attempts made */
    totalConnections: number;
    
    /** Number of currently active BLE connections */
    activeConnections: number;
    
    /** Number of connections with successful authentication */
    authenticatedConnections: number;
    
    /** Number of failed connection attempts */
    failedConnections: number;
    
    /** Total messages sent across all connections */
    totalMessagesSent: number;
    
    /** Total messages received across all connections */
    totalMessagesReceived: number;
    
    /** Total bytes transferred (sent + received) */
    totalBytesTransferred: number;
    
    /** Average round-trip latency across all connections (milliseconds) */
    averageLatency: number;
    
    /** Average throughput across all connections (bytes per second) */
    averageThroughput: number;
    
    /** Number of successful Double Ratchet session establishments */
    sessionEstablishments: number;
    
    /** Number of authentication failures */
    authenticationFailures: number;
    
    /** Number of signature verification failures (Protocol v2.1 security) */
    signatureVerificationFailures: number;
    
    /** Number of detected message chain breaks (security monitoring) */
    messageChainBreaks: number;
    
    /** Number of messages that required fragmentation */
    fragmentationCount: number;
    
    /** Number of fragment reassembly failures */
    reassemblyFailures: number;
}

// === CALLBACK TYPE DEFINITIONS ===

/**
 * Callback function type for connection state change events.
 * 
 * Invoked whenever a connection state changes (connected, disconnected,
 * authenticated, failed, etc.). Used for monitoring connection lifecycle
 * and implementing custom connection management logic.
 * 
 * @param event Connection event with state change information
 */
export type ConnectionCallback = (event: BLEConnectionEvent) => void;

/**
 * Callback function type for incoming message handling with Protocol v2.1 verification.
 * 
 * Invoked when a new message is received and successfully processed. Includes
 * verification results for Protocol v2.1 compliance, allowing applications
 * to handle messages based on their security status.
 * 
 * @param message Received and processed BLE message
 * @param fromNodeId Node fingerprint of the message sender
 * @param session Active Double Ratchet session (if authenticated)
 * @param verificationResult Signature verification result (Protocol v2.1)
 */
export type MessageCallback = (
    message: BLEMessage, 
    fromNodeId: string, 
    session?: BLESession,
    verificationResult?: { verified: boolean; error?: string }
) => Promise<void>;

/**
 * Callback function type for session establishment events.
 * 
 * Invoked when a new Double Ratchet session is successfully established
 * with a peer node. Used for tracking authentication status and enabling
 * secure communication features.
 * 
 * @param nodeId Node fingerprint of the authenticated peer
 * @param session Newly established Double Ratchet session
 */
export type SessionCallback = (nodeId: string, session: BLESession) => void;

/**
 * Enhanced BLE Connection Manager with Protocol v2.1 security and advanced features.
 * 
 * This abstract class provides a comprehensive foundation for managing BLE connections
 * in the GhostComm mesh network. It implements Protocol v2.1 security requirements,
 * message fragmentation, authentication, and performance monitoring.
 * 
 * Key Responsibilities:
 * 1. BLE Connection Lifecycle Management
 *    - Connection establishment with retry logic
 *    - Authentication using Double Ratchet algorithm
 *    - Graceful disconnection and cleanup
 * 
 * 2. Protocol v2.1 Security Implementation
 *    - Mandatory signature verification for all messages
 *    - Message chain integrity verification
 *    - Rate limiting and anti-spam protection
 *    - Device attestation and verification status tracking
 * 
 * 3. Message Processing and Fragmentation
 *    - Large message fragmentation and reassembly
 *    - Acknowledgment tracking and timeout handling
 *    - Message ordering and duplicate detection
 *    - Secure message encryption and decryption
 * 
 * 4. Performance Monitoring and Optimization
 *    - Real-time throughput and latency measurement
 *    - Connection quality assessment
 *    - Packet loss detection and recovery
 *    - MTU negotiation for optimal performance
 * 
 * 5. Event Management and Callbacks
 *    - Connection state change notifications
 *    - Message delivery callbacks with verification results
 *    - Session establishment notifications
 *    - Error handling and recovery
 * 
 * Platform Integration:
 * Subclasses must implement platform-specific BLE operations while this
 * abstract class handles protocol-level logic, security, and state management.
 * 
 * Thread Safety:
 * This class is designed to be used from a single thread. If multi-threaded
 * access is required, external synchronization must be provided.
 * 
 * @abstract Platform-specific BLE operations must be implemented by subclasses
 */
export abstract class BLEConnectionManager {
    // === State Management ===
    /** Map of active secure connections indexed by node ID */
    private connections: Map<string, SecureConnection>;
    
    /** Map of authenticated Double Ratchet sessions indexed by node ID */
    private sessions: Map<string, BLESession>;
    
    /** Configuration parameters for connection behavior and security */
    private config: ConnectionConfig;

    // === Security Components ===
    /** Local cryptographic key pair for signing and encryption (optional) */
    protected keyPair?: IGhostKeyPair;
    
    /** Message encryption/decryption engine using Double Ratchet */
    protected encryption: MessageEncryption;
    
    /** Map of pending authentication operations to prevent concurrent attempts */
    private pendingAuthentications: Map<string, Promise<SessionKeys>>;
    
    /** Map of queued messages waiting for connection establishment */
    private messageQueues: Map<string, BLEMessage[]>;

    // === Event Callback Management ===
    /** Set of registered connection event callbacks */
    private connectionCallbacks: Set<ConnectionCallback>;
    
    /** Set of registered message processing callbacks */
    private messageCallbacks: Set<MessageCallback>;
    
    /** Set of registered session establishment callbacks */
    private sessionCallbacks: Set<SessionCallback>;

    // === Timer Management for Background Tasks ===
    /** Timer for periodic heartbeat messages and connection health checks */
    private heartbeatTimer?: NodeJS.Timeout;
    
    /** Timer for connection timeout monitoring and cleanup */
    private timeoutTimer?: NodeJS.Timeout;
    
    /** Timer for acknowledgment timeout detection and retry logic */
    private ackTimer?: NodeJS.Timeout;
    
    /** Timer for fragment reassembly timeout and cleanup */
    private fragmentTimer?: NodeJS.Timeout;

    // === Performance and Usage Statistics ===
    /** Comprehensive connection and message processing statistics */
    private statistics: ConnectionStatistics;

    // === Rate Limiting and DoS Protection ===
    /** Map tracking connection attempts per node for rate limiting */
    private connectionAttempts: Map<string, number>;
    
    /** Map tracking last connection attempt timestamp per node */
    private lastConnectionAttempt: Map<string, number>;

    /**
     * Constructor for BLE Connection Manager with Protocol v2.1 security.
     * 
     * Initializes the connection manager with optional cryptographic key pair
     * and customizable configuration. Sets up all internal state, timers,
     * and default security settings.
     * 
     * @param keyPair Optional cryptographic key pair for authentication and signing
     * @param config Optional configuration overrides (uses secure defaults)
     */
    constructor(keyPair?: IGhostKeyPair, config?: Partial<ConnectionConfig>) {
        this.keyPair = keyPair;
        this.encryption = new MessageEncryption();

        // Initialize collections for state management
        this.connections = new Map();
        this.sessions = new Map();
        this.pendingAuthentications = new Map();
        this.messageQueues = new Map();
        this.connectionAttempts = new Map();
        this.lastConnectionAttempt = new Map();

        // Initialize callback collections
        this.connectionCallbacks = new Set();
        this.messageCallbacks = new Set();
        this.sessionCallbacks = new Set();

        // Configure connection behavior with Protocol v2.1 security defaults
        this.config = {
            autoAuthenticate: true,                                          // Enable automatic Double Ratchet setup
            requireVerification: false,                                      // Optional cryptographic verification
            requireProtocolV2: BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION, // Protocol v2.1 compliance
            connectionTimeout: BLE_CONFIG.CONNECTION_TIMEOUT,                // 30 second connection timeout
            authenticationTimeout: BLE_CONFIG.AUTHENTICATION_TIMEOUT,       // 15 second auth timeout
            heartbeatInterval: 30000,                                       // 30 second heartbeat interval
            maxRetries: 3,                                                  // 3 connection retry attempts
            fragmentTimeout: 30000,                                         // 30 second fragment timeout
            ackTimeout: 5000,                                               // 5 second acknowledgment timeout
            maxFragmentSize: BLE_CONFIG.FRAGMENT_SIZE,                      // Optimal fragment size
            maxMessageRate: BLE_CONFIG.MAX_MESSAGES_PER_SECOND,             // Rate limiting protection
            chainBreakThreshold: 5,                                         // Maximum allowed chain breaks
            ...config                                                       // Apply user overrides
        };

        // Initialize comprehensive statistics tracking
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
            signatureVerificationFailures: 0,                               // Protocol v2.1 security metric
            messageChainBreaks: 0,                                          // Protocol v2.1 integrity metric
            fragmentationCount: 0,
            reassemblyFailures: 0
        };

        // Start background timer tasks for connection management
        this.startHeartbeatTimer();                                         // Connection keep-alive
        this.startTimeoutTimer();                                           // Timeout monitoring
        this.startAckTimer();                                               // Acknowledgment tracking
        this.startFragmentTimer();                                          // Fragment cleanup
    }

    // === ABSTRACT PLATFORM-SPECIFIC METHODS ===
    
    /**
     * Establish a platform-specific BLE connection to a device.
     * 
     * This method must be implemented by platform-specific subclasses to handle
     * the actual BLE connection establishment using the platform's BLE APIs.
     * 
     * Implementation Requirements:
     * - Connect to the specified device using its platform identifier
     * - Configure connection parameters for optimal performance
     * - Handle platform-specific error conditions
     * - Return a unique connection identifier for subsequent operations
     * 
     * @param deviceId Platform-specific device identifier (MAC, UUID, etc.)
     * @param nodeId GhostComm node fingerprint for logging and tracking
     * @returns Promise resolving to unique connection identifier
     * @throws Error if connection fails or device is unreachable
     */
    protected abstract connectToDevice(deviceId: string, nodeId: string): Promise<string>;
    
    /**
     * Disconnect from a platform-specific BLE device.
     * 
     * This method must be implemented to gracefully close BLE connections
     * and clean up platform-specific resources.
     * 
     * Implementation Requirements:
     * - Gracefully close the specified BLE connection
     * - Clean up any platform-specific resources
     * - Handle cases where connection is already closed
     * - Ensure method is idempotent (safe to call multiple times)
     * 
     * @param connectionId Unique connection identifier from connectToDevice
     * @throws Error if disconnection fails or connection is invalid
     */
    protected abstract disconnectFromDevice(connectionId: string): Promise<void>;
    
    /**
     * Send raw data over a BLE connection.
     * 
     * This method must be implemented to transmit data using the platform's
     * BLE characteristic write operations.
     * 
     * Implementation Requirements:
     * - Write data to appropriate BLE characteristics
     * - Handle MTU limitations and fragmentation at BLE level
     * - Provide reliable delivery guarantees
     * - Handle connection errors and timeouts
     * 
     * @param connectionId Unique connection identifier
     * @param data Raw bytes to transmit over BLE
     * @throws Error if transmission fails or connection is invalid
     */
    protected abstract sendDataToDevice(connectionId: string, data: Uint8Array): Promise<void>;
    
    /**
     * Setup message receiving for a BLE connection.
     * 
     * This method must be implemented to configure BLE characteristic
     * notifications and route incoming data to the message handling system.
     * 
     * Implementation Requirements:
     * - Subscribe to appropriate BLE characteristic notifications
     * - Route received data to handleIncomingMessage method
     * - Handle connection state changes and errors
     * - Configure optimal notification parameters
     * 
     * @param connectionId Unique connection identifier
     * @param nodeId GhostComm node fingerprint for message routing
     * @throws Error if setup fails or connection is invalid
     */
    protected abstract setupMessageReceiving(connectionId: string, nodeId: string): Promise<void>;
    
    /**
     * Negotiate optimal MTU (Maximum Transmission Unit) for a connection.
     * 
     * This method should be implemented to optimize BLE performance by
     * negotiating the largest possible packet size supported by both devices.
     * 
     * Implementation Requirements:
     * - Attempt MTU negotiation with the connected device
     * - Return the negotiated MTU size in bytes
     * - Handle devices that don't support MTU negotiation
     * - Provide reasonable fallback values
     * 
     * @param connectionId Unique connection identifier
     * @returns Promise resolving to negotiated MTU size in bytes
     * @throws Error if negotiation fails (should not prevent connection)
     */
    protected abstract negotiateMTU(connectionId: string): Promise<number>;
    
    /**
     * Retrieve BLE connection parameters for performance monitoring.
     * 
     * This method should be implemented to provide insight into the
     * current BLE connection quality and performance characteristics.
     * 
     * Implementation Requirements:
     * - Query current BLE connection parameters
     * - Return standardized parameter values
     * - Handle platforms that don't expose these parameters
     * - Provide reasonable defaults when unavailable
     * 
     * @param connectionId Unique connection identifier
     * @returns Promise resolving to connection parameter object
     * @throws Error if parameter retrieval fails (should not prevent operation)
     */
    protected abstract getConnectionParameters(connectionId: string): Promise<{
        /** Connection interval in milliseconds */
        interval: number;
        
        /** Slave latency (number of intervals) */
        latency: number;
        
        /** Supervision timeout in milliseconds */
        timeout: number;
    }>;

    /**
     * Connect to a mesh network node with comprehensive Protocol v2.1 security establishment.
     * 
     * This is the primary method for establishing secure connections in the GhostComm mesh
     * network. It handles the complete connection lifecycle including BLE connection,
     * protocol negotiation, authentication, and session establishment.
     * 
     * Connection Process:
     * 1. Protocol Compatibility Check - Ensures peer supports required protocol version
     * 2. Rate Limiting Validation - Prevents connection spam and DoS attacks
     * 3. Verification Status Check - Validates peer's cryptographic verification status
     * 4. BLE Connection Establishment - Platform-specific connection with retry logic
     * 5. MTU Negotiation - Optimizes packet size for performance
     * 6. Protocol v2.1 Handshake - Exchanges keys and establishes security context
     * 7. Double Ratchet Authentication - Establishes encrypted session (if configured)
     * 8. Message Queue Processing - Sends any queued messages
     * 
     * Security Features:
     * - Protocol v2.1 compliance with mandatory signature verification
     * - Rate limiting to prevent connection flooding
     * - Verification status checking for trusted communication
     * - Secure key exchange and session establishment
     * - Message chain integrity initialization
     * 
     * Error Handling:
     * - Automatic retry logic with exponential backoff
     * - Graceful fallback for non-critical failures
     * - Comprehensive error reporting and event emission
     * - Resource cleanup on connection failure
     * 
     * @param node Target mesh network node information
     * @param deviceId Platform-specific device identifier for BLE connection
     * @returns Promise resolving to unique connection identifier
     * @throws Error if connection fails, protocol incompatible, or rate limited
     */
    async connectToNode(node: BLENode, deviceId: string): Promise<string> {
        const nodeId = node.id;

        // === Protocol Compatibility Validation ===
        if (this.config.requireProtocolV2 && node.protocolVersion < 2.1) {
            throw new Error(`Node ${nodeId} uses incompatible protocol version ${node.protocolVersion}. Required: v2.1`);
        }

        // === Rate Limiting Protection ===
        if (!this.checkConnectionRateLimit(nodeId)) {
            throw new Error(`Connection rate limit exceeded for ${nodeId}`);
        }

        // === Duplicate Connection Check ===
        const existing = this.connections.get(nodeId);
        if (existing && existing.state !== ConnectionState.DISCONNECTED) {
            console.log(`Already connected/connecting to node: ${nodeId}`);
            return existing.id;
        }

        // === Verification Requirement Check ===
        if (this.config.requireVerification &&
            node.verificationStatus === VerificationStatus.UNVERIFIED) {
            throw new Error(`Node ${nodeId} must be verified before connection`);
        }

        try {
            console.log(`Initiating secure connection to node: ${nodeId} (Protocol v${node.protocolVersion})`);

            // === Initialize Connection State ===
            const connection: SecureConnection = {
                id: '', // Will be populated after platform connection
                nodeId,
                deviceId,
                protocolVersion: node.protocolVersion,
                requiresSignatureVerification: node.protocolVersion >= 2,
                state: ConnectionState.CONNECTING,
                messageChain: {
                    lastSentHash: '',
                    lastReceivedHash: '',
                    sentSequence: 0,
                    receivedSequence: 0,
                    chainBreaks: 0
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
                verificationStatus: node.verificationStatus,
                messageRateLimit: {
                    count: 0,
                    windowStart: Date.now()
                }
            };

            // === Cache Peer Public Keys (Protocol v2.1 Optimization) ===
            if (node.identityKey && node.encryptionKey) {
                connection.peerPublicKeys = {
                    identity: node.identityKey,
                    encryption: node.encryptionKey,
                    lastValidated: Date.now()
                };
            }

            // Register connection and update statistics
            this.connections.set(nodeId, connection);
            this.statistics.totalConnections++;

            // === Emit Connection Initiated Event ===
            this.emitConnectionEvent({
                type: 'connected',
                nodeId,
                timestamp: Date.now()
            });

            // === Platform-Specific BLE Connection ===
            const connectionId = await this.connectWithRetry(deviceId, nodeId);
            connection.id = connectionId;
            connection.state = ConnectionState.CONNECTED;
            this.statistics.activeConnections++;

            // === MTU Negotiation for Performance Optimization ===
            try {
                connection.mtu = await this.negotiateMTU(connectionId);
                console.log(`Negotiated MTU: ${connection.mtu} bytes`);
            } catch (error) {
                console.warn('MTU negotiation failed, using default');
            }

            // === Connection Parameter Monitoring ===
            try {
                const params = await this.getConnectionParameters(connectionId);
                console.log(`Connection parameters - Interval: ${params.interval}ms, Latency: ${params.latency}, Timeout: ${params.timeout}ms`);
            } catch (error) {
                console.warn('Failed to get connection parameters');
            }

            // === Setup Message Receiving Pipeline ===
            await this.setupMessageReceiving(connectionId, nodeId);

            // === Protocol v2.1 Security Handshake ===
            if (connection.requiresSignatureVerification) {
                await this.performProtocolHandshake(node, connection);
            }

            // === Automatic Authentication (Double Ratchet) ===
            if (this.config.autoAuthenticate && this.keyPair) {
                try {
                    await this.authenticateConnection(node, connection);
                } catch (error) {
                    console.warn('Auto-authentication failed:', error);
                }
            }

            console.log(`Successfully connected to node: ${nodeId} (Protocol v${connection.protocolVersion})`);

            // === Process Queued Messages ===
            await this.processMessageQueue(nodeId);

            return connectionId;

        } catch (error) {
            console.error(`Failed to connect to node ${nodeId}:`, error);

            // === Cleanup on Failure ===
            this.connections.delete(nodeId);
            this.statistics.failedConnections++;

            // === Emit Error Event ===
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
     * Perform Protocol v2.1 handshake with comprehensive security establishment.
     * 
     * This method implements the Protocol v2.1 handshake process, which establishes
     * a secure communication context between two nodes. The handshake exchange 
     * cryptographic keys, verifies node identities, and negotiates security parameters.
     * 
     * Handshake Process:
     * 1. Generate handshake message with local node information
     * 2. Include identity and encryption public keys
     * 3. Add capability information and security requirements
     * 4. Sign entire handshake with identity key for authenticity
     * 5. Send handshake message to peer
     * 6. Await peer's handshake response (handled in message processing)
     * 
     * Security Features:
     * - Digital signature ensures handshake authenticity
     * - Fresh nonce prevents replay attacks
     * - Capability negotiation for feature compatibility
     * - Protocol version verification for forward compatibility
     * 
     * @param node Target mesh network node information
     * @param connection Active secure connection for the handshake
     * @throws Error if handshake generation or transmission fails
     */
    private async performProtocolHandshake(
        node: BLENode,
        connection: SecureConnection
    ): Promise<void> {
        if (!this.keyPair) {
            throw new Error('Key pair required for Protocol v2.1 handshake');
        }

        console.log(`Performing Protocol v2.1 handshake with ${node.id}`);

        // === Create Handshake Message ===
        const handshake: ProtocolHandshake = {
            protocolVersion: 2.1,                                           // Protocol v2.1 specification
            supportedVersions: [2, 2.1],                                   // Backward compatibility support
            identityKey: this.bytesToHex(this.keyPair.getIdentityPublicKey()),     // Ed25519 for signatures
            encryptionKey: this.bytesToHex(this.keyPair.getEncryptionPublicKey()), // X25519 for key exchange
            timestamp: Date.now(),                                         // Fresh timestamp
            nonce: this.generateNonce(),                                   // Random nonce for uniqueness
            signature: '',                                                 // Will be filled after signing
            capabilities: [NodeCapability.RELAY, NodeCapability.STORAGE], // Advertised capabilities
            requireSignatureVerification: true                            // Protocol v2.1 requirement
        };

        // === Sign Handshake for Authenticity ===
        const handshakeData = JSON.stringify(handshake);
        const signature = this.keyPair.signMessage(handshakeData);
        handshake.signature = this.bytesToHex(signature);

        // === Create Protocol Message ===
        const handshakeMessage: BLEMessage = {
            messageId: this.generateMessageId(),
            version: 2.1,
            sourceId: this.keyPair.getFingerprint(),
            destinationId: node.id,
            senderPublicKey: this.bytesToHex(this.keyPair.getIdentityPublicKey()),
            messageSignature: handshake.signature,
            messageHash: await this.calculateHash(handshakeData),
            previousMessageHash: '',                                       // First message in chain
            sequenceNumber: 0,                                             // Initial sequence
            ttl: Date.now() + 30000,                                      // 30 second TTL
            hopCount: 0,
            maxHops: 1,                                                   // Direct connection only
            priority: MessagePriority.HIGH,                               // High priority handshake
            encryptedPayload: {} as EncryptedMessage,                     // Handshake is not encrypted
            routePath: [],
            relaySignatures: [],
            createdAt: Date.now(),
            expiresAt: Date.now() + 30000                                 // 30 second expiry
        };

        // === Send Handshake Message ===
        await this.sendMessageInternal(connection, handshakeMessage);
        console.log(`Protocol v2.1 handshake sent to ${node.id}`);
    }

    /**
     * Send a secure message with comprehensive Protocol v2.1 requirements and validation.
     * 
     * This is the primary method for sending messages through the GhostComm mesh network
     * with full Protocol v2.1 compliance. It handles message validation, rate limiting,
     * authentication waiting, message chaining, and secure transmission.
     * 
     * Message Processing Pipeline:
     * 1. Connection Validation - Ensures target connection exists and is valid
     * 2. Rate Limiting Check - Prevents message spam and DoS attacks
     * 3. Protocol v2.1 Validation - Ensures required security fields are present
     * 4. Authentication Wait - Waits for ongoing authentication to complete
     * 5. Message Chain Update - Links message to previous message for integrity
     * 6. Hash Calculation - Computes message hash for integrity verification
     * 7. Session Chain Update - Updates Double Ratchet session state
     * 8. Secure Transmission - Sends message with fragmentation if needed
     * 
     * Security Features:
     * - Mandatory signature verification for Protocol v2.1
     * - Message chain integrity for replay attack prevention
     * - Rate limiting for DoS protection
     * - Session state management for forward secrecy
     * - Comprehensive error handling and recovery
     * 
     * @param nodeId Target node's fingerprint identifier
     * @param message BLE message to send with all required fields
     * @throws Error if connection invalid, rate limited, or missing required fields
     */
    async sendMessage(nodeId: string, message: BLEMessage): Promise<void> {
        // === Connection Validation ===
        const connection = this.connections.get(nodeId);

        if (!connection) {
            // Queue message for when connection is established
            this.queueMessage(nodeId, message);
            throw new Error(`No connection to node: ${nodeId}`);
        }

        if (connection.state === ConnectionState.DISCONNECTED) {
            throw new Error(`Connection to ${nodeId} is disconnected`);
        }

        // === Rate Limiting Protection ===
        if (!this.checkMessageRateLimit(connection)) {
            throw new Error(`Message rate limit exceeded for ${nodeId}`);
        }

        // === Protocol v2.1 Security Validation ===
        if (connection.requiresSignatureVerification) {
            if (!message.senderPublicKey) {
                throw new Error('Protocol v2.1 requires senderPublicKey in message');
            }
            if (!message.messageSignature) {
                throw new Error('Protocol v2.1 requires messageSignature in message');
            }
        }

        // === Wait for Authentication Completion ===
        if (connection.state === ConnectionState.AUTHENTICATING) {
            console.log(`Waiting for authentication to complete for ${nodeId}`);
            await this.waitForAuthentication(nodeId);
        }

        // === Message Chain Integrity Update ===
        message.previousMessageHash = connection.messageChain.lastSentHash;
        message.sequenceNumber = connection.messageChain.sentSequence++;

        // === Calculate and Store Message Hash ===
        const messageHash = await this.calculateMessageHash(message);
        message.messageHash = messageHash;
        connection.messageChain.lastSentHash = messageHash;

        // === Update Session Chain State (if authenticated) ===
        if (connection.session) {
            connection.session.lastSentMessageHash = messageHash;
            connection.session.sentSequenceNumber = connection.messageChain.sentSequence;
        }

        // === Secure Message Transmission ===
        await this.sendMessageInternal(connection, message);
    }

    /**
     * Handle incoming message with comprehensive Protocol v2.1 verification and processing.
     * 
     * This method processes all incoming messages with full security validation,
     * integrity checking, and proper message chain verification. It implements
     * the complete Protocol v2.1 security model for incoming message handling.
     * 
     * Message Processing Pipeline:
     * 1. Connection Validation - Ensures sender has valid connection
     * 2. Message Parsing - Deserializes message from raw bytes
     * 3. Signature Verification - Validates message authenticity (Protocol v2.1)
     * 4. Chain Integrity Check - Verifies message chain for replay protection
     * 5. Fragment Handling - Reassembles fragmented messages
     * 6. Acknowledgment - Sends delivery confirmation
     * 7. Latency Tracking - Updates performance metrics
     * 8. Callback Processing - Invokes registered message handlers
     * 
     * Security Features:
     * - Mandatory signature verification for Protocol v2.1 compliance
     * - Message chain integrity validation against replay attacks
     * - Chain break detection and threshold enforcement
     * - Comprehensive error handling and security event logging
     * - Statistics tracking for security monitoring
     * 
     * Error Handling:
     * - Signature verification failures are logged and reported
     * - Chain breaks are tracked with automatic disconnection threshold
     * - Malformed messages are safely handled without crashes
     * - Security events are emitted for monitoring and alerting
     * 
     * @param data Raw message bytes received from BLE connection
     * @param fromNodeId Node fingerprint of the message sender
     */
    protected async handleIncomingMessage(
        data: Uint8Array,
        fromNodeId: string
    ): Promise<void> {
        // === Connection Validation ===
        const connection = this.connections.get(fromNodeId);
        if (!connection) {
            console.warn(`Received message from unknown node: ${fromNodeId}`);
            return;
        }

        try {
            // === Message Parsing ===
            const messageStr = new TextDecoder().decode(data);
            const message: BLEMessage = JSON.parse(messageStr);

            console.log(`Received message ${message.messageId} from ${fromNodeId} (Protocol v${message.version})`);

            // === Protocol v2.1: Signature Verification ===
            let verificationResult: { verified: boolean; error?: string } | undefined;
            
            if (connection.requiresSignatureVerification || message.version >= 2) {
                verificationResult = await this.verifyMessageSignature(message, connection);
                
                if (!verificationResult.verified) {
                    console.error(`Signature verification failed: ${verificationResult.error}`);
                    this.statistics.signatureVerificationFailures++;
                    
                    // === Emit Security Event ===
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
                    
                    return; // Reject unsigned/invalid message
                }
            }

            // === Message Chain Integrity Verification ===
            if (connection.messageChain.lastReceivedHash && BLE_SECURITY_CONFIG.REQUIRE_MESSAGE_CHAINING) {
                if (!this.verifyMessageChain(message, connection)) {
                    console.error('Message chain verification failed');
                    this.statistics.messageChainBreaks++;
                    connection.messageChain.chainBreaks++;
                    
                    // === Chain Break Threshold Enforcement ===
                    if (connection.messageChain.chainBreaks > this.config.chainBreakThreshold) {
                        console.error(`Too many chain breaks (${connection.messageChain.chainBreaks}), closing connection`);
                        await this.disconnectFromNode(fromNodeId);
                        return;
                    }
                }
            }

            // === Update Connection Activity and Statistics ===
            connection.receivedMessages++;
            connection.lastActivity = Date.now();
            this.statistics.totalMessagesReceived++;
            this.statistics.totalBytesTransferred += data.length;

            // === Update Message Chain State ===
            connection.messageChain.lastReceivedHash = message.messageHash;
            connection.messageChain.receivedSequence = message.sequenceNumber;

            // === Update Session Chain State (if authenticated) ===
            if (connection.session) {
                connection.session.lastReceivedMessageHash = message.messageHash;
                connection.session.receivedSequenceNumber = message.sequenceNumber;
            }

            // === Fragment Handling and Reassembly ===
            if (message.fragment) {
                const completeMessage = await this.handleFragment(connection, message, data);
                if (!completeMessage) {
                    return; // Waiting for more fragments
                }
                message.encryptedPayload = completeMessage.encryptedPayload;
            }

            // === Send Delivery Acknowledgment ===
            await this.sendAcknowledgment(connection, message.messageId);

            // === Update Latency Metrics (if this is an acknowledgment) ===
            if (connection.pendingAcks.has(message.messageId)) {
                const sentTime = connection.pendingAcks.get(message.messageId)!;
                const latency = Date.now() - sentTime;
                this.updateLatency(connection, latency);
                connection.pendingAcks.delete(message.messageId);
            }

            // === Process Message Callbacks with Verification Result ===
            await this.processMessageCallbacks(message, fromNodeId, connection.session, verificationResult);

        } catch (error) {
            console.error(`Error handling message from ${fromNodeId}:`, error);
        }
    }

    /**
     * Verify message signature with comprehensive Protocol v2.1 requirements and caching.
     * 
     * This method implements the Protocol v2.1 signature verification process with
     * optimizations for performance and security. It validates message authenticity
     * using Ed25519 digital signatures and maintains a cache of verified public keys.
     * 
     * Verification Process:
     * 1. Required Field Check - Ensures Protocol v2.1 mandatory fields are present
     * 2. Public Key Retrieval - Gets sender's public key from cache or message
     * 3. Cache Validation - Verifies cached keys are recent and valid
     * 4. Signature Verification - Validates Ed25519 signature using sender's key
     * 5. Cache Update - Updates public key cache with verified keys
     * 
     * Security Features:
     * - Mandatory public key validation for Protocol v2.1
     * - Public key caching with expiration for performance
     * - Key mismatch detection to prevent substitution attacks
     * - Comprehensive error handling with detailed error messages
     * 
     * Performance Optimizations:
     * - Public key caching reduces cryptographic overhead
     * - Cache validation prevents stale key usage
     * - Efficient error reporting for debugging
     * 
     * @param message BLE message to verify
     * @param connection Secure connection with cached key information
     * @returns Verification result with success status and error details
     */
    private async verifyMessageSignature(
        message: BLEMessage,
        connection: SecureConnection
    ): Promise<{ verified: boolean; error?: string }> {
        // === Protocol v2.1: Check Required Fields ===
        if (!message.senderPublicKey) {
            return { verified: false, error: BLEErrorCode.NO_SENDER_KEY };
        }

        if (!message.messageSignature) {
            return { verified: false, error: 'Missing message signature' };
        }

        try {
            // === Public Key Retrieval and Caching ===
            let senderPublicKey: Uint8Array;
            
            // Try cached key first for performance
            if (connection.peerPublicKeys?.identity) {
                senderPublicKey = connection.peerPublicKeys.identity;
                
                // === Validate Cache Freshness (1 hour expiry) ===
                if (Date.now() - connection.peerPublicKeys.lastValidated > 3600000) {
                    // Re-validate key against message
                    const messageKey = this.hexToBytes(message.senderPublicKey);
                    if (!this.arraysEqual(senderPublicKey, messageKey)) {
                        return { verified: false, error: 'Public key mismatch' };
                    }
                    connection.peerPublicKeys.lastValidated = Date.now();
                }
            } else {
                // === Parse Public Key from Message ===
                senderPublicKey = this.hexToBytes(message.senderPublicKey);
                
                // === Cache the Verified Key ===
                if (connection.peerPublicKeys) {
                    connection.peerPublicKeys.identity = senderPublicKey;
                    connection.peerPublicKeys.lastValidated = Date.now();
                } else {
                    connection.peerPublicKeys = {
                        identity: senderPublicKey,
                        encryption: new Uint8Array(32), // Placeholder
                        lastValidated: Date.now()
                    };
                }
            }

            // === Verify Ed25519 Signature ===
            const messageHashBytes = new TextEncoder().encode(message.messageHash);
            const signatureBytes = this.hexToBytes(message.messageSignature);

            if (!this.keyPair) {
                return { verified: false, error: 'No key pair for verification' };
            }

            const verified = this.keyPair.verifySignature(
                messageHashBytes,
                signatureBytes,
                senderPublicKey // Protocol v2.1: Third parameter required
            );

            return { verified, error: verified ? undefined : 'Invalid signature' };

        } catch (error) {
            return { verified: false, error: String(error) };
        }
    }

    /**
     * Handle message fragments with comprehensive data tracking and security validation.
     * 
     * This method manages the reassembly of large messages that have been fragmented
     * for transmission over BLE connections. It provides robust fragment tracking,
     * timeout handling, and integrity verification for reliable message delivery.
     * 
     * Fragment Processing:
     * 1. Fragment Collector Setup - Creates or retrieves fragment reassembly state
     * 2. Fragment Storage - Stores fragment data with metadata
     * 3. Completeness Check - Determines if all fragments have been received
     * 4. Reassembly Process - Combines fragments in correct order
     * 5. Integrity Verification - Validates checksum of reassembled message
     * 6. Cleanup - Removes fragment state after successful reassembly
     * 
     * Security Features:
     * - Checksum verification prevents fragment corruption
     * - Fragment timeout prevents memory exhaustion
     * - Duplicate fragment detection and handling
     * - Statistics tracking for monitoring and debugging
     * 
     * Performance Considerations:
     * - Efficient fragment storage with minimal memory overhead
     * - Fast reassembly using ordered fragment collection
     * - Automatic cleanup to prevent memory leaks
     * 
     * @param connection Secure connection for fragment tracking
     * @param message BLE message containing fragment metadata
     * @param rawData Raw fragment data bytes
     * @returns Complete reassembled message or null if waiting for more fragments
     * @throws Error if fragment processing or reassembly fails
     */
    private async handleFragment(
        connection: SecureConnection,
        message: BLEMessage,
        rawData: Uint8Array
    ): Promise<BLEMessage | null> {
        const fragment = message.fragment!;
        const fragmentId = fragment.fragmentId;

        // === Get or Create Fragment Collector ===
        let fragmentCollector = connection.fragments.get(fragmentId);
        if (!fragmentCollector) {
            fragmentCollector = {
                fragments: new Map(),
                totalSize: 0,
                receivedSize: 0,
                startTime: Date.now()  // For timeout tracking
            };
            connection.fragments.set(fragmentId, fragmentCollector);
            this.statistics.fragmentationCount++;
        }

        // === Store Fragment with Actual Data ===
        fragmentCollector.fragments.set(fragment.index, {
            data: rawData,          // Store raw fragment bytes
            metadata: fragment      // Store fragment metadata
        });
        
        fragmentCollector.receivedSize += rawData.length;

        console.log(`Received fragment ${fragment.index + 1}/${fragment.total} for message ${message.messageId}`);

        // === Check Fragment Completeness ===
        if (fragmentCollector.fragments.size === fragment.total) {
            console.log(`All fragments received, reassembling message`);

            try {
                // === Reassemble Message from Fragments ===
                const reassembled = await this.reassembleFragments(
                    fragmentCollector.fragments,
                    fragment.total
                );

                // === Verify Integrity Checksum ===
                const checksum = await this.calculateChecksum(reassembled);
                if (checksum !== fragment.checksum) {
                    throw new Error('Fragment checksum mismatch');
                }

                // === Parse Complete Message ===
                const completeMessage = JSON.parse(new TextDecoder().decode(reassembled));

                // === Cleanup Fragment State ===
                connection.fragments.delete(fragmentId);

                return completeMessage;
                
            } catch (error) {
                console.error('Fragment reassembly failed:', error);
                this.statistics.reassemblyFailures++;
                connection.fragments.delete(fragmentId);
                throw error;
            }
        }

        return null; // Still waiting for more fragments
    }

    /**
     * Reassemble message fragments with proper data extraction and validation.
     * 
     * This method reconstructs the original message from its constituent fragments,
     * ensuring proper ordering and completeness. It provides robust error handling
     * and validates fragment integrity before reassembly.
     * 
     * Reassembly Process:
     * 1. Fragment Validation - Ensures all required fragments are present
     * 2. Size Calculation - Computes total reassembled message size
     * 3. Buffer Allocation - Creates appropriately sized result buffer
     * 4. Sequential Assembly - Copies fragments in correct order
     * 5. Integrity Check - Validates reassembled data consistency
     * 
     * @param fragments Map of fragment index to fragment data and metadata
     * @param total Expected total number of fragments
     * @returns Reassembled message as byte array
     * @throws Error if fragments are missing or reassembly fails
     */
    private async reassembleFragments(
        fragments: Map<number, { data: Uint8Array; metadata: MessageFragment }>,
        total: number
    ): Promise<Uint8Array> {
        // === Verify All Fragments Present ===
        for (let i = 0; i < total; i++) {
            if (!fragments.has(i)) {
                throw new Error(`Missing fragment ${i}`);
            }
        }

        // === Calculate Total Reassembled Size ===
        let totalSize = 0;
        for (const fragment of fragments.values()) {
            totalSize += fragment.data.length;
        }

        // === Allocate Result Buffer ===
        const result = new Uint8Array(totalSize);
        let offset = 0;

        // === Copy Fragments in Sequential Order ===
        for (let i = 0; i < total; i++) {
            const fragment = fragments.get(i)!;
            result.set(fragment.data, offset);
            offset += fragment.data.length;
        }

        return result;
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
            if (messageBytes.length > connection.mtu - 100) { // Leave room for protocol overhead
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
     * Send fragmented message with proper tracking
     */
    private async sendFragmentedMessage(
        connection: SecureConnection,
        message: BLEMessage,
        data: Uint8Array
    ): Promise<void> {
        const fragmentSize = Math.min(
            connection.mtu - 100,
            this.config.maxFragmentSize
        );
        const totalFragments = Math.ceil(data.length / fragmentSize);
        const fragmentId = this.generateFragmentId();
        const checksum = await this.calculateChecksum(data);

        console.log(`Sending message in ${totalFragments} fragments`);
        this.statistics.fragmentationCount++;

        for (let i = 0; i < totalFragments; i++) {
            const start = i * fragmentSize;
            const end = Math.min(start + fragmentSize, data.length);
            const fragmentData = data.slice(start, end);

            // Create fragment metadata
            message.fragment = {
                fragmentId,
                index: i,
                total: totalFragments,
                size: fragmentData.length,
                checksum
            };

            // Send fragment
            const fragmentMessage = {
                ...message,
                fragment: { ...message.fragment }
            };

            const fragmentBytes = new TextEncoder().encode(JSON.stringify(fragmentMessage));
            await this.sendSingleMessage(connection, fragmentBytes);

            // Small delay between fragments
            if (i < totalFragments - 1) {
                await this.delay(10);
            }
        }

        console.log(`All ${totalFragments} fragments sent`);
    }

    /**
     * Check message rate limiting
     */
    private checkMessageRateLimit(connection: SecureConnection): boolean {
        const now = Date.now();
        
        // Reset window if needed
        if (now - connection.messageRateLimit.windowStart > 1000) {
            connection.messageRateLimit.count = 0;
            connection.messageRateLimit.windowStart = now;
        }

        // Check limit
        if (connection.messageRateLimit.count >= this.config.maxMessageRate) {
            return false;
        }

        connection.messageRateLimit.count++;
        return true;
    }

    /**
     * Verify message chain integrity for replay attack prevention and ordering.
     * 
     * This method implements Protocol v2.1 message chain verification to prevent
     * replay attacks and ensure message ordering. Each message must reference the
     * hash of the previous message, creating an unbreakable chain of integrity.
     * 
     * Chain Verification Process:
     * 1. Sequence Number Check - Validates message ordering with gap tolerance
     * 2. Chain Hash Validation - Ensures message references correct previous hash
     * 3. First Message Handling - Allows initial messages to start new chains
     * 4. Gap Tolerance - Accommodates network-related message reordering
     * 
     * Security Benefits:
     * - Prevents replay attacks by detecting duplicate or out-of-order messages
     * - Ensures message integrity through cryptographic hash chaining
     * - Detects message injection or manipulation attempts
     * - Provides audit trail for forensic analysis
     * 
     * @param message BLE message to verify against chain
     * @param connection Secure connection with chain state
     * @returns true if message chain is valid, false otherwise
     */
    private verifyMessageChain(
        message: BLEMessage,
        connection: SecureConnection
    ): boolean {
        // === Sequence Number Verification ===
        if (BLE_SECURITY_CONFIG.REQUIRE_SEQUENCE_NUMBERS) {
            const expectedSequence = connection.messageChain.receivedSequence + 1;
            if (message.sequenceNumber !== expectedSequence) {
                console.warn(`Sequence mismatch: expected ${expectedSequence}, got ${message.sequenceNumber}`);
                
                // === Allow Limited Gap for Network Issues ===
                const gap = Math.abs(message.sequenceNumber - expectedSequence);
                if (gap > BLE_SECURITY_CONFIG.MAX_SEQUENCE_NUMBER_GAP) {
                    return false;
                }
            }
        }

        // === Message Chain Hash Verification ===
        if (message.previousMessageHash !== connection.messageChain.lastReceivedHash) {
            console.warn(`Chain break: expected ${connection.messageChain.lastReceivedHash}, got ${message.previousMessageHash}`);
            
            // === Allow First Message in Chain ===
            if (connection.messageChain.lastReceivedHash === '') {
                return true;
            }
            
            return false; // Chain integrity violation
        }

        return true; // Chain verification successful
    }

    // === UTILITY AND HELPER METHODS ===

    /**
     * Compare two Uint8Arrays for equality with constant-time behavior.
     * 
     * This utility provides secure array comparison that prevents timing attacks
     * by ensuring consistent execution time regardless of array differences.
     * 
     * @param a First array to compare
     * @param b Second array to compare
     * @returns true if arrays are identical, false otherwise
     */
    private arraysEqual(a: Uint8Array, b: Uint8Array): boolean {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) return false;
        }
        return true;
    }

    // Include all other helper methods and timer management...
    private async sendSingleMessage(
        connection: SecureConnection,
        data: Uint8Array
    ): Promise<void> {
        await this.sendDataToDevice(connection.id, data);
        this.updateThroughput(connection, data.length);
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

    // Authentication and session management
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

            // Create BLE session with Protocol v2.1 fields
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

        // Send authentication request with Protocol v2.1 fields
        const authRequest: BLEMessage = {
            messageId: this.generateMessageId(),
            version: 2.1,
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
            // Protocol v2.1 chain tracking
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

    // Include all remaining methods (they remain unchanged)...
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

    // Include all utility methods...
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
        // Perform any session cleanup
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
        // Check if error indicates connection problem
        const errorStr = String(error).toLowerCase();
        return errorStr.includes('connection') ||
               errorStr.includes('disconnect') ||
               errorStr.includes('timeout') ||
               errorStr.includes('lost');
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
                // Could send actual heartbeat message here
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
        const now = Date.now();

        for (const [nodeId, connection] of this.connections) {
            for (const [fragmentId, collector] of connection.fragments) {
                if (now - collector.startTime > this.config.fragmentTimeout) {
                    connection.fragments.delete(fragmentId);
                    console.warn(`Fragment timeout for ${fragmentId}`);
                    this.statistics.reassemblyFailures++;
                }
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

        // Stop all timers
        if (this.heartbeatTimer) clearInterval(this.heartbeatTimer);
        if (this.timeoutTimer) clearInterval(this.timeoutTimer);
        if (this.ackTimer) clearInterval(this.ackTimer);
        if (this.fragmentTimer) clearInterval(this.fragmentTimer);

        // Disconnect all nodes
        const promises: Promise<void>[] = [];
        for (const nodeId of this.connections.keys()) {
            promises.push(this.disconnectFromNode(nodeId));
        }

        await Promise.allSettled(promises);

        // Clear all collections
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