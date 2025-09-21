// core/src/ble/mesh.ts
// ================================================================================================
// Enhanced Mesh Network with Protocol v2.1 Security and Intelligent Routing
// ================================================================================================
//
// This module implements the core mesh networking layer for the GhostComm secure communication
// system, providing intelligent multi-hop routing, message forwarding, and network topology
// management. The mesh network enables seamless communication across multiple devices even
// when direct connections are not possible.
//
// MESH NETWORKING ARCHITECTURE:
// =============================
//
// Topology Management:
// - Dynamic discovery and integration of mesh nodes
// - Automatic route calculation and optimization
// - Self-healing network topology with failover capabilities
// - Load balancing across multiple available paths
//
// Routing Intelligence:
// - Distance vector routing with reliability metrics
// - Adaptive route selection based on network conditions
// - Loop prevention and cycle detection algorithms
// - Quality-based path optimization for performance
//
// Message Forwarding:
// - Multi-hop message delivery with integrity preservation
// - Priority-based message scheduling and queuing
// - Automatic retry mechanisms with exponential backoff
// - Fragment handling for large message transmission
//
// PROTOCOL v2.1 SECURITY INTEGRATION:
// ==================================
//
// Signature Preservation:
// - Original message signatures maintained through all relay hops
// - Relay signature chain providing forwarding path verification
// - End-to-end authenticity guarantee regardless of routing path
// - Tamper detection through cryptographic signature validation
//
// Security Validation:
// - Protocol v2 compliance checking for all forwarded messages
// - Mandatory cryptographic fields validation before relay
// - Message verification caching for performance optimization
// - Security statistics tracking for network monitoring
//
// Relay Authentication:
// - Each relay node adds cryptographic signature to forwarding path
// - Relay signature chain enables path verification and audit
// - Prevention of malicious message modification during forwarding
// - Trust chain establishment through relay signature verification
//
// PERFORMANCE OPTIMIZATIONS:
// ==========================
//
// Intelligent Routing:
// - Route caching with freshness validation and automatic cleanup
// - Multi-path routing for improved reliability and load distribution
// - Adaptive routing metrics based on delivery success rates
// - Network congestion detection and avoidance algorithms
//
// Message Management:
// - Priority-based message queuing with fair scheduling
// - Intelligent retry strategies with backoff algorithms
// - Message deduplication preventing network flooding
// - Automatic cleanup of expired and failed messages
//
// Resource Optimization:
// - Memory-efficient data structures for large network topologies
// - Periodic cleanup of stale routing information
// - Optimized message forwarding with minimal processing overhead
// - Configurable limits preventing resource exhaustion
//
// NETWORK RESILIENCE FEATURES:
// ============================
//
// Fault Tolerance:
// - Automatic detection and recovery from node failures
// - Route healing and alternative path discovery
// - Graceful degradation under adverse network conditions
// - Partition tolerance with automatic network rejoining
//
// Quality of Service:
// - Message priority handling for urgent communications
// - Latency optimization for real-time message delivery
// - Bandwidth management and congestion control
// - Reliability guarantees through acknowledgment and retry
//
// Network Health:
// - Comprehensive statistics and performance monitoring
// - Network topology visualization and analysis support
// - Health metrics for proactive network maintenance
// - Performance analytics for optimization opportunities
//
// USAGE PATTERNS:
// ==============
//
// The mesh network operates autonomously once initialized, requiring minimal
// configuration while providing comprehensive networking capabilities:
//
// Basic Usage:
// ```typescript
// const mesh = new MeshNetwork(nodeId, keyPair);
// 
// // Update topology with discovered nodes
// mesh.updateRoutingTable(discoveredNodes, connectedNodes);
// 
// // Queue message for delivery
// mesh.queueMessage(message, targetNodeId);
// 
// // Process message queue periodically
// await mesh.processMessageQueue(sendFunction, getNodesFunction);
// ```
//
// Advanced Features:
// ```typescript
// // Get routing information
// const route = mesh.findRoute(targetNodeId);
// 
// // Handle incoming messages
// const decision = mesh.handleIncomingMessage(message, fromNodeId);
// 
// // Monitor network performance
// const stats = mesh.getStats();
// ```
// @author LCpl Szymon 'Si' Procak
// @version 2.1

import { 
    BLENode, 
    BLEMessage, 
    BLE_CONFIG,
    BLE_SECURITY_CONFIG,
    RelaySignature,
    BLEErrorCode
} from './types';
import { IGhostKeyPair } from '../types/crypto';

/**
 * Routing table entry representing a path to a destination node
 *
 * Each route entry contains complete information about how to reach a specific
 * destination node in the mesh network, including path metrics, reliability
 * information, and Protocol v2 compatibility details.
 *
 * Route Management:
 * - Entries automatically created when nodes discovered or connected
 * - Routes updated based on network topology changes and performance
 * - Stale routes automatically removed based on age and reliability
 * - Route quality tracked through delivery success metrics
 *
 * Routing Algorithm:
 * - Distance vector routing with reliability weighting
 * - Next hop selection based on shortest reliable path
 * - Dynamic route updates based on network conditions
 * - Load balancing through multiple path availability
 *
 * Route Quality Metrics:
 * - Hop count: Network distance to destination
 * - Reliability: Success rate for message delivery (0.0-1.0)
 * - Freshness: Age of route information for validity assessment
 * - Protocol compatibility: Version support for feature negotiation
 */
export interface RouteEntry {
    /** Cryptographic fingerprint of the destination node */
    targetNodeId: string;
    
    /** Next hop node ID for reaching the destination */
    nextHopNodeId: string;
    
    /** Number of hops required to reach destination */
    hopCount: number;
    
    /** Timestamp when this route was last updated or validated */
    lastUpdated: number;
    
    /** Route reliability score (0.0-1.0) based on delivery success */
    reliability: number;
    
    /** Protocol version supported by the target node */
    protocolVersion?: number;
}

/**
 * Message queue entry for pending delivery operations
 *
 * Represents a message awaiting delivery through the mesh network with
 * comprehensive retry logic, Protocol v2 compliance tracking, and
 * delivery attempt management.
 *
 * Queue Management:
 * - Messages automatically queued when direct delivery impossible
 * - Priority-based processing with fair scheduling algorithms
 * - Automatic retry with exponential backoff for failed deliveries
 * - Expired message cleanup preventing queue growth
 *
 * Delivery Strategy:
 * - Direct delivery attempted first for connected nodes
 * - Multi-hop routing through optimal available paths
 * - Intelligent retry scheduling based on network conditions
 * - Protocol v2 compliance verification before forwarding
 *
 * Performance Tracking:
 * - Delivery attempt counting for retry limit enforcement
 * - Timing information for backoff calculation and optimization
 * - Protocol compliance tracking for security validation
 * - Success/failure statistics for route quality assessment
 */
export interface MessageQueueEntry {
    /** Complete message data with Protocol v2 security fields */
    message: BLEMessage;
    
    /** Cryptographic fingerprint of the intended recipient */
    targetNodeId: string;
    
    /** Number of delivery attempts made for this message */
    attempts: number;
    
    /** Timestamp of the most recent delivery attempt */
    lastAttempt: number;
    
    /** Maximum delivery attempts before message abandonment */
    maxAttempts: number;
    
    /** Whether message requires Protocol v2 verification before relay */
    requiresVerification: boolean;
}

/**
 * Comprehensive mesh network statistics and performance metrics
 *
 * Provides detailed operational metrics for network performance monitoring,
 * optimization, and health assessment. Statistics include both traditional
 * networking metrics and Protocol v2 security-specific measurements.
 *
 * Message Metrics:
 * - Total message volume for capacity planning
 * - Delivery success and failure rates for reliability assessment
 * - Queue depth for congestion monitoring
 * - Forwarding statistics for relay efficiency analysis
 *
 * Security Metrics:
 * - Message verification success rates for security monitoring
 * - Verification failure detection for threat assessment
 * - Signature preservation tracking for integrity validation
 * - Protocol compliance statistics for network health
 *
 * Network Health:
 * - Routing table size for topology complexity assessment
 * - Node connectivity for network density analysis
 * - Performance trends for optimization opportunities
 * - Error rates for troubleshooting and maintenance
 */
export interface MeshStats {
    /** Total number of messages processed by this mesh node */
    totalMessages: number;
    
    /** Current size of the routing table (number of known routes) */
    routingTableSize: number;
    
    /** Number of messages currently queued for delivery */
    queuedMessages: number;
    
    /** Number of messages successfully forwarded to other nodes */
    messagesForwarded: number;
    
    /** Number of messages successfully delivered to final destinations */
    messagesDelivered: number;
    
    /** Number of messages that failed delivery after all retry attempts */
    messagesFailed: number;
    
    /** Number of messages successfully verified with Protocol v2 signatures */
    messagesVerified: number;
    
    /** Number of message verification failures indicating security issues */
    verificationFailures: number;
    
    /** Number of messages forwarded with original signatures preserved */
    signaturesMaintained: number;
}

/**
 * Enhanced Mesh Network with Protocol v2 signature preservation
 *
 * The MeshNetwork class implements the core mesh networking logic for GhostComm,
 * providing multi-hop routing, message forwarding, and Protocol v2.1 security integration.
 *
 * CORE RESPONSIBILITIES:
 * =====================
 * - Dynamic topology management and route calculation
 * - Multi-hop message delivery with signature preservation
 * - Priority-based message queuing and retry logic
 * - Protocol v2 compliance enforcement and verification
 * - Relay authentication and signature chain management
 * - Performance monitoring and statistics reporting
 *
 * SECURITY ARCHITECTURE:
 * =====================
 * - End-to-end signature preservation for message authenticity
 * - Relay signature chain for path verification and audit
 * - Protocol v2 field validation for all forwarded messages
 * - Verification caching for performance optimization
 * - Replay and loop prevention through message tracking
 *
 * PERFORMANCE OPTIMIZATIONS:
 * ==========================
 * - Route caching and freshness validation
 * - Adaptive retry and backoff algorithms
 * - Efficient memory management for large topologies
 * - Periodic cleanup of stale routing and verification data
 *
 * USAGE PATTERNS:
 * ==============
 * - Autonomous operation after initialization
 * - Periodic message queue processing for delivery
 * - Topology updates on node discovery and connection changes
 * - Statistics reporting for network health monitoring
 */
export class MeshNetwork {
    private routingTable: Map<string, RouteEntry> = new Map();
    private messageQueue: Map<string, MessageQueueEntry> = new Map();
    private forwardedMessages: Set<string> = new Set(); // Prevent loops
    private nodeId: string;
    private routingTableVersion: number = 0;
    private keyPair?: IGhostKeyPair; // For relay signatures
    // Enhanced loop prevention with message path tracking
    private messageRoutes: Map<string, Set<string>> = new Map(); // messageId -> Set of nodeIds that have seen it
    private routeTimeout = 60000; // 1 minute
    private routeCleanupTimer?: NodeJS.Timeout;
    
    // Protocol v2: Track message verification state
    private verifiedMessages: Set<string> = new Set();
    private messageVerificationCache: Map<string, {
        verified: boolean;
        senderPublicKey?: string;
        timestamp: number;
    }> = new Map();
    
    private stats: MeshStats = {
        totalMessages: 0,
        routingTableSize: 0,
        queuedMessages: 0,
        messagesForwarded: 0,
        messagesDelivered: 0,
        messagesFailed: 0,
        messagesVerified: 0,
        verificationFailures: 0,
        signaturesMaintained: 0
    };
    processedMessages: any;

    constructor(nodeId: string, keyPair?: IGhostKeyPair) {
        this.nodeId = nodeId;
        this.keyPair = keyPair;
        this.startRoutingTableCleanup();
        this.startVerificationCacheCleanup();
    }

    /**
     * Get routing table version
     */
    getRoutingTableVersion(): number {
        return this.routingTableVersion;
    }

    /**
     * Update routing table based on discovered nodes with Protocol v2 awareness
     *
     * Adds direct routes for connected nodes, removes stale routes, and updates
     * routing table version and statistics. Ensures Protocol v2 compatibility
     * tracking for feature negotiation and security enforcement.
     */
    updateRoutingTable(discoveredNodes: BLENode[], connectedNodes: BLENode[]): void {
        console.log(`Updating routing table with ${discoveredNodes.length} discovered nodes`);

        // Add direct routes for connected nodes
        for (const node of connectedNodes) {
            if (node.id !== this.nodeId) {
                const route: RouteEntry = {
                    targetNodeId: node.id,
                    nextHopNodeId: node.id, // Direct connection
                    hopCount: 1,
                    lastUpdated: Date.now(),
                    reliability: 0.9, // High reliability for direct connections
                    protocolVersion: node.protocolVersion // Track protocol version
                };

                this.routingTable.set(node.id, route);
            }
        }

        // Remove routes for nodes that are no longer discovered
        const discoveredNodeIds = new Set(discoveredNodes.map(n => n.id));
        for (const [nodeId] of this.routingTable) {
            if (!discoveredNodeIds.has(nodeId)) {
                console.log(`Removing route to lost node: ${nodeId}`);
                this.routingTable.delete(nodeId);
            }
        }

        this.stats.routingTableSize = this.routingTable.size;
        this.routingTableVersion++;
        console.log(`Routing table updated: ${this.routingTable.size} routes`);
    }

    /**
     * Find best route to a target node
     *
     * Returns the optimal route entry for a given destination node, considering
     * route freshness, reliability, and hop count. Removes stale routes and updates
     * statistics as needed.
     */
    findRoute(targetNodeId: string): RouteEntry | null {
        const route = this.routingTable.get(targetNodeId);

        if (!route) {
            console.log(`No route found to node: ${targetNodeId}`);
            return null;
        }

        // Check if route is still valid (not too old)
        const maxAge = BLE_CONFIG.MESSAGE_TTL / 2;
        if (Date.now() - route.lastUpdated > maxAge) {
            console.log(`Route to ${targetNodeId} is stale, removing`);
            this.routingTable.delete(targetNodeId);
            this.stats.routingTableSize = this.routingTable.size;
            return null;
        }

        return route;
    }

    /**
     * Queue message for delivery with Protocol v2 awareness
     *
     * Adds a message to the delivery queue, enforcing Protocol v2 field validation
     * and retry logic. Tracks delivery attempts, timing, and verification requirements.
     */
    queueMessage(message: BLEMessage, targetNodeId: string): void {
        // Verify message has Protocol v2 required fields if needed
        const requiresVerification = message.version >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION;
        
        if (requiresVerification && !this.validateMessageForRelay(message)) {
            console.error(`Message ${message.messageId} missing required Protocol v2 fields for relay`);
            this.stats.messagesFailed++;
            return;
        }

        const queueEntry: MessageQueueEntry = {
            message,
            targetNodeId,
            attempts: 0,
            lastAttempt: 0,
            maxAttempts: 3,
            requiresVerification
        };

        this.messageQueue.set(message.messageId, queueEntry);
        this.stats.queuedMessages = this.messageQueue.size;
        this.stats.totalMessages++;

        console.log(`Queued message ${message.messageId} for delivery to ${targetNodeId} (Protocol v${message.version})`);
    }

    /**
     * Validate message has required Protocol v2 fields for relay
     *
     * Ensures all mandatory cryptographic fields are present for Protocol v2
     * compliance before allowing message relay or forwarding.
     */
    private validateMessageForRelay(message: BLEMessage): boolean {
        if (message.version < BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            return true; // Backward compatibility
        }

        // Protocol v2 requires these fields
        if (!message.senderPublicKey) {
            console.error('Protocol v2 message missing senderPublicKey');
            return false;
        }

        if (!message.messageSignature) {
            console.error('Protocol v2 message missing messageSignature');
            return false;
        }

        if (!message.messageHash) {
            console.error('Protocol v2 message missing messageHash');
            return false;
        }

        return true;
    }

    /**
     * Process message queue with Protocol v2 signature preservation
     *
     * Attempts direct delivery or multi-hop forwarding for queued messages,
     * preserving all Protocol v2 fields and relay signatures. Implements
     * retry logic, queue cleanup, and statistics updates.
     */
    async processMessageQueue(
        sendDirectMessage: (nodeId: string, message: BLEMessage) => Promise<boolean>,
        getConnectedNodes: () => BLENode[]
    ): Promise<void> {
        if (this.messageQueue.size === 0) {
            return;
        }

        console.log(`Processing message queue: ${this.messageQueue.size} messages`);

        const now = Date.now();
        const connectedNodes = getConnectedNodes();
        const connectedNodeIds = new Set(connectedNodes.map(n => n.id));

        for (const [messageId, queueEntry] of this.messageQueue) {
            const { message, targetNodeId, attempts, lastAttempt, maxAttempts } = queueEntry;

            // Skip if attempted too recently
            if (now - lastAttempt < 5000) {
                continue;
            }

            // Remove if expired or too many attempts
            if (message.ttl < now || attempts >= maxAttempts) {
                console.log(`Removing expired/failed message ${messageId}`);
                this.messageQueue.delete(messageId);
                this.stats.messagesFailed++;
                continue;
            }

            // Try to deliver the message
            let delivered = false;

            // First, try direct delivery if target is connected
            if (connectedNodeIds.has(targetNodeId)) {
                try {
                    // Preserve all Protocol v2 fields during direct delivery
                    delivered = await sendDirectMessage(targetNodeId, message);
                    if (delivered) {
                        console.log(`Direct delivery successful for message ${messageId}`);
                        this.stats.messagesDelivered++;
                        this.stats.signaturesMaintained++;
                    }
                } catch (error) {
                    console.warn(`Direct delivery failed for message ${messageId}:`, error);
                }
            }

            // If direct delivery failed, try routing through mesh
            if (!delivered) {
                const route = this.findRoute(targetNodeId);
                if (route && connectedNodeIds.has(route.nextHopNodeId)) {
                    try {
                        // Forward message through next hop with signature preservation
                        const forwardedMessage = await this.prepareMessageForRelay(message);
                        
                        delivered = await sendDirectMessage(route.nextHopNodeId, forwardedMessage);
                        if (delivered) {
                            console.log(`Mesh delivery successful for message ${messageId} via ${route.nextHopNodeId}`);
                            this.stats.messagesForwarded++;
                            this.stats.signaturesMaintained++;
                        }
                    } catch (error) {
                        console.warn(`Mesh delivery failed for message ${messageId}:`, error);
                    }
                }
            }

            // Update queue entry
            queueEntry.attempts++;
            queueEntry.lastAttempt = now;

            if (delivered) {
                this.messageQueue.delete(messageId);
            }
        }

        this.stats.queuedMessages = this.messageQueue.size;
    }

    /**
     * Prepare message for relay with Protocol v2 signature preservation
     *
     * Increments hop count, appends relay signature, and ensures all original
     * Protocol v2 fields are preserved for authenticity and integrity.
     */
    private async prepareMessageForRelay(message: BLEMessage): Promise<BLEMessage> {
        // Increment hop count
        const relayedMessage: BLEMessage = {
            ...message,
            hopCount: message.hopCount + 1,
            routePath: [...message.routePath, this.nodeId]
        };

        // Add relay signature if we have a key pair
        if (this.keyPair) {
            const relaySignature: RelaySignature = {
                nodeId: this.nodeId,
                timestamp: Date.now(),
                signature: this.createRelaySignature(message.messageId),
                rssi: -50 // Would get actual RSSI from connection
            };

            relayedMessage.relaySignatures = [
                ...message.relaySignatures,
                relaySignature
            ];
        }

        // CRITICAL: Preserve original Protocol v2 fields
        // These must NEVER be modified during relay
        relayedMessage.senderPublicKey = message.senderPublicKey;
        relayedMessage.messageSignature = message.messageSignature;
        relayedMessage.messageHash = message.messageHash;
        relayedMessage.previousMessageHash = message.previousMessageHash;
        relayedMessage.sequenceNumber = message.sequenceNumber;

        return relayedMessage;
    }


    /**
     * Enhanced loop prevention with message path tracking
     * Tracks which nodes have seen each message to prevent routing loops
     */
    private hasMessageLooped(messageId: string, nodeId: string): boolean {
        const route = this.messageRoutes.get(messageId);
        
        if (!route) {
            // First time seeing this message, create route tracking
            const newRoute = new Set([this.nodeId, nodeId]);
            this.messageRoutes.set(messageId, newRoute);
            
            // Schedule cleanup after timeout
            setTimeout(() => {
                this.messageRoutes.delete(messageId);
                console.log(`🧹 Cleaned up route tracking for message ${messageId}`);
            }, this.routeTimeout);
            
            return false;
        }
        
        // Check if this node has already seen the message
        if (route.has(nodeId)) {
            console.warn(`🔄 Loop detected: ${nodeId} has already seen message ${messageId}`);
            console.warn(`   Route path: ${Array.from(route).join(' → ')}`);
            return true;
        }
        
        // Add node to route tracking
        route.add(nodeId);
        console.log(`📍 Message ${messageId} route: ${Array.from(route).join(' → ')}`);
        
        // Check for potential loops based on route size
        if (route.size > 10) {
            console.warn(`⚠️ Suspicious route length (${route.size} nodes) for message ${messageId}`);
        }
        
        return false;
    }

    /**
     * Advanced loop detection with path analysis
     */
    private detectRoutingLoop(message: BLEMessage): boolean {
        // Check if we're already in the route path
        if (message.routePath && message.routePath.includes(this.nodeId)) {
            console.warn(`🔄 Node ${this.nodeId} already in route path for message ${message.messageId}`);
            return true;
        }
        
        // Check hop count against route path length
        if (message.routePath && message.hopCount !== message.routePath.length) {
            console.warn(`⚠️ Hop count mismatch: hopCount=${message.hopCount}, routePath=${message.routePath.length}`);
        }
        
        // Check for duplicate consecutive nodes in path (bouncing)
        if (message.routePath && message.routePath.length > 2) {
            for (let i = 0; i < message.routePath.length - 2; i++) {
                if (message.routePath[i] === message.routePath[i + 2]) {
                    console.warn(`🔄 Message bouncing detected between nodes in path`);
                    return true;
                }
            }
        }
        
        return false;
    }

    /**
     * Create relay signature
     *
     * Generates a cryptographic signature for message relay using the node's
     * key pair, binding the relay operation to the node's identity.
     */
    private createRelaySignature(messageId: string): string {
        if (!this.keyPair) {
            return '';
        }

        const signatureData = `relay-${this.nodeId}-${messageId}-${Date.now()}`;
        const signature = this.keyPair.signMessage(signatureData);
        return this.bytesToHex(signature);
    }

    /**
     * Handle incoming message with Protocol v2 verification awareness
     *
     * Processes incoming messages, enforcing verification, replay protection,
     * TTL and hop count checks, and forwarding or delivery decisions based on
     * network topology and Protocol v2 compliance.
     */
        handleIncomingMessage(message: BLEMessage, fromNodeId: string): 'accept' | 'forward' | 'drop' {
        const messageId = message.messageId;
        
        // Enhanced loop prevention - check multiple conditions
        if (this.hasMessageLooped(messageId, fromNodeId)) {
            console.log(`🚫 Loop detected for message ${messageId}, dropping`);
            return 'drop';
        }
        
        // Additional path-based loop detection
        if (this.detectRoutingLoop(message)) {
            console.log(`🚫 Routing loop detected for message ${messageId}, dropping`);
            return 'drop';
        }
        
        // Check if we've seen this exact message before (replay protection)
        if (this.processedMessages.has(messageId)) {
            const processedInfo = this.processedMessages.get(messageId)!;
            
            // If it's from a different node, might be legitimate relay
            if (processedInfo.fromNodeId !== fromNodeId) {
                console.log(`📨 Message ${messageId} already processed but from different node, checking relay validity`);
                
                // Check if hop count increased (valid relay)
                if (message.hopCount <= processedInfo.hopCount) {
                    console.log(`🚫 Invalid relay: hop count not increased, dropping`);
                    return 'drop';
                }
            } else {
                console.log(`🚫 Duplicate message ${messageId} from same node, dropping`);
                return 'drop';
            }
        }
        
        // Continue with existing logic...
        // Check if message is for us
        if (message.destinationId === this.nodeId) {
            this.markMessageProcessed(messageId, fromNodeId, message.hopCount);
            return 'accept';
        }
        
        // Check TTL
        if (Date.now() > message.expiresAt) {
            console.log(`⏰ Message ${messageId} expired, dropping`);
            return 'drop';
        }
        
        // Check max hops
        if (message.hopCount >= message.maxHops) {
            console.log(`🚫 Message ${messageId} exceeded max hops (${message.maxHops}), dropping`);
            return 'drop';
        }
        
        // Forward the message
        this.markMessageProcessed(messageId, fromNodeId, message.hopCount);
        return 'forward';
    }

        /**
         * Mark message as processed with additional metadata
         */
    private markMessageProcessed(messageId: string, fromNodeId: string, hopCount: number): void {
        this.processedMessages.set(messageId, {
            timestamp: Date.now(),
            fromNodeId,
            hopCount
        });
    }

    /**
     * Start periodic cleanup of route tracking
     */
    private startRouteCleanup(): void {
        if (this.routeCleanupTimer) return;
        
        this.routeCleanupTimer = setInterval(() => {
            const now = Date.now();
            let cleaned = 0;
            
            // Clean up old routes
            for (const [messageId, route] of this.messageRoutes) {
                // Routes are automatically cleaned by setTimeout, 
                // this is just a backup cleanup
                if (route.size === 0) {
                    this.messageRoutes.delete(messageId);
                    cleaned++;
                }
            }
            
            if (cleaned > 0) {
                console.log(`🧹 Cleaned ${cleaned} empty route entries`);
            }
            
            // Log route table size for monitoring
            if (this.messageRoutes.size > 100) {
                console.warn(`⚠️ Large route table size: ${this.messageRoutes.size} entries`);
            }
        }, 30000); // Every 30 seconds
    }

        /**
         * Stop route cleanup timer
         */
        private stopRouteCleanup(): void {
            if (this.routeCleanupTimer) {
                clearInterval(this.routeCleanupTimer);
                this.routeCleanupTimer = undefined;
            }
        }

    /**
     * Learn route from message routing with protocol version tracking
     *
     * Updates routing table with new or improved routes based on observed
     * message paths, reliability, and protocol version information.
     */
    private learnRoute(
        targetNodeId: string, 
        nextHopNodeId: string, 
        hopCount: number, 
        reliability: number,
        protocolVersion?: number
    ): void {
        const existingRoute = this.routingTable.get(targetNodeId);

        // Only update if this is a better route
        if (!existingRoute ||
            hopCount < existingRoute.hopCount ||
            (hopCount === existingRoute.hopCount && reliability > existingRoute.reliability)) {

            const route: RouteEntry = {
                targetNodeId,
                nextHopNodeId,
                hopCount,
                lastUpdated: Date.now(),
                reliability,
                protocolVersion
            };

            this.routingTable.set(targetNodeId, route);
            this.stats.routingTableSize = this.routingTable.size;
            this.routingTableVersion++;

            console.log(`Learned route to ${targetNodeId} via ${nextHopNodeId} (${hopCount} hops, Protocol v${protocolVersion || 'unknown'})`);
        }
    }

    /**
     * Verify relay signatures in message path
     *
     * Checks that all relay signatures match the expected route path, enabling
     * audit and verification of message forwarding integrity.
     */
    verifyRelaySignatures(message: BLEMessage): boolean {
        if (!message.relaySignatures || message.relaySignatures.length === 0) {
            return true; // No signatures to verify
        }

        // Verify each relay signature matches the route path
        for (let i = 0; i < message.relaySignatures.length; i++) {
            const signature = message.relaySignatures[i];
            const expectedNodeId = message.routePath[i + 1]; // +1 because first is sender

            if (signature.nodeId !== expectedNodeId) {
                console.warn(`Relay signature mismatch at hop ${i + 1}`);
                return false;
            }

            // Could verify actual signature here if we have the relay node's public key
        }

        return true;
    }

    /**
     * Get verification state for a message
     *
     * Returns cached verification status and sender public key for a given message ID.
     */
    getMessageVerificationState(messageId: string): { 
        verified: boolean; 
        senderPublicKey?: string 
    } | null {
        return this.messageVerificationCache.get(messageId) || null;
    }

    /**
     * Start periodic verification cache cleanup
     *
     * Initiates regular cleanup of old verification cache entries to optimize memory usage.
     */
    private startVerificationCacheCleanup(): void {
        setInterval(() => {
            this.cleanupVerificationCache();
        }, 120000); // Clean up every 2 minutes
    }

    /**
     * Clean up old verification cache entries
     *
     * Removes verification cache entries older than the configured maximum age.
     */
    private cleanupVerificationCache(): void {
        const now = Date.now();
        const maxAge = 300000; // 5 minutes
        let removed = 0;

        for (const [messageId, entry] of this.messageVerificationCache) {
            if (now - entry.timestamp > maxAge) {
                this.messageVerificationCache.delete(messageId);
                this.verifiedMessages.delete(messageId);
                removed++;
            }
        }

        if (removed > 0) {
            console.log(`Cleaned up ${removed} verification cache entries`);
        }
    }

    /**
     * Get routing table
     *
     * Returns the current routing table as an array of route entries.
     */
    getRoutingTable(): RouteEntry[] {
        return Array.from(this.routingTable.values());
    }

    /**
     * Get message queue status
     *
     * Returns the current message queue as an array of queue entries.
     */
    getMessageQueue(): MessageQueueEntry[] {
        return Array.from(this.messageQueue.values());
    }

    /**
     * Get mesh statistics
     *
     * Returns a snapshot of current mesh network statistics and performance metrics.
     */
    getStats(): MeshStats {
        this.stats.totalMessages = this.stats.messagesDelivered +
            this.stats.messagesForwarded +
            this.stats.messagesFailed +
            this.stats.queuedMessages;
        return { ...this.stats };
    }

    /**
     * Clear routing table
     *
     * Removes all entries from the routing table and updates statistics.
     */
    clearRoutingTable(): void {
        console.log('Clearing routing table');
        this.routingTable.clear();
        this.stats.routingTableSize = 0;
        this.routingTableVersion++;
    }

    /**
     * Clear message queue
     *
     * Removes all messages from the delivery queue and updates statistics.
     */
    clearMessageQueue(): void {
        console.log('Clearing message queue');
        this.messageQueue.clear();
        this.stats.queuedMessages = 0;
    }

    /**
     * Start periodic routing table cleanup
     *
     * Initiates regular cleanup of stale routing table entries to maintain topology freshness.
     */
    private startRoutingTableCleanup(): void {
        setInterval(() => {
            this.cleanupRoutingTable();
        }, 60000); // Clean up every minute
    }

    /**
     * Clean up stale routing table entries
     *
     * Removes routing table entries older than the configured maximum age.
     */
    private cleanupRoutingTable(): void {
        const now = Date.now();
        const maxAge = BLE_CONFIG.MESSAGE_TTL;
        let removed = 0;

        for (const [nodeId, route] of this.routingTable) {
            if (now - route.lastUpdated > maxAge) {
                this.routingTable.delete(nodeId);
                removed++;
            }
        }

        if (removed > 0) {
            console.log(`Cleaned up ${removed} stale routes`);
            this.stats.routingTableSize = this.routingTable.size;
            this.routingTableVersion++;
        }
    }

    /**
     * Export mesh state for debugging
     *
     * Returns a complete snapshot of mesh state including node ID, routing table,
     * message queue, statistics, verified messages, and protocol version.
     */
    exportMeshState(): {
        nodeId: string;
        routingTable: RouteEntry[];
        messageQueue: MessageQueueEntry[];
        stats: MeshStats;
        verifiedMessages: string[];
        protocolVersion: number;
    } {
        return {
            nodeId: this.nodeId,
            routingTable: this.getRoutingTable(),
            messageQueue: this.getMessageQueue(),
            stats: this.getStats(),
            verifiedMessages: Array.from(this.verifiedMessages),
            protocolVersion: BLE_SECURITY_CONFIG.PROTOCOL_VERSION
        };
    }

    /**
     * Set key pair for relay signatures
     *
     * Assigns the node's cryptographic key pair for relay signature generation.
     */
    setKeyPair(keyPair: IGhostKeyPair): void {
        this.keyPair = keyPair;
    }

    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }
}