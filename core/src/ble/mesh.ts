// core/src/ble/mesh.ts
// Enhanced Mesh Network with Protocol v2 Security

import { 
    BLENode, 
    BLEMessage, 
    BLE_CONFIG,
    BLE_SECURITY_CONFIG,
    RelaySignature,
    BLEErrorCode
} from './types';
import { IGhostKeyPair } from '../types/crypto';

export interface RouteEntry {
    targetNodeId: string;         // Destination node
    nextHopNodeId: string;        // Next hop to reach destination
    hopCount: number;             // Number of hops to destination
    lastUpdated: number;          // When this route was last updated
    reliability: number;          // Route reliability score (0-1)
    protocolVersion?: number;     // Protocol version of target node
}

export interface MessageQueueEntry {
    message: BLEMessage;
    targetNodeId: string;
    attempts: number;
    lastAttempt: number;
    maxAttempts: number;
    requiresVerification: boolean; // Protocol v2 requirement
}

export interface MeshStats {
    totalMessages: number;
    routingTableSize: number;
    queuedMessages: number;
    messagesForwarded: number;
    messagesDelivered: number;
    messagesFailed: number;
    messagesVerified: number;      // Protocol v2: verified messages
    verificationFailures: number;  // Protocol v2: failed verifications
    signaturesMaintained: number;  // Protocol v2: signatures preserved
}

/**
 * Enhanced Mesh Network with Protocol v2 signature preservation
 */
export class MeshNetwork {
    private routingTable: Map<string, RouteEntry> = new Map();
    private messageQueue: Map<string, MessageQueueEntry> = new Map();
    private forwardedMessages: Set<string> = new Set(); // Prevent loops
    private nodeId: string;
    private routingTableVersion: number = 0;
    private keyPair?: IGhostKeyPair; // For relay signatures
    
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
     * Create relay signature
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
     */
    handleIncomingMessage(
        message: BLEMessage, 
        fromNodeId: string,
        isVerified?: boolean
    ): 'deliver' | 'forward' | 'drop' | 'accept' {
        const messageId = message.messageId;

        // Increment total messages processed
        this.stats.totalMessages++;

        // Protocol v2: Check if message requires verification
        if (message.version >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            // Cache verification state
            if (isVerified !== undefined) {
                this.messageVerificationCache.set(messageId, {
                    verified: isVerified,
                    senderPublicKey: message.senderPublicKey,
                    timestamp: Date.now()
                });

                if (isVerified) {
                    this.verifiedMessages.add(messageId);
                    this.stats.messagesVerified++;
                } else {
                    this.stats.verificationFailures++;
                    console.error(`Message ${messageId} failed verification, dropping`);
                    return 'drop';
                }
            } else if (BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION) {
                // If verification is required but not provided, drop
                console.error(`Message ${messageId} requires verification but none provided`);
                return 'drop';
            }
        }

        // Check if we've already seen this message (prevent loops)
        if (this.forwardedMessages.has(messageId)) {
            console.log(`Already forwarded message ${messageId}, dropping`);
            return 'drop';
        }

        // Check TTL
        if (message.ttl < Date.now()) {
            console.log(`Message ${messageId} expired, dropping`);
            return 'drop';
        }

        // Check hop count
        if (message.hopCount >= BLE_CONFIG.MAX_HOP_COUNT) {
            console.log(`Message ${messageId} exceeded max hop count, dropping`);
            return 'drop';
        }

        // Mark as seen
        this.forwardedMessages.add(messageId);

        // Clean up old forwarded messages to prevent memory leak
        if (this.forwardedMessages.size > 1000) {
            const messagesToRemove = Array.from(this.forwardedMessages).slice(0, 500);
            messagesToRemove.forEach(id => this.forwardedMessages.delete(id));
        }

        // Update route to sender (reverse path learning)
        this.learnRoute(fromNodeId, fromNodeId, 1, 0.8);

        // Check if message is for us
        if (message.destinationId === this.nodeId) {
            return 'deliver';
        }

        // Check if we should forward
        if (message.destinationId) {
            // Unicast message - check if we have a route
            const route = this.findRoute(message.destinationId);
            if (route) {
                // Validate Protocol v2 fields are intact for forwarding
                if (message.version >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                    if (!this.validateMessageForRelay(message)) {
                        console.error(`Cannot forward message ${messageId} - Protocol v2 fields corrupted`);
                        return 'drop';
                    }
                }
                return 'forward';
            }
        } else {
            // Broadcast message - forward if not at hop limit
            if (message.hopCount < message.maxHops) {
                return 'forward';
            }
        }

        return 'accept';
    }

    /**
     * Learn route from message routing with protocol version tracking
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
     */
    getMessageVerificationState(messageId: string): { 
        verified: boolean; 
        senderPublicKey?: string 
    } | null {
        return this.messageVerificationCache.get(messageId) || null;
    }

    /**
     * Start periodic verification cache cleanup
     */
    private startVerificationCacheCleanup(): void {
        setInterval(() => {
            this.cleanupVerificationCache();
        }, 120000); // Clean up every 2 minutes
    }

    /**
     * Clean up old verification cache entries
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
     */
    getRoutingTable(): RouteEntry[] {
        return Array.from(this.routingTable.values());
    }

    /**
     * Get message queue status
     */
    getMessageQueue(): MessageQueueEntry[] {
        return Array.from(this.messageQueue.values());
    }

    /**
     * Get mesh statistics
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
     */
    clearRoutingTable(): void {
        console.log('Clearing routing table');
        this.routingTable.clear();
        this.stats.routingTableSize = 0;
        this.routingTableVersion++;
    }

    /**
     * Clear message queue
     */
    clearMessageQueue(): void {
        console.log('Clearing message queue');
        this.messageQueue.clear();
        this.stats.queuedMessages = 0;
    }

    /**
     * Start periodic routing table cleanup
     */
    private startRoutingTableCleanup(): void {
        setInterval(() => {
            this.cleanupRoutingTable();
        }, 60000); // Clean up every minute
    }

    /**
     * Clean up stale routing table entries
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