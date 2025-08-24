// core/src/ble/mesh.ts
import { BLENode, BLEMessage, BLE_CONFIG } from './types';

export interface RouteEntry {
    targetNodeId: string;         // Destination node
    nextHopNodeId: string;        // Next hop to reach destination
    hopCount: number;             // Number of hops to destination
    lastUpdated: number;          // When this route was last updated
    reliability: number;          // Route reliability score (0-1)
}

export interface MessageQueueEntry {
    message: BLEMessage;
    targetNodeId: string;
    attempts: number;
    lastAttempt: number;
    maxAttempts: number;
}

export interface MeshStats {
    totalMessages: number;        // Total messages processed (ADDED)
    routingTableSize: number;
    queuedMessages: number;
    messagesForwarded: number;
    messagesDelivered: number;
    messagesFailed: number;
}

export class MeshNetwork {
    getRoutingTableVersion(): number {
        return this.routingTableVersion;
    }

    private routingTable: Map<string, RouteEntry> = new Map();
    private messageQueue: Map<string, MessageQueueEntry> = new Map();
    private forwardedMessages: Set<string> = new Set(); // Prevent loops
    private nodeId: string;
    private routingTableVersion: number = 0;  // Added for getRoutingTableVersion
    private stats: MeshStats = {
        totalMessages: 0,         // Initialize totalMessages
        routingTableSize: 0,
        queuedMessages: 0,
        messagesForwarded: 0,
        messagesDelivered: 0,
        messagesFailed: 0
    };

    constructor(nodeId: string) {
        this.nodeId = nodeId;
        this.startRoutingTableCleanup();
    }

    /**
     * Update routing table based on discovered nodes
     */
    updateRoutingTable(discoveredNodes: BLENode[], connectedNodes: BLENode[]): void {
        console.log(`🗺️ Updating routing table with ${discoveredNodes.length} discovered nodes`);

        // Add direct routes for connected nodes
        for (const node of connectedNodes) {
            if (node.id !== this.nodeId) {
                const route: RouteEntry = {
                    targetNodeId: node.id,
                    nextHopNodeId: node.id, // Direct connection
                    hopCount: 1,
                    lastUpdated: Date.now(),
                    reliability: 0.9 // High reliability for direct connections
                };

                this.routingTable.set(node.id, route);
            }
        }

        // Remove routes for nodes that are no longer discovered
        const discoveredNodeIds = new Set(discoveredNodes.map(n => n.id));
        for (const [nodeId] of this.routingTable) {
            if (!discoveredNodeIds.has(nodeId)) {
                console.log(`🗑️ Removing route to lost node: ${nodeId}`);
                this.routingTable.delete(nodeId);
            }
        }

        this.stats.routingTableSize = this.routingTable.size;
        this.routingTableVersion++;  // Increment version on update
        console.log(`✅ Routing table updated: ${this.routingTable.size} routes`);
    }

    /**
     * Find best route to a target node
     */
    findRoute(targetNodeId: string): RouteEntry | null {
        const route = this.routingTable.get(targetNodeId);

        if (!route) {
            console.log(`❌ No route found to node: ${targetNodeId}`);
            return null;
        }

        // Check if route is still valid (not too old)
        const maxAge = BLE_CONFIG.MESSAGE_TTL / 2; // Routes expire after half message TTL
        if (Date.now() - route.lastUpdated > maxAge) {
            console.log(`⏰ Route to ${targetNodeId} is stale, removing`);
            this.routingTable.delete(targetNodeId);
            this.stats.routingTableSize = this.routingTable.size;
            return null;
        }

        return route;
    }

    /**
     * Queue message for delivery
     */
    queueMessage(message: BLEMessage, targetNodeId: string): void {
        const queueEntry: MessageQueueEntry = {
            message,
            targetNodeId,
            attempts: 0,
            lastAttempt: 0,
            maxAttempts: 3
        };

        this.messageQueue.set(message.messageId, queueEntry);
        this.stats.queuedMessages = this.messageQueue.size;
        this.stats.totalMessages++;  // Increment total messages

        console.log(`📦 Queued message ${message.messageId} for delivery to ${targetNodeId}`);
    }

    /**
     * Process message queue and attempt delivery
     */
    async processMessageQueue(
        sendDirectMessage: (nodeId: string, message: BLEMessage) => Promise<boolean>,
        getConnectedNodes: () => BLENode[]
    ): Promise<void> {
        if (this.messageQueue.size === 0) {
            return;
        }

        console.log(`📮 Processing message queue: ${this.messageQueue.size} messages`);

        const now = Date.now();
        const connectedNodes = getConnectedNodes();
        const connectedNodeIds = new Set(connectedNodes.map(n => n.id));

        for (const [messageId, queueEntry] of this.messageQueue) {
            const { message, targetNodeId, attempts, lastAttempt, maxAttempts } = queueEntry;

            // Skip if attempted too recently
            if (now - lastAttempt < 5000) { // Wait 5 seconds between attempts
                continue;
            }

            // Remove if expired or too many attempts
            if (message.ttl < now || attempts >= maxAttempts) {
                console.log(`🗑️ Removing expired/failed message ${messageId}`);
                this.messageQueue.delete(messageId);
                this.stats.messagesFailed++;
                continue;
            }

            // Try to deliver the message
            let delivered = false;

            // First, try direct delivery if target is connected
            if (connectedNodeIds.has(targetNodeId)) {
                try {
                    delivered = await sendDirectMessage(targetNodeId, message);
                    if (delivered) {
                        console.log(`✅ Direct delivery successful for message ${messageId}`);
                        this.stats.messagesDelivered++;
                    }
                } catch (error) {
                    console.warn(`❌ Direct delivery failed for message ${messageId}:`, error);
                }
            }

            // If direct delivery failed, try routing through mesh
            if (!delivered) {
                const route = this.findRoute(targetNodeId);
                if (route && connectedNodeIds.has(route.nextHopNodeId)) {
                    try {
                        // Forward message through next hop
                        const forwardedMessage: BLEMessage = {
                            ...message,
                            hopCount: message.hopCount + 1
                        };

                        delivered = await sendDirectMessage(route.nextHopNodeId, forwardedMessage);
                        if (delivered) {
                            console.log(`✅ Mesh delivery successful for message ${messageId} via ${route.nextHopNodeId}`);
                            this.stats.messagesForwarded++;
                        }
                    } catch (error) {
                        console.warn(`❌ Mesh delivery failed for message ${messageId}:`, error);
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
     * Handle incoming message for routing decision
     */
    handleIncomingMessage(message: BLEMessage, fromNodeId: string): 'deliver' | 'forward' | 'drop' | 'accept' {
        const messageId = message.messageId;

        // Increment total messages processed
        this.stats.totalMessages++;

        // Check if we've already seen this message (prevent loops)
        if (this.forwardedMessages.has(messageId)) {
            console.log(`🔄 Already forwarded message ${messageId}, dropping`);
            return 'drop';
        }

        // Check TTL
        if (message.ttl < Date.now()) {
            console.log(`⏰ Message ${messageId} expired, dropping`);
            return 'drop';
        }

        // Check hop count
        if (message.hopCount >= BLE_CONFIG.MAX_HOP_COUNT) {
            console.log(`🚫 Message ${messageId} exceeded max hop count, dropping`);
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

        // Return routing decision (accept is a valid decision)
        return 'accept';
    }

    /**
     * Learn route from message routing
     */
    private learnRoute(targetNodeId: string, nextHopNodeId: string, hopCount: number, reliability: number): void {
        const existingRoute = this.routingTable.get(targetNodeId);

        // Only update if this is a better route (fewer hops or more recent)
        if (!existingRoute ||
            hopCount < existingRoute.hopCount ||
            (hopCount === existingRoute.hopCount && reliability > existingRoute.reliability)) {

            const route: RouteEntry = {
                targetNodeId,
                nextHopNodeId,
                hopCount,
                lastUpdated: Date.now(),
                reliability
            };

            this.routingTable.set(targetNodeId, route);
            this.stats.routingTableSize = this.routingTable.size;
            this.routingTableVersion++;  // Increment version when routes change

            console.log(`📍 Learned route to ${targetNodeId} via ${nextHopNodeId} (${hopCount} hops)`);
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
        // Update totalMessages to reflect all processed messages
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
        console.log('🧹 Clearing routing table');
        this.routingTable.clear();
        this.stats.routingTableSize = 0;
        this.routingTableVersion++;
    }

    /**
     * Clear message queue
     */
    clearMessageQueue(): void {
        console.log('🧹 Clearing message queue');
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
            console.log(`🧹 Cleaned up ${removed} stale routes`);
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
    } {
        return {
            nodeId: this.nodeId,
            routingTable: this.getRoutingTable(),
            messageQueue: this.getMessageQueue(),
            stats: this.getStats()
        };
    }
}