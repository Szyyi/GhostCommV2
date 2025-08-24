// core/src/ble/scanner.ts
// Enhanced BLE Scanner with cryptographic verification and anti-tracking

import {
    BLENode,
    BLEAdvertisementData,
    BLEDiscoveryEvent,
    BLE_CONFIG,
    IdentityProof,
    PreKeyBundle,
    VerificationStatus,
    VerificationResult,
    VerificationMethod,
    NodeCapability,
    DeviceType,
    ConnectionState,
    BLEError,
    BLEErrorCode,
    RouteMetrics,
    RelayStatistics
} from './types';
import {
    IGhostKeyPair,
    PreKey,
    CryptoAlgorithm
} from '../types/crypto';
import { BLEAdvertiser } from './advertiser';

/**
 * Enhanced scan result with security metadata
 */
export interface ScanResult {
    deviceId: string;                    // Platform-specific device ID
    advertisementData: BLEAdvertisementData;
    rssi: number;                        // Signal strength
    txPower?: number;                    // Transmission power
    distance?: number;                   // Estimated distance
    timestamp: number;                   // Discovery timestamp
    rawData?: Uint8Array;               // Raw advertisement packet
    isVerified: boolean;                // Signature verification status
    verificationError?: string;          // Verification failure reason
}

/**
 * Node tracking information
 */
interface NodeTracker {
    node: BLENode;
    advertisements: ScanResult[];        // Recent advertisements
    rssiHistory: number[];              // Signal strength history
    lastVerified: number;               // Last verification timestamp
    verificationAttempts: number;       // Verification attempt count
    trustScore: number;                 // Computed trust score
    ephemeralIds: Map<string, number>; // Seen ephemeral IDs
}

/**
 * Scan filter configuration
 */
export interface ScanFilter {
    serviceUUID?: string;               // Filter by service UUID
    minRssi?: number;                  // Minimum signal strength
    maxDistance?: number;              // Maximum distance
    capabilities?: NodeCapability[];   // Required capabilities
    verifiedOnly?: boolean;           // Only verified nodes
    trustedOnly?: boolean;            // Only trusted nodes
}

/**
 * Scan configuration
 */
export interface ScanConfig {
    interval: number;                   // Scan interval in ms
    window: number;                    // Scan window in ms
    duplicates: boolean;               // Allow duplicate advertisements
    activeScan: boolean;              // Active vs passive scanning
    filters?: ScanFilter[];           // Scan filters
}

// Callback types
export type ScanCallback = (result: ScanResult) => void;
export type DiscoveryCallback = (event: BLEDiscoveryEvent) => void;
export type VerificationCallback = (nodeId: string, result: VerificationResult) => void;

/**
 * Enhanced BLE Scanner with security features
 */
export abstract class BLEScanner {
    // State management
    private isScanning: boolean = false;
    private isPaused: boolean = false;
    private scanConfig: ScanConfig;

    // Node tracking
    private nodeTrackers: Map<string, NodeTracker>;
    private ephemeralIdMap: Map<string, string>; // Ephemeral ID -> Node ID
    private verifiedNodes: Map<string, VerificationResult>;
    private blockedNodes: Set<string>;

    // Security components
    protected keyPair?: IGhostKeyPair;
    private replayProtection: Map<string, Set<number>>; // Node ID -> Sequence numbers
    private signatureCache: Map<string, boolean>;

    // Callbacks
    private scanCallbacks: Set<ScanCallback>;
    private discoveryCallbacks: Set<DiscoveryCallback>;
    private verificationCallbacks: Set<VerificationCallback>;

    // Timers
    private nodeTimeoutTimer?: NodeJS.Timeout;
    private verificationTimer?: NodeJS.Timeout;
    private cleanupTimer?: NodeJS.Timeout;

    // Rate limiting
    private discoveryRateLimit: Map<string, number>;
    private lastDiscoveryTime: number = 0;

    // Statistics
    private statistics = {
        totalScans: 0,
        advertisementsReceived: 0,
        nodesDiscovered: 0,
        nodesVerified: 0,
        verificationFailures: 0,
        replaysDetected: 0,
        duplicatesFiltered: 0,
        averageRssi: -70,
        strongestSignal: -100,
        weakestSignal: 0
    };

    constructor(keyPair?: IGhostKeyPair) {
        this.keyPair = keyPair;

        // Initialize collections
        this.nodeTrackers = new Map();
        this.ephemeralIdMap = new Map();
        this.verifiedNodes = new Map();
        this.blockedNodes = new Set();
        this.replayProtection = new Map();
        this.signatureCache = new Map();
        this.discoveryRateLimit = new Map();

        // Initialize callbacks
        this.scanCallbacks = new Set();
        this.discoveryCallbacks = new Set();
        this.verificationCallbacks = new Set();

        // Default scan configuration
        this.scanConfig = {
            interval: BLE_CONFIG.SCAN_INTERVAL,
            window: BLE_CONFIG.SCAN_WINDOW,
            duplicates: false,
            activeScan: true,
            filters: []
        };

        // Start cleanup timer
        this.startCleanupTimer();
    }

    /**
     * Platform-specific scanning implementation
     */
    protected abstract startPlatformScanning(config: ScanConfig): Promise<void>;
    protected abstract stopPlatformScanning(): Promise<void>;
    protected abstract setPlatformScanFilters(filters: ScanFilter[]): Promise<void>;
    protected abstract checkPlatformCapabilities(): Promise<{
        maxScanFilters: number;
        supportsActiveScan: boolean;
        supportsContinuousScan: boolean;
        supportsBackgroundScan: boolean;
    }>;

    /**
     * Start secure scanning with verification
     */
    async startScanning(config?: Partial<ScanConfig>): Promise<void> {
        if (this.isScanning && !this.isPaused) {
            console.log('⚠️ Already scanning');
            return;
        }

        try {
            console.log('🔍 Starting secure BLE scanning...');

            // Merge configuration
            if (config) {
                this.scanConfig = { ...this.scanConfig, ...config };
            }

            // Validate configuration
            this.validateScanConfig();

            // Check platform capabilities
            const capabilities = await this.checkPlatformCapabilities();

            // Apply filters if supported
            if (this.scanConfig.filters && this.scanConfig.filters.length > 0) {
                if (this.scanConfig.filters.length > capabilities.maxScanFilters) {
                    console.warn(`⚠️ Too many filters (${this.scanConfig.filters.length}), using first ${capabilities.maxScanFilters}`);
                    this.scanConfig.filters = this.scanConfig.filters.slice(0, capabilities.maxScanFilters);
                }
                await this.setPlatformScanFilters(this.scanConfig.filters);
            }

            // Start platform scanning
            await this.startPlatformScanning(this.scanConfig);

            // Update state
            this.isScanning = true;
            this.isPaused = false;

            // Start timers
            this.startNodeTimeoutTimer();
            this.startVerificationTimer();

            // Update statistics
            this.statistics.totalScans++;

            console.log('✅ Secure BLE scanning started successfully');

        } catch (error) {
            console.error('❌ Failed to start BLE scanning:', error);
            this.isScanning = false;
            throw error;
        }
    }

    /**
     * Stop scanning
     */
    async stopScanning(): Promise<void> {
        if (!this.isScanning) {
            return;
        }

        try {
            console.log('🛑 Stopping BLE scanning...');

            // Stop platform scanning
            await this.stopPlatformScanning();

            // Stop timers
            this.stopNodeTimeoutTimer();
            this.stopVerificationTimer();

            // Update state
            this.isScanning = false;
            this.isPaused = false;

            console.log('✅ BLE scanning stopped');

        } catch (error) {
            console.error('❌ Failed to stop BLE scanning:', error);
            throw error;
        }
    }

    /**
     * Pause scanning temporarily
     */
    async pauseScanning(): Promise<void> {
        if (!this.isScanning || this.isPaused) {
            return;
        }

        console.log('⏸️ Pausing BLE scanning');
        await this.stopPlatformScanning();
        this.isPaused = true;
    }

    /**
     * Resume scanning
     */
    async resumeScanning(): Promise<void> {
        if (!this.isScanning || !this.isPaused) {
            return;
        }

        console.log('▶️ Resuming BLE scanning');
        await this.startPlatformScanning(this.scanConfig);
        this.isPaused = false;
    }

    /**
     * Handle scan result from platform with verification
     */
    protected async handleScanResult(
        deviceId: string,
        rawData: Uint8Array,
        rssi: number,
        txPower?: number
    ): Promise<void> {
        try {
            // Update statistics
            this.statistics.advertisementsReceived++;
            this.updateRssiStatistics(rssi);

            // Parse advertisement packet
            const packet = BLEAdvertiser.parseAdvertisementPacket(rawData);
            if (!packet) {
                console.warn('⚠️ Failed to parse advertisement packet');
                return;
            }

            // Convert packet to advertisement data
            const advertisementData = await this.packetToAdvertisementData(packet);
            if (!advertisementData) {
                console.warn('⚠️ Failed to convert packet to advertisement data');
                return;
            }

            // Check if node is blocked
            const nodeId = await this.resolveNodeId(advertisementData);
            if (this.blockedNodes.has(nodeId)) {
                console.log(`🚫 Blocked node detected: ${nodeId}`);
                return;
            }

            // Verify advertisement signature
            const isVerified = await this.verifyAdvertisement(advertisementData, packet);

            // Check replay protection
            if (!this.checkReplayProtection(nodeId, advertisementData.sequenceNumber)) {
                console.warn(`⚠️ Replay detected from ${nodeId}`);
                this.statistics.replaysDetected++;
                return;
            }

            // Apply filters
            if (!this.applyFilters(advertisementData, rssi, isVerified)) {
                return;
            }

            // Check rate limiting
            if (!this.checkDiscoveryRateLimit(nodeId)) {
                console.warn(`⚠️ Discovery rate limit exceeded for ${nodeId}`);
                return;
            }

            // Calculate distance if TX power available
            const distance = txPower ? this.calculateDistance(rssi, txPower) : undefined;

            // Create scan result
            const scanResult: ScanResult = {
                deviceId,
                advertisementData,
                rssi,
                txPower,
                distance,
                timestamp: Date.now(),
                rawData,
                isVerified,
                verificationError: isVerified ? undefined : 'Signature verification failed'
            };

            // Notify scan callbacks
            this.notifyScanCallbacks(scanResult);

            // Update node discovery
            await this.updateNodeDiscovery(scanResult, nodeId);

        } catch (error) {
            console.error('❌ Error handling scan result:', error);
        }
    }

    /**
     * Convert packet to advertisement data
     */
    private async packetToAdvertisementData(packet: any): Promise<BLEAdvertisementData | null> {
        try {
            // Parse extended data if present
            let preKeyBundle: PreKeyBundle | undefined;
            if (packet.extendedData) {
                try {
                    const extendedStr = new TextDecoder().decode(packet.extendedData);
                    preKeyBundle = JSON.parse(extendedStr);
                } catch {
                    // Extended data might not be pre-key bundle
                }
            }

            // Create identity proof
            const identityProof: IdentityProof = {
                publicKeyHash: this.bytesToHex(packet.identityHash),
                timestamp: packet.timestamp * 1000, // Convert to ms
                nonce: this.bytesToHex(packet.ephemeralId).substring(0, 32),
                signature: this.bytesToHex(packet.signature),
                preKeyBundle
            };

            // Parse capabilities from flags
            const capabilities = this.parseCapabilityFlags(packet.flags);

            // Create advertisement data
            const advertisementData: BLEAdvertisementData = {
                version: packet.version,
                ephemeralId: this.bytesToHex(packet.ephemeralId),
                identityProof,
                timestamp: packet.timestamp * 1000,
                sequenceNumber: packet.sequenceNumber,
                capabilities,
                deviceType: DeviceType.PHONE, // Would determine from flags
                protocolVersion: packet.version,
                meshInfo: {
                    nodeCount: packet.meshInfo.nodeCount,
                    messageQueueSize: packet.meshInfo.queueSize,
                    routingTableVersion: 0,
                    beaconInterval: BLE_CONFIG.ADVERTISEMENT_INTERVAL
                },
                batteryLevel: packet.meshInfo.batteryLevel
            };

            return advertisementData;

        } catch (error) {
            console.error('❌ Error converting packet to advertisement data:', error);
            return null;
        }
    }

    /**
     * Verify advertisement signature
     */
    private async verifyAdvertisement(
        data: BLEAdvertisementData,
        packet: any
    ): Promise<boolean> {
        try {
            // Check signature cache
            const cacheKey = `${data.ephemeralId}-${data.sequenceNumber}`;
            const cached = this.signatureCache.get(cacheKey);
            if (cached !== undefined) {
                return cached;
            }

            // Get node's public key
            const nodeId = await this.resolveNodeId(data);
            const tracker = this.nodeTrackers.get(nodeId);

            if (!tracker || !tracker.node.identityKey) {
                // Can't verify without public key
                this.signatureCache.set(cacheKey, false);
                return false;
            }

            // Recreate signing data
            const signingData = this.createSigningData(data);

            // Verify signature
            const signature = this.hexToBytes(data.identityProof.signature);
            const isValid = await this.verifySignature(
                signingData,
                signature,
                tracker.node.identityKey
            );

            // Cache result
            this.signatureCache.set(cacheKey, isValid);

            // Limit cache size
            if (this.signatureCache.size > 1000) {
                const firstKey = this.signatureCache.keys().next().value;
                if (firstKey) {
                    this.signatureCache.delete(firstKey);
                }
            }

            if (!isValid) {
                this.statistics.verificationFailures++;
            }

            return isValid;

        } catch (error) {
            console.error('❌ Error verifying advertisement:', error);
            return false;
        }
    }

    /**
     * Resolve node ID from advertisement
     */
    private async resolveNodeId(data: BLEAdvertisementData): Promise<string> {
        // Check if we've seen this ephemeral ID before
        const existingNodeId = this.ephemeralIdMap.get(data.ephemeralId);
        if (existingNodeId) {
            return existingNodeId;
        }

        // Try to match by public key hash
        for (const [nodeId, tracker] of this.nodeTrackers) {
            const nodeFingerprint = tracker.node.id;
            if (nodeFingerprint.startsWith(data.identityProof.publicKeyHash)) {
                // Update ephemeral ID mapping
                this.ephemeralIdMap.set(data.ephemeralId, nodeId);
                return nodeId;
            }
        }

        // Generate node ID from public key hash
        const nodeId = data.identityProof.publicKeyHash;
        this.ephemeralIdMap.set(data.ephemeralId, nodeId);
        return nodeId;
    }

    /**
     * Update node discovery with enhanced tracking
     */
    private async updateNodeDiscovery(
        scanResult: ScanResult,
        nodeId: string
    ): Promise<void> {
        const { advertisementData, rssi, distance } = scanResult;

        // Get or create tracker
        let tracker = this.nodeTrackers.get(nodeId);
        const isNewNode = !tracker;

        if (!tracker) {
            // Create new node
            const node: BLENode = await this.createNodeFromAdvertisement(
                nodeId,
                advertisementData,
                rssi,
                distance
            );

            tracker = {
                node,
                advertisements: [],
                rssiHistory: [],
                lastVerified: 0,
                verificationAttempts: 0,
                trustScore: 0,
                ephemeralIds: new Map()
            };

            this.nodeTrackers.set(nodeId, tracker);
            this.statistics.nodesDiscovered++;
        }

        // Update tracker
        tracker.node.lastSeen = Date.now();
        tracker.node.rssi = rssi;
        tracker.node.distance = distance;

        // Track advertisement
        tracker.advertisements.push(scanResult);
        if (tracker.advertisements.length > 10) {
            tracker.advertisements.shift();
        }

        // Track RSSI history
        tracker.rssiHistory.push(rssi);
        if (tracker.rssiHistory.length > 20) {
            tracker.rssiHistory.shift();
        }

        // Track ephemeral ID
        tracker.ephemeralIds.set(advertisementData.ephemeralId, Date.now());

        // Update trust score
        tracker.trustScore = this.calculateTrustScore(tracker, scanResult);
        tracker.node.trustScore = tracker.trustScore;

        // Update capabilities
        tracker.node.capabilities = advertisementData.capabilities;
        tracker.node.batteryLevel = advertisementData.batteryLevel;

        // Handle pre-keys if present
        if (advertisementData.identityProof.preKeyBundle) {
            await this.handlePreKeyBundle(
                tracker.node,
                advertisementData.identityProof.preKeyBundle
            );
        }

        // Emit discovery event
        if (isNewNode) {
            console.log(`🔍 Discovered new node: ${nodeId} (RSSI: ${rssi}dBm, Distance: ${distance?.toFixed(1)}m)`);

            const event: BLEDiscoveryEvent = {
                type: 'node_discovered',
                node: tracker.node,
                advertisement: advertisementData,
                rssi,
                timestamp: Date.now()
            };

            this.emitDiscoveryEvent(event);

        } else {
            // Update event for existing node
            if (Date.now() - tracker.lastVerified > 60000) { // Re-verify every minute
                this.scheduleVerification(nodeId);
            }

            const event: BLEDiscoveryEvent = {
                type: 'node_updated',
                node: tracker.node,
                advertisement: advertisementData,
                rssi,
                timestamp: Date.now()
            };

            this.emitDiscoveryEvent(event);
        }
    }

    /**
     * Create node from advertisement
     */
    private async createNodeFromAdvertisement(
        nodeId: string,
        ad: BLEAdvertisementData,
        rssi: number,
        distance?: number
    ): Promise<BLENode> {
        // Extract keys from pre-key bundle if available
        let identityKey: Uint8Array | undefined;
        let encryptionKey: Uint8Array | undefined;
        let preKeys: PreKey[] | undefined;

        if (ad.identityProof.preKeyBundle) {
            identityKey = this.hexToBytes(ad.identityProof.preKeyBundle.identityKey);
            encryptionKey = this.hexToBytes(ad.identityProof.preKeyBundle.signedPreKey.publicKey);

            // Convert pre-keys
            if (ad.identityProof.preKeyBundle.oneTimePreKeys) {
                preKeys = ad.identityProof.preKeyBundle.oneTimePreKeys.map((pk, index) => ({
                    keyId: pk.keyId,
                    publicKey: this.hexToBytes(pk.publicKey),
                    privateKey: new Uint8Array(0), // Not available
                    signature: new Uint8Array(0), // Would need to extract
                    createdAt: Date.now()
                }));
            }
        }

        const node: BLENode = {
            id: nodeId,
            name: `GhostNode-${nodeId.substring(0, 8)}`,
            identityKey: identityKey || new Uint8Array(32),
            encryptionKey: encryptionKey || new Uint8Array(32),
            preKeys,
            isConnected: false,
            lastSeen: Date.now(),
            firstSeen: Date.now(),
            rssi,
            distance,
            verificationStatus: VerificationStatus.UNVERIFIED,
            trustScore: 0,
            protocolVersion: ad.protocolVersion,
            capabilities: ad.capabilities,
            deviceType: ad.deviceType,
            supportedAlgorithms: [CryptoAlgorithm.ED25519, CryptoAlgorithm.X25519],
            isRelay: ad.capabilities.includes(NodeCapability.RELAY),
            bluetoothAddress: '', // Would get from platform
            batteryLevel: ad.batteryLevel,
            lastRSSI: 0,
            canSee: undefined
        };

        return node;
    }

    /**
     * Calculate trust score for a node
     */
    private calculateTrustScore(tracker: NodeTracker, scanResult: ScanResult): number {
        let score = 0;

        // Verification status (0-40 points)
        if (scanResult.isVerified) {
            score += 20;
        }
        if (tracker.node.verificationStatus === VerificationStatus.VERIFIED) {
            score += 10;
        }
        if (tracker.node.verificationStatus === VerificationStatus.TRUSTED) {
            score += 10;
        }

        // Signal stability (0-20 points)
        if (tracker.rssiHistory.length >= 5) {
            const variance = this.calculateVariance(tracker.rssiHistory);
            if (variance < 5) score += 20;
            else if (variance < 10) score += 10;
            else if (variance < 15) score += 5;
        }

        // Presence duration (0-20 points)
        const presenceDuration = Date.now() - tracker.node.firstSeen;
        if (presenceDuration > 3600000) score += 20; // 1 hour
        else if (presenceDuration > 600000) score += 10; // 10 minutes
        else if (presenceDuration > 60000) score += 5; // 1 minute

        // Advertisement consistency (0-20 points)
        const successRate = tracker.verificationAttempts > 0
            ? (tracker.verificationAttempts - this.statistics.verificationFailures) / tracker.verificationAttempts
            : 0;
        score += Math.floor(successRate * 20);

        return Math.min(100, score);
    }

    /**
     * Handle pre-key bundle
     */
    private async handlePreKeyBundle(
        node: BLENode,
        bundle: PreKeyBundle
    ): Promise<void> {
        // Update node keys
        node.identityKey = this.hexToBytes(bundle.identityKey);

        // Extract encryption key from signed pre-key
        node.encryptionKey = this.hexToBytes(bundle.signedPreKey.publicKey);

        // Store pre-keys if available
        if (bundle.oneTimePreKeys && bundle.oneTimePreKeys.length > 0) {
            node.preKeys = bundle.oneTimePreKeys.map(pk => ({
                keyId: pk.keyId,
                publicKey: this.hexToBytes(pk.publicKey),
                privateKey: new Uint8Array(0),
                signature: new Uint8Array(0),
                createdAt: Date.now()
            }));
        }

        console.log(`🔑 Updated keys for node ${node.id}`);
    }

    /**
     * Verify a node's identity
     */
    async verifyNode(
        nodeId: string,
        method: VerificationMethod,
        verificationData?: string
    ): Promise<VerificationResult> {
        const tracker = this.nodeTrackers.get(nodeId);
        if (!tracker) {
            throw new Error(`Node ${nodeId} not found`);
        }

        const result: VerificationResult = {
            verified: false,
            method,
            timestamp: Date.now()
        };

        tracker.verificationAttempts++;

        try {
            switch (method) {
                case VerificationMethod.FINGERPRINT:
                    result.verified = nodeId === verificationData;
                    break;

                case VerificationMethod.QR_CODE:
                    // QR code would contain node ID and public key
                    result.verified = await this.verifyQRCode(tracker.node, verificationData!);
                    break;

                case VerificationMethod.NUMERIC_COMPARISON:
                    // Generate numeric code from shared data
                    result.verified = await this.verifyNumericCode(tracker.node, verificationData!);
                    break;

                default:
                    throw new Error(`Unsupported verification method: ${method}`);
            }

            if (result.verified) {
                tracker.node.verificationStatus = VerificationStatus.VERIFIED;
                tracker.node.verifiedAt = Date.now();
                tracker.node.verificationMethod = method;
                tracker.lastVerified = Date.now();
                this.verifiedNodes.set(nodeId, result);
                this.statistics.nodesVerified++;

                console.log(`✅ Node ${nodeId} verified using ${method}`);
            }

            // Emit verification event
            this.emitVerificationEvent(nodeId, result);

        } catch (error) {
            console.error(`❌ Verification failed for ${nodeId}:`, error);
            result.verified = false;
        }

        return result;
    }

    /**
     * Block a node
     */
    blockNode(nodeId: string): void {
        this.blockedNodes.add(nodeId);

        // Remove from discovered nodes
        const tracker = this.nodeTrackers.get(nodeId);
        if (tracker) {
            this.removeNode(nodeId);
        }

        console.log(`🚫 Node ${nodeId} blocked`);
    }

    /**
     * Unblock a node
     */
    unblockNode(nodeId: string): void {
        this.blockedNodes.delete(nodeId);
        console.log(`✅ Node ${nodeId} unblocked`);
    }

    /**
     * Apply scan filters
     */
    private applyFilters(
        ad: BLEAdvertisementData,
        rssi: number,
        isVerified: boolean
    ): boolean {
        if (!this.scanConfig.filters || this.scanConfig.filters.length === 0) {
            return true;
        }

        for (const filter of this.scanConfig.filters) {
            // RSSI filter
            if (filter.minRssi && rssi < filter.minRssi) {
                continue;
            }

            // Verification filter
            if (filter.verifiedOnly && !isVerified) {
                continue;
            }

            // Capability filter
            if (filter.capabilities) {
                const hasAllCapabilities = filter.capabilities.every(cap =>
                    ad.capabilities.includes(cap)
                );
                if (!hasAllCapabilities) {
                    continue;
                }
            }

            // Filter passed
            return true;
        }

        return false;
    }

    /**
     * Check replay protection
     */
    private checkReplayProtection(nodeId: string, sequenceNumber: number): boolean {
        let sequences = this.replayProtection.get(nodeId);

        if (!sequences) {
            sequences = new Set();
            this.replayProtection.set(nodeId, sequences);
        }

        if (sequences.has(sequenceNumber)) {
            return false; // Replay detected
        }

        sequences.add(sequenceNumber);

        // Limit set size
        if (sequences.size > 1000) {
            const oldestSeq = Math.min(...sequences);
            sequences.delete(oldestSeq);
        }

        return true;
    }

    /**
     * Check discovery rate limit
     */
    private checkDiscoveryRateLimit(nodeId: string): boolean {
        const now = Date.now();
        const lastTime = this.discoveryRateLimit.get(nodeId) || 0;

        if (now - lastTime < 200) { // Max 5 discoveries per second per node
            return false;
        }

        this.discoveryRateLimit.set(nodeId, now);
        return true;
    }

    /**
     * Calculate distance from RSSI and TX power
     */
    private calculateDistance(rssi: number, txPower: number): number {
        // Path loss formula: Distance = 10^((TX Power - RSSI) / (10 * n))
        // n = path loss exponent (2 for free space, 2-4 for indoor)
        const pathLossExponent = 2.5;
        const distance = Math.pow(10, (txPower - rssi) / (10 * pathLossExponent));
        return Math.max(0.1, Math.min(100, distance)); // Clamp between 0.1m and 100m
    }

    /**
     * Update RSSI statistics
     */
    private updateRssiStatistics(rssi: number): void {
        // Update average
        this.statistics.averageRssi =
            (this.statistics.averageRssi * 0.95) + (rssi * 0.05);

        // Update extremes
        if (rssi > this.statistics.strongestSignal) {
            this.statistics.strongestSignal = rssi;
        }
        if (rssi < this.statistics.weakestSignal || this.statistics.weakestSignal === 0) {
            this.statistics.weakestSignal = rssi;
        }
    }

    /**
     * Remove a node
     */
    private removeNode(nodeId: string): void {
        const tracker = this.nodeTrackers.get(nodeId);
        if (!tracker) return;

        // Clean up ephemeral ID mappings
        for (const ephemeralId of tracker.ephemeralIds.keys()) {
            this.ephemeralIdMap.delete(ephemeralId);
        }

        // Remove tracker
        this.nodeTrackers.delete(nodeId);

        // Clean up other maps
        this.replayProtection.delete(nodeId);
        this.verifiedNodes.delete(nodeId);
        this.discoveryRateLimit.delete(nodeId);

        // Emit event
        const event: BLEDiscoveryEvent = {
            type: 'node_lost',
            node: tracker.node,
            rssi: tracker.node.rssi || -100,
            timestamp: Date.now()
        };

        this.emitDiscoveryEvent(event);

        console.log(`🗑️ Removed node: ${nodeId}`);
    }

    // ===== TIMER MANAGEMENT =====

    private startNodeTimeoutTimer(): void {
        this.nodeTimeoutTimer = setInterval(() => {
            this.checkForStaleNodes();
        }, BLE_CONFIG.NEIGHBOR_TIMEOUT / 4);
    }

    private stopNodeTimeoutTimer(): void {
        if (this.nodeTimeoutTimer) {
            clearInterval(this.nodeTimeoutTimer);
            this.nodeTimeoutTimer = undefined;
        }
    }

    private startVerificationTimer(): void {
        this.verificationTimer = setInterval(() => {
            this.performPeriodicVerification();
        }, 30000); // Every 30 seconds
    }

    private stopVerificationTimer(): void {
        if (this.verificationTimer) {
            clearInterval(this.verificationTimer);
            this.verificationTimer = undefined;
        }
    }

    private startCleanupTimer(): void {
        this.cleanupTimer = setInterval(() => {
            this.performCleanup();
        }, 60000); // Every minute
    }

    private stopCleanupTimer(): void {
        if (this.cleanupTimer) {
            clearInterval(this.cleanupTimer);
            this.cleanupTimer = undefined;
        }
    }

    private checkForStaleNodes(): void {
        const now = Date.now();

        for (const [nodeId, tracker] of this.nodeTrackers) {
            if (tracker.node.isConnected) {
                continue; // Don't remove connected nodes
            }

            const timeSinceLastSeen = now - tracker.node.lastSeen;
            if (timeSinceLastSeen > BLE_CONFIG.NEIGHBOR_TIMEOUT) {
                console.log(`⏰ Node ${nodeId} is stale, removing`);
                this.removeNode(nodeId);
            }
        }
    }

    private performPeriodicVerification(): void {
        // Re-verify nodes that haven't been verified recently
        const now = Date.now();

        for (const [nodeId, tracker] of this.nodeTrackers) {
            if (now - tracker.lastVerified > 300000) { // 5 minutes
                this.scheduleVerification(nodeId);
            }
        }
    }

    private scheduleVerification(nodeId: string): void {
        // Would trigger automatic verification
        console.log(`📝 Scheduled verification for ${nodeId}`);
    }

    private performCleanup(): void {
        // Clean up old data
        const now = Date.now();

        // Clean discovery rate limits
        for (const [nodeId, lastTime] of this.discoveryRateLimit) {
            if (now - lastTime > 60000) {
                this.discoveryRateLimit.delete(nodeId);
            }
        }

        // Clean signature cache
        if (this.signatureCache.size > 1000) {
            this.signatureCache.clear();
        }

        // Clean ephemeral ID mappings
        for (const [ephemeralId, nodeId] of this.ephemeralIdMap) {
            if (!this.nodeTrackers.has(nodeId)) {
                this.ephemeralIdMap.delete(ephemeralId);
            }
        }
    }

    // ===== HELPER METHODS =====

    private validateScanConfig(): void {
        if (this.scanConfig.interval < 100 || this.scanConfig.interval > 10000) {
            throw new Error('Scan interval must be between 100ms and 10s');
        }

        if (this.scanConfig.window > this.scanConfig.interval) {
            throw new Error('Scan window cannot exceed scan interval');
        }
    }

    private createSigningData(data: BLEAdvertisementData): Uint8Array {
        const parts = [
            data.ephemeralId,
            data.identityProof.publicKeyHash,
            data.identityProof.timestamp.toString(),
            data.identityProof.nonce,
            data.sequenceNumber.toString()
        ];

        return new TextEncoder().encode(parts.join('-'));
    }

    private async verifySignature(
        data: Uint8Array,
        signature: Uint8Array,
        publicKey: Uint8Array
    ): Promise<boolean> {
        // Would use Ed25519 verification
        return signature.length === 64; // Placeholder
    }

    private async verifyQRCode(node: BLENode, qrData: string): Promise<boolean> {
        // QR code verification logic
        return true;
    }

    private async verifyNumericCode(node: BLENode, code: string): Promise<boolean> {
        // Numeric code verification logic
        return true;
    }

    private parseCapabilityFlags(flags: number): NodeCapability[] {
        const capabilities: NodeCapability[] = [];

        if (flags & 0x01) capabilities.push(NodeCapability.RELAY);
        if (flags & 0x02) capabilities.push(NodeCapability.STORAGE);
        if (flags & 0x04) capabilities.push(NodeCapability.BRIDGE);
        if (flags & 0x08) capabilities.push(NodeCapability.GROUP_CHAT);
        if (flags & 0x10) capabilities.push(NodeCapability.FILE_TRANSFER);
        if (flags & 0x20) capabilities.push(NodeCapability.VOICE_NOTES);

        return capabilities;
    }

    private calculateVariance(values: number[]): number {
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
        return Math.sqrt(squaredDiffs.reduce((a, b) => a + b, 0) / values.length);
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

    // ===== CALLBACK MANAGEMENT =====

    private notifyScanCallbacks(result: ScanResult): void {
        for (const callback of this.scanCallbacks) {
            try {
                callback(result);
            } catch (error) {
                console.error('❌ Error in scan callback:', error);
            }
        }
    }

    private emitDiscoveryEvent(event: BLEDiscoveryEvent): void {
        for (const callback of this.discoveryCallbacks) {
            try {
                callback(event);
            } catch (error) {
                console.error('❌ Error in discovery callback:', error);
            }
        }
    }

    private emitVerificationEvent(nodeId: string, result: VerificationResult): void {
        for (const callback of this.verificationCallbacks) {
            try {
                callback(nodeId, result);
            } catch (error) {
                console.error('❌ Error in verification callback:', error);
            }
        }
    }

    // ===== PUBLIC API =====

    onScanResult(callback: ScanCallback): void {
        this.scanCallbacks.add(callback);
    }

    removeScanCallback(callback: ScanCallback): void {
        this.scanCallbacks.delete(callback);
    }

    onNodeDiscovery(callback: DiscoveryCallback): void {
        this.discoveryCallbacks.add(callback);
    }

    removeDiscoveryCallback(callback: DiscoveryCallback): void {
        this.discoveryCallbacks.delete(callback);
    }

    onVerification(callback: VerificationCallback): void {
        this.verificationCallbacks.add(callback);
    }

    removeVerificationCallback(callback: VerificationCallback): void {
        this.verificationCallbacks.delete(callback);
    }

    getDiscoveredNodes(): BLENode[] {
        return Array.from(this.nodeTrackers.values()).map(t => t.node);
    }

    getDiscoveredNode(nodeId: string): BLENode | undefined {
        return this.nodeTrackers.get(nodeId)?.node;
    }

    getVerifiedNodes(): BLENode[] {
        return Array.from(this.nodeTrackers.values())
            .filter(t => t.node.verificationStatus !== VerificationStatus.UNVERIFIED)
            .map(t => t.node);
    }

    getTrustedNodes(): BLENode[] {
        return Array.from(this.nodeTrackers.values())
            .filter(t => t.node.verificationStatus === VerificationStatus.TRUSTED)
            .map(t => t.node);
    }

    updateNodeConnectionStatus(nodeId: string, isConnected: boolean, connectionId?: string): void {
        const tracker = this.nodeTrackers.get(nodeId);
        if (tracker) {
            tracker.node.isConnected = isConnected;
            tracker.node.connectionId = connectionId;
            console.log(`🔗 Updated connection status for ${nodeId}: ${isConnected ? 'connected' : 'disconnected'}`);
        }
    }

    clearDiscoveredNodes(): void {
        console.log('🧹 Clearing all discovered nodes');

        // Clean up all mappings
        this.ephemeralIdMap.clear();
        this.nodeTrackers.clear();
        this.verifiedNodes.clear();
        this.replayProtection.clear();
        this.signatureCache.clear();
        this.discoveryRateLimit.clear();
    }

    getScanningStatus(): {
        isScanning: boolean;
        isPaused: boolean;
        nodeCount: number;
        verifiedCount: number;
        statistics: {
            totalScans: number;
            advertisementsReceived: number;
            nodesDiscovered: number;
            nodesVerified: number;
            verificationFailures: number;
            replaysDetected: number;
            duplicatesFiltered: number;
            averageRssi: number;
            strongestSignal: number;
            weakestSignal: number;
        };
    } {
        return {
            isScanning: this.isScanning,
            isPaused: this.isPaused,
            nodeCount: this.nodeTrackers.size,
            verifiedCount: this.getVerifiedNodes().length,
            statistics: { ...this.statistics }
        };
    }

    setKeyPair(keyPair: IGhostKeyPair): void {
        this.keyPair = keyPair;
    }
}