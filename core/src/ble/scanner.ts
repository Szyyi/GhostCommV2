// core/src/ble/scanner.ts
// Enhanced BLE Scanner with Protocol v2 cryptographic verification

import {
    BLENode,
    BLEAdvertisementData,
    BLEDiscoveryEvent,
    BLE_CONFIG,
    BLE_SECURITY_CONFIG,
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
 * Enhanced scan result with Protocol v2 security metadata
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
    protocolVersion: number;            // Protocol version detected
}

/**
 * Node tracking information with Protocol v2 enhancements
 */
interface NodeTracker {
    node: BLENode;
    advertisements: ScanResult[];        // Recent advertisements
    rssiHistory: number[];              // Signal strength history
    lastVerified: number;               // Last verification timestamp
    verificationAttempts: number;       // Verification attempt count
    trustScore: number;                 // Computed trust score
    ephemeralIds: Map<string, number>; // Seen ephemeral IDs
    publicKeyExtracted: boolean;        // Protocol v2: Public key extracted from ad
    publicKeyVerified: boolean;         // Protocol v2: Public key verified
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
    minProtocolVersion?: number;       // Minimum protocol version
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
    requireProtocolV2?: boolean;      // Require Protocol v2 nodes
}

// Callback types
export type ScanCallback = (result: ScanResult) => void;
export type DiscoveryCallback = (event: BLEDiscoveryEvent) => void;
export type VerificationCallback = (nodeId: string, result: VerificationResult) => void;

/**
 * Enhanced BLE Scanner with Protocol v2 security features
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

    // Protocol v2: Public key tracking
    private publicKeyCache: Map<string, {
        identityKey: Uint8Array;
        encryptionKey?: Uint8Array;
        timestamp: number;
    }>;

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
        weakestSignal: 0,
        protocolV2Nodes: 0,
        publicKeysExtracted: 0
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
        this.publicKeyCache = new Map();

        // Initialize callbacks
        this.scanCallbacks = new Set();
        this.discoveryCallbacks = new Set();
        this.verificationCallbacks = new Set();

        // Default scan configuration with Protocol v2 awareness
        this.scanConfig = {
            interval: BLE_CONFIG.SCAN_INTERVAL,
            window: BLE_CONFIG.SCAN_WINDOW,
            duplicates: false,
            activeScan: true,
            filters: [],
            requireProtocolV2: BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION
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
     * Start secure scanning with Protocol v2 verification
     */
    async startScanning(config?: Partial<ScanConfig>): Promise<void> {
        if (this.isScanning && !this.isPaused) {
            console.log('Already scanning');
            return;
        }

        try {
            console.log(`Starting secure BLE scanning (Protocol v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION} ${this.scanConfig.requireProtocolV2 ? 'required' : 'preferred'})`);

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
                    console.warn(`Too many filters (${this.scanConfig.filters.length}), using first ${capabilities.maxScanFilters}`);
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

            console.log('Secure BLE scanning started successfully');

        } catch (error) {
            console.error('Failed to start BLE scanning:', error);
            this.isScanning = false;
            throw error;
        }
    }

    /**
     * Handle scan result from platform with Protocol v2 verification
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
                console.warn('Failed to parse advertisement packet');
                return;
            }

            // Convert packet to advertisement data with Protocol v2 awareness
            const advertisementData = await this.packetToAdvertisementDataV2(packet);
            if (!advertisementData) {
                console.warn('Failed to convert packet to advertisement data');
                return;
            }

            // Check protocol version requirements
            if (this.scanConfig.requireProtocolV2 && advertisementData.version < BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                console.log(`Ignoring Protocol v${advertisementData.version} node (v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION} required)`);
                return;
            }

            // Check if node is blocked
            const nodeId = await this.resolveNodeId(advertisementData);
            if (this.blockedNodes.has(nodeId)) {
                console.log(`Blocked node detected: ${nodeId}`);
                return;
            }

            // Protocol v2: Extract and cache public key if available
            let publicKeyExtracted = false;
            if (packet.publicKey && advertisementData.version >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                this.cachePublicKey(nodeId, packet.publicKey, packet);
                publicKeyExtracted = true;
                this.statistics.publicKeysExtracted++;
            }

            // Verify advertisement signature with Protocol v2
            const isVerified = await this.verifyAdvertisementV2(advertisementData, packet, nodeId);

            // Check replay protection
            if (!this.checkReplayProtection(nodeId, advertisementData.sequenceNumber)) {
                console.warn(`Replay detected from ${nodeId}`);
                this.statistics.replaysDetected++;
                return;
            }

            // Apply filters
            if (!this.applyFilters(advertisementData, rssi, isVerified)) {
                return;
            }

            // Check rate limiting
            if (!this.checkDiscoveryRateLimit(nodeId)) {
                console.warn(`Discovery rate limit exceeded for ${nodeId}`);
                return;
            }

            // Calculate distance if TX power available
            const distance = txPower ? this.calculateDistance(rssi, txPower) : undefined;

            // Create scan result with Protocol v2 info
            const scanResult: ScanResult = {
                deviceId,
                advertisementData,
                rssi,
                txPower,
                distance,
                timestamp: Date.now(),
                rawData,
                isVerified,
                verificationError: isVerified ? undefined : 'Signature verification failed',
                protocolVersion: advertisementData.version
            };

            // Notify scan callbacks
            this.notifyScanCallbacks(scanResult);

            // Update node discovery with Protocol v2 tracking
            await this.updateNodeDiscoveryV2(scanResult, nodeId, publicKeyExtracted);

        } catch (error) {
            console.error('Error handling scan result:', error);
        }
    }

    /**
     * Convert packet to advertisement data with Protocol v2 support
     */
    private async packetToAdvertisementDataV2(packet: any): Promise<BLEAdvertisementData | null> {
        try {
            // Parse extended data if present
            let preKeyBundle: PreKeyBundle | undefined;
            let extendedInfo: any = {};
            
            if (packet.extendedData) {
                try {
                    const extendedStr = new TextDecoder().decode(packet.extendedData);
                    const extended = JSON.parse(extendedStr);
                    
                    if (extended.preKeyBundle) {
                        preKeyBundle = extended.preKeyBundle;
                    }
                    
                    // Protocol v2: Extract additional info
                    if (extended.supportedAlgorithms) {
                        extendedInfo.supportedAlgorithms = extended.supportedAlgorithms;
                    }
                    if (extended.protocolRequirements) {
                        extendedInfo.protocolRequirements = extended.protocolRequirements;
                    }
                } catch {
                    // Extended data might not be JSON
                }
            }

            // Create identity proof with Protocol v2 public key
            const identityProof: IdentityProof = {
                publicKeyHash: this.bytesToHex(packet.identityHash),
                ...(packet.publicKey && { publicKey: this.bytesToHex(packet.publicKey) }), // Protocol v2
                timestamp: packet.timestamp * 1000, // Convert to ms
                nonce: this.bytesToHex(packet.ephemeralId).substring(0, 32),
                signature: this.bytesToHex(packet.signature),
                preKeyBundle
            };

            // Parse capabilities from flags
            const capabilities = this.parseCapabilityFlags(packet.flags);

            // Detect protocol version
            const protocolVersion = packet.meshInfo?.protocolVersion || packet.version;

            // Create advertisement data
            const advertisementData: BLEAdvertisementData = {
                version: packet.version,
                ephemeralId: this.bytesToHex(packet.ephemeralId),
                identityProof,
                timestamp: packet.timestamp * 1000,
                sequenceNumber: packet.sequenceNumber,
                capabilities,
                deviceType: DeviceType.PHONE, // Would determine from flags
                protocolVersion,
                meshInfo: {
                    nodeCount: packet.meshInfo.nodeCount,
                    messageQueueSize: packet.meshInfo.queueSize,
                    routingTableVersion: 0,
                    beaconInterval: BLE_CONFIG.ADVERTISEMENT_INTERVAL
                },
                batteryLevel: packet.meshInfo.batteryLevel
            };

            // Track Protocol v2 nodes
            if (protocolVersion >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                this.statistics.protocolV2Nodes++;
            }

            return advertisementData;

        } catch (error) {
            console.error('Error converting packet to advertisement data:', error);
            return null;
        }
    }

    /**
     * Cache public key from Protocol v2 advertisement
     */
    private cachePublicKey(nodeId: string, publicKeyBytes: Uint8Array, packet: any): void {
        // Store the full public key for future verification
        this.publicKeyCache.set(nodeId, {
            identityKey: publicKeyBytes,
            encryptionKey: packet.encryptionKey, // If available
            timestamp: Date.now()
        });
        
        console.log(`Cached public key for node ${nodeId} from Protocol v2 advertisement`);
    }

    /**
     * Verify advertisement signature with Protocol v2 requirements
     */
    private async verifyAdvertisementV2(
        data: BLEAdvertisementData,
        packet: any,
        nodeId: string
    ): Promise<boolean> {
        try {
            // Check signature cache
            const cacheKey = `${data.ephemeralId}-${data.sequenceNumber}`;
            const cached = this.signatureCache.get(cacheKey);
            if (cached !== undefined) {
                return cached;
            }

            // Protocol v2: Get public key from advertisement or cache
            let publicKey: Uint8Array | undefined;
            
            if (data.identityProof.publicKey) {
                // Public key included in advertisement (Protocol v2)
                publicKey = this.hexToBytes(data.identityProof.publicKey);
            } else if (packet.publicKey) {
                // Public key in packet
                publicKey = packet.publicKey;
            } else {
                // Try to get from cache or node tracker
                const cachedKey = this.publicKeyCache.get(nodeId);
                if (cachedKey) {
                    publicKey = cachedKey.identityKey;
                } else {
                    const tracker = this.nodeTrackers.get(nodeId);
                    if (tracker?.node.identityKey) {
                        publicKey = tracker.node.identityKey;
                    }
                }
            }

            if (!publicKey) {
                // Can't verify without public key
                if (BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION) {
                    console.warn(`Cannot verify advertisement from ${nodeId} - no public key available`);
                }
                this.signatureCache.set(cacheKey, false);
                return false;
            }

            // Recreate signing data with Protocol v2 format
            const signingData = this.createSigningDataV2(data);

            // Verify signature
            const signature = this.hexToBytes(data.identityProof.signature);
            const isValid = await this.verifySignature(
                signingData,
                signature,
                publicKey
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
            console.error('Error verifying advertisement:', error);
            return false;
        }
    }

    /**
     * Create signing data with Protocol v2 format
     */
    private createSigningDataV2(data: BLEAdvertisementData): Uint8Array {
        const parts = [
            data.ephemeralId,
            data.identityProof.publicKeyHash,
            data.identityProof.publicKey || '', // Include public key for v2
            data.identityProof.timestamp.toString(),
            data.identityProof.nonce,
            data.sequenceNumber.toString(),
            data.version.toString()
        ];

        return new TextEncoder().encode(parts.join('-'));
    }

    /**
     * Update node discovery with Protocol v2 tracking
     */
    private async updateNodeDiscoveryV2(
        scanResult: ScanResult,
        nodeId: string,
        publicKeyExtracted: boolean
    ): Promise<void> {
        const { advertisementData, rssi, distance } = scanResult;

        // Get or create tracker
        let tracker = this.nodeTrackers.get(nodeId);
        const isNewNode = !tracker;

        if (!tracker) {
            // Create new node with Protocol v2 awareness
            const node: BLENode = await this.createNodeFromAdvertisementV2(
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
                ephemeralIds: new Map(),
                publicKeyExtracted: false,
                publicKeyVerified: false
            };

            this.nodeTrackers.set(nodeId, tracker);
            this.statistics.nodesDiscovered++;
        }

        // Update Protocol v2 tracking
        if (publicKeyExtracted && !tracker.publicKeyExtracted) {
            tracker.publicKeyExtracted = true;
            
            // Update node keys from cache
            const cachedKeys = this.publicKeyCache.get(nodeId);
            if (cachedKeys) {
                tracker.node.identityKey = cachedKeys.identityKey;
                if (cachedKeys.encryptionKey) {
                    tracker.node.encryptionKey = cachedKeys.encryptionKey;
                }
                tracker.node.keysValidatedAt = cachedKeys.timestamp;
                tracker.node.keyValidationMethod = 'advertisement';
            }
        }

        // Mark as verified if signature was valid
        if (scanResult.isVerified && !tracker.publicKeyVerified) {
            tracker.publicKeyVerified = true;
            tracker.lastVerified = Date.now();
        }

        // Update tracker
        tracker.node.lastSeen = Date.now();
        tracker.node.rssi = rssi;
        tracker.node.lastRSSI = rssi;
        tracker.node.distance = distance;
        tracker.node.protocolVersion = advertisementData.protocolVersion;

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

        // Update trust score with Protocol v2 bonus
        tracker.trustScore = this.calculateTrustScoreV2(tracker, scanResult);
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
            console.log(`Discovered new node: ${nodeId} (Protocol v${advertisementData.protocolVersion}, RSSI: ${rssi}dBm, Distance: ${distance?.toFixed(1)}m)`);

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
     * Create node from advertisement with Protocol v2 awareness
     */
    private async createNodeFromAdvertisementV2(
        nodeId: string,
        ad: BLEAdvertisementData,
        rssi: number,
        distance?: number
    ): Promise<BLENode> {
        // Extract keys from advertisement or cache
        let identityKey: Uint8Array | undefined;
        let encryptionKey: Uint8Array | undefined;
        let preKeys: PreKey[] | undefined;

        // Protocol v2: Check for public key in advertisement
        if (ad.identityProof.publicKey) {
            identityKey = this.hexToBytes(ad.identityProof.publicKey);
        }

        // Check cache
        const cachedKeys = this.publicKeyCache.get(nodeId);
        if (cachedKeys) {
            identityKey = identityKey || cachedKeys.identityKey;
            encryptionKey = cachedKeys.encryptionKey;
        }

        // Extract from pre-key bundle if available
        if (ad.identityProof.preKeyBundle) {
            identityKey = identityKey || this.hexToBytes(ad.identityProof.preKeyBundle.identityKey);
            encryptionKey = encryptionKey || this.hexToBytes(ad.identityProof.preKeyBundle.signedPreKey.publicKey);

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
            keysValidatedAt: identityKey ? Date.now() : undefined,
            keyValidationMethod: identityKey ? 'advertisement' : undefined,
            isConnected: false,
            lastSeen: Date.now(),
            firstSeen: Date.now(),
            rssi,
            lastRSSI: rssi,
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
            canSee: undefined
        };

        return node;
    }

    /**
     * Calculate trust score with Protocol v2 bonus
     */
    private calculateTrustScoreV2(tracker: NodeTracker, scanResult: ScanResult): number {
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

        // Protocol v2 bonus (0-10 points)
        if (scanResult.protocolVersion >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            score += 5;
        }
        if (tracker.publicKeyExtracted) {
            score += 3;
        }
        if (tracker.publicKeyVerified) {
            score += 2;
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

        // Advertisement consistency (0-10 points)
        const successRate = tracker.verificationAttempts > 0
            ? (tracker.verificationAttempts - this.statistics.verificationFailures) / tracker.verificationAttempts
            : 0;
        score += Math.floor(successRate * 10);

        return Math.min(100, score);
    }

    // ... [Include all other methods from original scanner.ts] ...

    /**
     * Stop scanning
     */
    async stopScanning(): Promise<void> {
        if (!this.isScanning) {
            return;
        }

        try {
            console.log('Stopping BLE scanning...');

            await this.stopPlatformScanning();

            this.stopNodeTimeoutTimer();
            this.stopVerificationTimer();

            this.isScanning = false;
            this.isPaused = false;

            console.log('BLE scanning stopped');

        } catch (error) {
            console.error('Failed to stop BLE scanning:', error);
            throw error;
        }
    }

    /**
     * Resolve node ID from advertisement
     */
    private async resolveNodeId(data: BLEAdvertisementData): Promise<string> {
        const existingNodeId = this.ephemeralIdMap.get(data.ephemeralId);
        if (existingNodeId) {
            return existingNodeId;
        }

        for (const [nodeId, tracker] of this.nodeTrackers) {
            const nodeFingerprint = tracker.node.id;
            if (nodeFingerprint.startsWith(data.identityProof.publicKeyHash)) {
                this.ephemeralIdMap.set(data.ephemeralId, nodeId);
                return nodeId;
            }
        }

        const nodeId = data.identityProof.publicKeyHash;
        this.ephemeralIdMap.set(data.ephemeralId, nodeId);
        return nodeId;
    }

    private async verifySignature(
        data: Uint8Array,
        signature: Uint8Array,
        publicKey: Uint8Array
    ): Promise<boolean> {
        if (this.keyPair) {
            return this.keyPair.verifySignature(data, signature, publicKey);
        }
        return false;
    }

    private handlePreKeyBundle(node: BLENode, bundle: PreKeyBundle): Promise<void> {
        node.identityKey = this.hexToBytes(bundle.identityKey);
        node.encryptionKey = this.hexToBytes(bundle.signedPreKey.publicKey);

        if (bundle.oneTimePreKeys && bundle.oneTimePreKeys.length > 0) {
            node.preKeys = bundle.oneTimePreKeys.map(pk => ({
                keyId: pk.keyId,
                publicKey: this.hexToBytes(pk.publicKey),
                privateKey: new Uint8Array(0),
                signature: new Uint8Array(0),
                createdAt: Date.now()
            }));
        }

        console.log(`Updated keys for node ${node.id}`);
        return Promise.resolve();
    }

    // Include all timer, filter, and utility methods...
    private checkReplayProtection(nodeId: string, sequenceNumber: number): boolean {
        let sequences = this.replayProtection.get(nodeId);

        if (!sequences) {
            sequences = new Set();
            this.replayProtection.set(nodeId, sequences);
        }

        if (sequences.has(sequenceNumber)) {
            return false;
        }

        sequences.add(sequenceNumber);

        if (sequences.size > 1000) {
            const oldestSeq = Math.min(...sequences);
            sequences.delete(oldestSeq);
        }

        return true;
    }

    private applyFilters(
        ad: BLEAdvertisementData,
        rssi: number,
        isVerified: boolean
    ): boolean {
        if (!this.scanConfig.filters || this.scanConfig.filters.length === 0) {
            return true;
        }

        for (const filter of this.scanConfig.filters) {
            if (filter.minRssi && rssi < filter.minRssi) {
                continue;
            }

            if (filter.verifiedOnly && !isVerified) {
                continue;
            }

            if (filter.minProtocolVersion && ad.protocolVersion < filter.minProtocolVersion) {
                continue;
            }

            if (filter.capabilities) {
                const hasAllCapabilities = filter.capabilities.every(cap =>
                    ad.capabilities.includes(cap)
                );
                if (!hasAllCapabilities) {
                    continue;
                }
            }

            return true;
        }

        return false;
    }

    private checkDiscoveryRateLimit(nodeId: string): boolean {
        const now = Date.now();
        const lastTime = this.discoveryRateLimit.get(nodeId) || 0;

        if (now - lastTime < 200) {
            return false;
        }

        this.discoveryRateLimit.set(nodeId, now);
        return true;
    }

    private calculateDistance(rssi: number, txPower: number): number {
        const pathLossExponent = 2.5;
        const distance = Math.pow(10, (txPower - rssi) / (10 * pathLossExponent));
        return Math.max(0.1, Math.min(100, distance));
    }

    private updateRssiStatistics(rssi: number): void {
        this.statistics.averageRssi =
            (this.statistics.averageRssi * 0.95) + (rssi * 0.05);

        if (rssi > this.statistics.strongestSignal) {
            this.statistics.strongestSignal = rssi;
        }
        if (rssi < this.statistics.weakestSignal || this.statistics.weakestSignal === 0) {
            this.statistics.weakestSignal = rssi;
        }
    }

    private validateScanConfig(): void {
        if (this.scanConfig.interval < 100 || this.scanConfig.interval > 10000) {
            throw new Error('Scan interval must be between 100ms and 10s');
        }

        if (this.scanConfig.window > this.scanConfig.interval) {
            throw new Error('Scan window cannot exceed scan interval');
        }
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

    // Timers
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
        }, 30000);
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
        }, 60000);
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
                continue;
            }

            const timeSinceLastSeen = now - tracker.node.lastSeen;
            if (timeSinceLastSeen > BLE_CONFIG.NEIGHBOR_TIMEOUT) {
                console.log(`Node ${nodeId} is stale, removing`);
                this.removeNode(nodeId);
            }
        }
    }

    private performPeriodicVerification(): void {
        const now = Date.now();

        for (const [nodeId, tracker] of this.nodeTrackers) {
            if (now - tracker.lastVerified > 300000) {
                this.scheduleVerification(nodeId);
            }
        }
    }

    private scheduleVerification(nodeId: string): void {
        console.log(`Scheduled verification for ${nodeId}`);
    }

    private performCleanup(): void {
        const now = Date.now();

        for (const [nodeId, lastTime] of this.discoveryRateLimit) {
            if (now - lastTime > 60000) {
                this.discoveryRateLimit.delete(nodeId);
            }
        }

        if (this.signatureCache.size > 1000) {
            this.signatureCache.clear();
        }

        for (const [ephemeralId, nodeId] of this.ephemeralIdMap) {
            if (!this.nodeTrackers.has(nodeId)) {
                this.ephemeralIdMap.delete(ephemeralId);
            }
        }

        // Clean old public key cache entries
        for (const [nodeId, entry] of this.publicKeyCache) {
            if (now - entry.timestamp > 3600000) { // 1 hour
                this.publicKeyCache.delete(nodeId);
            }
        }
    }

    private removeNode(nodeId: string): void {
        const tracker = this.nodeTrackers.get(nodeId);
        if (!tracker) return;

        for (const ephemeralId of tracker.ephemeralIds.keys()) {
            this.ephemeralIdMap.delete(ephemeralId);
        }

        this.nodeTrackers.delete(nodeId);
        this.replayProtection.delete(nodeId);
        this.verifiedNodes.delete(nodeId);
        this.discoveryRateLimit.delete(nodeId);
        this.publicKeyCache.delete(nodeId);

        const event: BLEDiscoveryEvent = {
            type: 'node_lost',
            node: tracker.node,
            rssi: tracker.node.rssi || -100,
            timestamp: Date.now()
        };

        this.emitDiscoveryEvent(event);

        console.log(`Removed node: ${nodeId}`);
    }

    // Callbacks
    private notifyScanCallbacks(result: ScanResult): void {
        for (const callback of this.scanCallbacks) {
            try {
                callback(result);
            } catch (error) {
                console.error('Error in scan callback:', error);
            }
        }
    }

    private emitDiscoveryEvent(event: BLEDiscoveryEvent): void {
        for (const callback of this.discoveryCallbacks) {
            try {
                callback(event);
            } catch (error) {
                console.error('Error in discovery callback:', error);
            }
        }
    }

    private emitVerificationEvent(nodeId: string, result: VerificationResult): void {
        for (const callback of this.verificationCallbacks) {
            try {
                callback(nodeId, result);
            } catch (error) {
                console.error('Error in verification callback:', error);
            }
        }
    }

    // Public API
    onScanResult(callback: ScanCallback): void {
        this.scanCallbacks.add(callback);
    }

    onNodeDiscovery(callback: DiscoveryCallback): void {
        this.discoveryCallbacks.add(callback);
    }

    getDiscoveredNodes(): BLENode[] {
        return Array.from(this.nodeTrackers.values()).map(t => t.node);
    }

    getDiscoveredNode(nodeId: string): BLENode | undefined {
        return this.nodeTrackers.get(nodeId)?.node;
    }

    getScanningStatus(): {
        isScanning: boolean;
        isPaused: boolean;
        nodeCount: number;
        verifiedCount: number;
        protocolV2Count: number;
        statistics: any;
    } {
        const protocolV2Count = Array.from(this.nodeTrackers.values())
            .filter(t => t.node.protocolVersion >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION).length;

        return {
            isScanning: this.isScanning,
            isPaused: this.isPaused,
            nodeCount: this.nodeTrackers.size,
            verifiedCount: this.getVerifiedNodes().length,
            protocolV2Count,
            statistics: { ...this.statistics }
        };
    }

    private getVerifiedNodes(): BLENode[] {
        return Array.from(this.nodeTrackers.values())
            .filter(t => t.node.verificationStatus !== VerificationStatus.UNVERIFIED)
            .map(t => t.node);
    }

    setKeyPair(keyPair: IGhostKeyPair): void {
        this.keyPair = keyPair;
    }
}