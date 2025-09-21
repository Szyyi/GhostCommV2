// core/src/ble/scanner.ts
// ================================================================================================
// BLE Scanner with Protocol v2.1 Cryptographic Verification and Discovery
// ================================================================================================
//
// This module implements the secure BLE scanning and node discovery layer for the GhostComm
// mesh network system. It provides comprehensive node discovery, cryptographic verification,
// and Protocol v2.1 security validation for all discovered mesh participants.
//
// @author LCpl Szymon 'Si' Procak
// @version 2.1

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
    RelayStatistics,
    ScanResult,
    ScanConfig,
    ScanFilter
} from './types';
import {
    IGhostKeyPair,
    PreKey,
    CryptoAlgorithm
} from '../types/crypto';
import { BLEAdvertiser } from './advertiser';

/**
 * Node tracking information with Protocol v2.1 enhancements and trust management
 */
interface NodeTracker {
    node: BLENode;
    advertisements: ScanResult[];
    rssiHistory: number[];
    lastVerified: number;
    verificationAttempts: number;
    trustScore: number;
    ephemeralIds: Map<string, number>;
    publicKeyExtracted: boolean;
    publicKeyVerified: boolean;
}

// Callback types
export type ScanCallback = (result: ScanResult) => void;
export type DiscoveryCallback = (event: BLEDiscoveryEvent) => void;
export type VerificationCallback = (nodeId: string, result: VerificationResult) => void;




/**
 * Enhanced BLE Scanner with Protocol v2.1 Security Features and Intelligent Discovery
 */
export abstract class BLEScanner {
    // ===== OPERATIONAL STATE MANAGEMENT =====
    private isScanning: boolean = false;
    private isPaused: boolean = false;
    private scanConfig: ScanConfig;

    // ===== NODE TRACKING AND DISCOVERY STATE =====
    private nodeTrackers: Map<string, NodeTracker>;
    private ephemeralIdMap: Map<string, string>;
    private verifiedNodes: Map<string, VerificationResult>;
    private blockedNodes: Set<string>;

    // ===== PROTOCOL v2 CRYPTOGRAPHIC STATE =====
    private publicKeyCache: Map<string, {
        identityKey: Uint8Array;
        encryptionKey?: Uint8Array;
        timestamp: number;
    }>;

    // ===== SECURITY VALIDATION COMPONENTS =====
    protected keyPair?: IGhostKeyPair;
    private replayProtection: Map<string, Set<number>>;
    private signatureCache: Map<string, boolean>;

    // ===== EVENT HANDLING AND CALLBACKS =====
    private scanCallbacks: Set<ScanCallback>;
    private discoveryCallbacks: Set<DiscoveryCallback>;
    private verificationCallbacks: Set<VerificationCallback>;

    // ===== OPERATIONAL TIMERS AND MAINTENANCE =====
    private nodeTimeoutTimer?: NodeJS.Timeout;
    private verificationTimer?: NodeJS.Timeout;
    // Changed from private to protected to allow subclass access
    protected cleanupTimer?: NodeJS.Timeout;

    // ===== PERFORMANCE AND RATE LIMITING =====
    private discoveryRateLimit: Map<string, number>;
    private lastDiscoveryTime: number = 0;

    // ===== PERFORMANCE STATISTICS AND MONITORING =====
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

    /**
     * Initialize BLE scanner with comprehensive security and discovery capabilities
     */
    constructor(keyPair?: IGhostKeyPair) {
        this.keyPair = keyPair;

        // Initialize tracking data structures
        this.nodeTrackers = new Map();
        this.ephemeralIdMap = new Map();
        this.verifiedNodes = new Map();
        this.blockedNodes = new Set();
        this.replayProtection = new Map();
        this.signatureCache = new Map();
        this.discoveryRateLimit = new Map();
        this.publicKeyCache = new Map();

        // Initialize callback management
        this.scanCallbacks = new Set();
        this.discoveryCallbacks = new Set();
        this.verificationCallbacks = new Set();

        // Establish default scan configuration optimized for Protocol v2
        this.scanConfig = {
            interval: BLE_CONFIG.SCAN_INTERVAL,
            window: BLE_CONFIG.SCAN_WINDOW,
            duplicates: false,
            activeScan: true,
            filters: [],
            requireProtocolV2: BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION,
            // React Native specific defaults
            filterByService: false,
            lowPower: false,
            aggressive: false,
            singleDevice: false,
            batchResults: false,
            dutyCycle: false
        };

        // Initialize maintenance systems
        this.startCleanupTimer();
    }

    // ===== PLATFORM ABSTRACTION LAYER =====
    protected abstract startPlatformScanning(config: ScanConfig): Promise<void>;
    protected abstract stopPlatformScanning(): Promise<void>;
    protected abstract setPlatformScanFilters(filters: ScanFilter[]): Promise<void>;
    protected abstract checkPlatformCapabilities(): Promise<{
        maxScanFilters: number;
        supportsActiveScan: boolean;
        supportsContinuousScan: boolean;
        supportsBackgroundScan: boolean;
    }>;

    // ===== CORE DISCOVERY OPERATIONS =====

    /**
     * Start comprehensive BLE scanning with Protocol v2.1 security verification
     */
    async startScanning(config?: Partial<ScanConfig>): Promise<void> {
        if (this.isScanning && !this.isPaused) {
            console.log('Already scanning');
            return;
        }

        try {
            console.log(`Starting secure BLE scanning (Protocol v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION} ${this.scanConfig.requireProtocolV2 ? 'required' : 'preferred'})`);

            // Merge provided configuration with existing defaults
            if (config) {
                this.scanConfig = { ...this.scanConfig, ...config };
            }

            // Validate merged configuration
            this.validateScanConfig();

            // Query platform capabilities
            const capabilities = await this.checkPlatformCapabilities();

            // Configure scan filters
            if (this.scanConfig.filters && this.scanConfig.filters.length > 0) {
                if (this.scanConfig.filters.length > capabilities.maxScanFilters) {
                    console.warn(`Too many filters (${this.scanConfig.filters.length}), using first ${capabilities.maxScanFilters}`);
                    this.scanConfig.filters = this.scanConfig.filters.slice(0, capabilities.maxScanFilters);
                }
                await this.setPlatformScanFilters(this.scanConfig.filters);
            }

            // Initialize platform-specific BLE scanning
            await this.startPlatformScanning(this.scanConfig);

            // Update operational state
            this.isScanning = true;
            this.isPaused = false;

            // Start maintenance timers
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
     * Process discovered BLE advertisements with Protocol v2.1 verification
     */
    protected async handleScanResult(
        deviceId: string,
        rawData: Uint8Array,
        rssi: number,
        txPower?: number
    ): Promise<void> {
        try {
            this.statistics.advertisementsReceived++;
            this.updateRssiStatistics(rssi);

            // Parse raw advertisement data
            const packet = BLEAdvertiser.parseAdvertisementPacket(rawData);
            if (!packet) {
                console.warn('Failed to parse advertisement packet');
                return;
            }

            // Convert to Protocol v2-aware advertisement structure
            const advertisementData = await this.packetToAdvertisementDataV2(packet);
            if (!advertisementData) {
                console.warn('Failed to convert packet to advertisement data');
                return;
            }

            // Enforce Protocol v2 requirements if configured
            if (this.scanConfig.requireProtocolV2 && advertisementData.version < BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                console.log(`Ignoring Protocol v${advertisementData.version} node (v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION} required)`);
                return;
            }

            // Resolve node identity
            const nodeId = await this.resolveNodeId(advertisementData);
            
            // Check blacklist
            if (this.blockedNodes.has(nodeId)) {
                console.log(`Blocked node detected: ${nodeId}`);
                return;
            }

            // Extract and cache public key
            let publicKeyExtracted = false;
            if (packet.publicKey && advertisementData.version >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                this.cachePublicKey(nodeId, packet.publicKey, packet);
                publicKeyExtracted = true;
                this.statistics.publicKeysExtracted++;
            }

            // Verify advertisement signature
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

            // Check discovery rate limit
            if (!this.checkDiscoveryRateLimit(nodeId)) {
                console.warn(`Discovery rate limit exceeded for ${nodeId}`);
                return;
            }

            // Calculate distance
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
                verificationError: isVerified ? undefined : 'Signature verification failed',
                protocolVersion: advertisementData.version
            };

            // Notify callbacks
            this.notifyScanCallbacks(scanResult);

            // Update node discovery
            await this.updateNodeDiscoveryV2(scanResult, nodeId, publicKeyExtracted);

        } catch (error) {
            console.error('Error handling scan result:', error);
        }
    }

    /**
     * Emit scan error to discovery callbacks
     * This method was missing and causing TypeScript errors
     */
    protected emitScanError(error: {
        code: string;
        message: string;
        timestamp: number;
    }): void {
        console.error(`[BLE Scanner Error] ${error.code}: ${error.message}`);
        
        // Create error event - you might want to extend BLEDiscoveryEvent to support error type
        const errorEvent: BLEDiscoveryEvent = {
            type: 'node_lost', // Using existing type, ideally add 'error' type
            node: {
                id: 'error',
                name: 'Error Node',
                identityKey: new Uint8Array(32),
                encryptionKey: new Uint8Array(32),
                isConnected: false,
                lastSeen: error.timestamp,
                firstSeen: error.timestamp,
                rssi: -100,
                lastRSSI: -100,
                verificationStatus: VerificationStatus.UNVERIFIED,
                trustScore: 0,
                protocolVersion: 0,
                capabilities: [],
                deviceType: DeviceType.PHONE,
                supportedAlgorithms: [],
                isRelay: false,
                bluetoothAddress: '',
                canSee: undefined
            } as BLENode,
            rssi: -100,
            timestamp: error.timestamp
        };
        
        // Notify all discovery callbacks about the error
        for (const callback of this.discoveryCallbacks) {
            try {
                callback(errorEvent);
            } catch (err) {
                console.error('Error in discovery callback:', err);
            }
        }
    }

    /**
     * Convert parsed advertisement packet to Protocol v2-aware advertisement data
     */
    private async packetToAdvertisementDataV2(packet: any): Promise<BLEAdvertisementData | null> {
        try {
            let preKeyBundle: PreKeyBundle | undefined;
            let extendedInfo: any = {};
            
            if (packet.extendedData) {
                try {
                    const extendedStr = new TextDecoder().decode(packet.extendedData);
                    const extended = JSON.parse(extendedStr);
                    
                    if (extended.preKeyBundle) {
                        preKeyBundle = extended.preKeyBundle;
                    }
                    
                    if (extended.supportedAlgorithms) {
                        extendedInfo.supportedAlgorithms = extended.supportedAlgorithms;
                    }
                    if (extended.protocolRequirements) {
                        extendedInfo.protocolRequirements = extended.protocolRequirements;
                    }
                } catch {
                    // Extended data parsing failed, continue with base data
                }
            }

            const identityProof: IdentityProof = {
                publicKeyHash: this.bytesToHex(packet.identityHash),
                publicKey: packet.publicKey ? this.bytesToHex(packet.publicKey) : undefined,
                timestamp: packet.timestamp * 1000,
                nonce: this.bytesToHex(packet.ephemeralId).substring(0, 32),
                signature: this.bytesToHex(packet.signature),
                preKeyBundle
            };

            const capabilities = this.parseCapabilityFlags(packet.flags);
            const protocolVersion = packet.meshInfo?.protocolVersion || packet.version;

            const advertisementData: BLEAdvertisementData = {
                version: packet.version,
                ephemeralId: this.bytesToHex(packet.ephemeralId),
                identityProof,
                timestamp: packet.timestamp * 1000,
                sequenceNumber: packet.sequenceNumber,
                capabilities,
                deviceType: DeviceType.PHONE,
                protocolVersion,
                meshInfo: {
                    nodeCount: packet.meshInfo.nodeCount,
                    messageQueueSize: packet.meshInfo.queueSize,
                    routingTableVersion: 0,
                    beaconInterval: BLE_CONFIG.ADVERTISEMENT_INTERVAL
                },
                batteryLevel: packet.meshInfo.batteryLevel
            };

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
     * Cache public key from Protocol v2+ advertisement
     */
    private cachePublicKey(nodeId: string, publicKeyBytes: Uint8Array, packet: any): void {
        this.publicKeyCache.set(nodeId, {
            identityKey: publicKeyBytes,
            encryptionKey: packet.encryptionKey,
            timestamp: Date.now()
        });
        
        console.log(`Cached public key for node ${nodeId} from Protocol v${packet.version} advertisement`);
    }

    /**
     * Verify advertisement signature with Protocol v2+ validation
     */
    private async verifyAdvertisementV2(
        data: BLEAdvertisementData,
        packet: any,
        nodeId: string
    ): Promise<boolean> {
        try {
            if (data.version < BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                return true;
            }

            const cacheKey = `${data.ephemeralId}-${data.sequenceNumber}`;
            const cached = this.signatureCache.get(cacheKey);
            if (cached !== undefined) {
                return cached;
            }

            let publicKey: Uint8Array | undefined;
            
            if (data.identityProof.publicKey) {
                publicKey = this.hexToBytes(data.identityProof.publicKey);
            } else if (packet.publicKey) {
                publicKey = packet.publicKey;
            } else {
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
                if (BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION) {
                    console.warn(`Cannot verify advertisement from ${nodeId} - no public key available`);
                }
                this.signatureCache.set(cacheKey, false);
                return false;
            }

            const signingData = this.createSigningDataV2(data);
            const signature = this.hexToBytes(data.identityProof.signature);
            const isValid = await this.verifySignature(signingData, signature, publicKey);

            this.signatureCache.set(cacheKey, isValid);

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
     * Create signing data for Protocol v2.1 signature verification
     */
    private createSigningDataV2(data: BLEAdvertisementData): Uint8Array {
        const parts = [
            data.ephemeralId,
            data.identityProof.publicKeyHash,
            data.identityProof.publicKey || '',
            data.identityProof.timestamp.toString(),
            data.identityProof.nonce,
            data.sequenceNumber.toString(),
            data.version.toString()
        ];

        return new TextEncoder().encode(parts.join('-'));
    }

    /**
     * Update node discovery tracking with Protocol v2.1 enhancements
     */
    private async updateNodeDiscoveryV2(
        scanResult: ScanResult,
        nodeId: string,
        publicKeyExtracted: boolean
    ): Promise<void> {
        const { advertisementData, rssi, distance } = scanResult;

        let tracker = this.nodeTrackers.get(nodeId);
        const isNewNode = !tracker;

        if (!tracker) {
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

        tracker.advertisements.push(scanResult);
        if (tracker.advertisements.length > 10) {
            tracker.advertisements.shift();
        }

        tracker.rssiHistory.push(rssi);
        if (tracker.rssiHistory.length > 20) {
            tracker.rssiHistory.shift();
        }

        tracker.ephemeralIds.set(advertisementData.ephemeralId, Date.now());
        tracker.trustScore = this.calculateTrustScoreV2(tracker, scanResult);
        tracker.node.trustScore = tracker.trustScore;
        tracker.node.capabilities = advertisementData.capabilities;
        tracker.node.batteryLevel = advertisementData.batteryLevel;

        if (advertisementData.identityProof.preKeyBundle) {
            await this.handlePreKeyBundle(tracker.node, advertisementData.identityProof.preKeyBundle);
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
            if (Date.now() - tracker.lastVerified > 60000) {
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
        let identityKey: Uint8Array | undefined;
        let encryptionKey: Uint8Array | undefined;
        let preKeys: PreKey[] | undefined;

        if (ad.identityProof.publicKey) {
            identityKey = this.hexToBytes(ad.identityProof.publicKey);
        }

        const cachedKeys = this.publicKeyCache.get(nodeId);
        if (cachedKeys) {
            identityKey = identityKey || cachedKeys.identityKey;
            encryptionKey = cachedKeys.encryptionKey;
        }

        if (ad.identityProof.preKeyBundle) {
            identityKey = identityKey || this.hexToBytes(ad.identityProof.preKeyBundle.identityKey);
            encryptionKey = encryptionKey || this.hexToBytes(ad.identityProof.preKeyBundle.signedPreKey.publicKey);

            if (ad.identityProof.preKeyBundle.oneTimePreKeys) {
                preKeys = ad.identityProof.preKeyBundle.oneTimePreKeys.map((pk, index) => ({
                    keyId: pk.keyId,
                    publicKey: this.hexToBytes(pk.publicKey),
                    privateKey: new Uint8Array(0),
                    signature: new Uint8Array(0),
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
            bluetoothAddress: '',
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

        if (scanResult.isVerified) {
            score += 20;
        }
        if (tracker.node.verificationStatus === VerificationStatus.VERIFIED) {
            score += 10;
        }
        if (tracker.node.verificationStatus === VerificationStatus.TRUSTED) {
            score += 10;
        }

        if (scanResult.protocolVersion >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            score += 5;
        }
        if (tracker.publicKeyExtracted) {
            score += 3;
        }
        if (tracker.publicKeyVerified) {
            score += 2;
        }

        if (tracker.rssiHistory.length >= 5) {
            const variance = this.calculateVariance(tracker.rssiHistory);
            if (variance < 5) score += 20;
            else if (variance < 10) score += 10;
            else if (variance < 15) score += 5;
        }

        const presenceDuration = Date.now() - tracker.node.firstSeen;
        if (presenceDuration > 3600000) score += 20;
        else if (presenceDuration > 600000) score += 10;
        else if (presenceDuration > 60000) score += 5;

        const successRate = tracker.verificationAttempts > 0
            ? (tracker.verificationAttempts - this.statistics.verificationFailures) / tracker.verificationAttempts
            : 0;
        score += Math.floor(successRate * 10);

        return Math.min(100, score);
    }

    /**
     * Stop secure BLE scanning and cleanup
     */
    async stopScanning(): Promise<void> {
        if (!this.isScanning) {
            return;
        }

        try {
            console.log('Stopping secure BLE scanning...');

            await this.stopPlatformScanning();

            this.stopNodeTimeoutTimer();
            this.stopVerificationTimer();

            this.isScanning = false;
            this.isPaused = false;

            console.log('Secure BLE scanning stopped successfully');

        } catch (error) {
            console.error('Failed to stop BLE scanning:', error);
            throw error;
        }
    }

    /**
     * Resolve ephemeral identifier to stable node identity
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

    /**
     * Verify cryptographic signature
     */
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

    /**
     * Process pre-key bundle
     */
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

        console.log(`Updated cryptographic keys for node ${node.id} from pre-key bundle`);
        return Promise.resolve();
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
            return false;
        }

        sequences.add(sequenceNumber);

        if (sequences.size > 1000) {
            const oldestSeq = Math.min(...sequences);
            sequences.delete(oldestSeq);
        }

        return true;
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

    /**
     * Check discovery rate limit
     */
    private checkDiscoveryRateLimit(nodeId: string): boolean {
        const now = Date.now();
        const lastTime = this.discoveryRateLimit.get(nodeId) || 0;

        if (now - lastTime < 200) {
            return false;
        }

        this.discoveryRateLimit.set(nodeId, now);
        return true;
    }

    /**
     * Calculate distance from RSSI
     */
    private calculateDistance(rssi: number, txPower: number): number {
        const pathLossExponent = 2.5;
        const distance = Math.pow(10, (txPower - rssi) / (10 * pathLossExponent));
        return Math.max(0.1, Math.min(100, distance));
    }

    /**
     * Update RSSI statistics
     */
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

    /**
     * Validate scan configuration
     */
    private validateScanConfig(): void {
        if (this.scanConfig.interval < 100 || this.scanConfig.interval > 10000) {
            throw new Error('Scan interval must be between 100ms and 10s');
        }

        if (this.scanConfig.window > this.scanConfig.interval) {
            throw new Error('Scan window cannot exceed scan interval');
        }
    }

    /**
     * Parse capability flags
     */
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

    /**
     * Calculate variance
     */
    private calculateVariance(values: number[]): number {
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const squaredDiffs = values.map(v => Math.pow(v - mean, 2));
        return Math.sqrt(squaredDiffs.reduce((a, b) => a + b, 0) / values.length);
    }

    /**
     * Convert bytes to hex
     */
    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Convert hex to bytes
     */
    private hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    // ===== TIMERS =====

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

        for (const [nodeId, entry] of this.publicKeyCache) {
            if (now - entry.timestamp > 3600000) {
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

    // ===== CALLBACKS =====

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

    // ===== PUBLIC API =====

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