// core/src/ble/advertiser.ts
// Enhanced BLE Advertiser with cryptographic signatures and anti-tracking

import {
    BLEAdvertisementData,
    BLE_CONFIG,
    IdentityProof,
    PreKeyBundle,
    MeshAdvertisement,
    NodeCapability,
    DeviceType
} from './types';
import {
    IGhostKeyPair,
    PreKey,
    CryptoAlgorithm
} from '../types/crypto';

/**
 * Advertisement packet structure for efficient BLE transmission
 */
interface AdvertisementPacket {
    version: number;
    flags: number;                    // Bit flags for capabilities
    ephemeralId: Uint8Array;          // 16 bytes rotating ID
    identityHash: Uint8Array;         // 8 bytes identity hash
    sequenceNumber: number;           // 4 bytes sequence
    timestamp: number;                // 4 bytes timestamp (seconds since epoch)
    signature: Uint8Array;            // 64 bytes Ed25519 signature
    meshInfo: CompactMeshInfo;        // Compact mesh data
    extendedData?: Uint8Array;        // Optional extended data
}

/**
 * Compact mesh information for advertisements
 */
interface CompactMeshInfo {
    nodeCount: number;                // 1 byte (0-255)
    queueSize: number;                // 1 byte (0-255)
    batteryLevel: number;             // 1 byte (0-100)
    flags: number;                    // 1 byte flags
}

/**
 * Advertisement rotation schedule
 */
interface RotationSchedule {
    ephemeralId: string;
    validFrom: number;
    validUntil: number;
    nextRotation: number;
}

/**
 * Enhanced BLE Advertiser with security features
 */
export abstract class BLEAdvertiser {
    // State management
    private isAdvertising: boolean = false;
    private isPaused: boolean = false;
    private currentAdvertisement?: BLEAdvertisementData;
    private currentPacket?: AdvertisementPacket;

    // Security components
    protected keyPair?: IGhostKeyPair;
    private sequenceNumber: number = 0;
    private rotationSchedule?: RotationSchedule;
    private advertisementHistory: Map<number, string>;
    private signatureCache: Map<string, Uint8Array>;

    // Timing management
    private advertisementTimer?: NodeJS.Timeout;
    private rotationTimer?: NodeJS.Timeout;
    private lastAdvertisementTime: number = 0;
    private advertisementInterval: number = BLE_CONFIG.ADVERTISEMENT_INTERVAL;

    // Rate limiting
    private advertisementCount: number = 0;
    private rateLimitWindow: number = 60000; // 1 minute
    private maxAdvertisementsPerWindow: number = 30; // Reduced from 60 to prevent spam

    // Performance tracking
    private statistics = {
        totalAdvertisements: 0,
        successfulAdvertisements: 0,
        failedAdvertisements: 0,
        rotations: 0,
        averageInterval: 0,
        lastError: null as Error | null
    };

    constructor(keyPair?: IGhostKeyPair) {
        this.keyPair = keyPair;
        this.advertisementHistory = new Map();
        this.signatureCache = new Map();
    }

    /**
     * Platform-specific advertising implementation
     */
    protected abstract startPlatformAdvertising(packet: Uint8Array): Promise<void>;
    protected abstract stopPlatformAdvertising(): Promise<void>;
    protected abstract updatePlatformAdvertising(packet: Uint8Array): Promise<void>;
    protected abstract checkPlatformCapabilities(): Promise<{
        maxAdvertisementSize: number;
        supportsExtendedAdvertising: boolean;
        supportsPeriodicAdvertising: boolean;
    }>;

    /**
     * Start secure advertising with signatures and rotation
     */
    async startAdvertising(data: BLEAdvertisementData): Promise<void> {
        if (this.isAdvertising && !this.isPaused) {
            console.log('⚠️ Already advertising, updating advertisement data');
            await this.updateAdvertisement(data);
            return;
        }

        try {
            console.log(`📡 Starting secure BLE advertisement`);

            // Validate and enhance advertisement data
            this.validateAdvertisementData(data);
            const enhancedData = await this.enhanceAdvertisementData(data);

            // Create advertisement packet
            const packet = await this.createAdvertisementPacket(enhancedData);

            // Check platform capabilities
            const capabilities = await this.checkPlatformCapabilities();
            const packetBytes = this.serializePacket(packet);

            if (packetBytes.length > capabilities.maxAdvertisementSize) {
                // Use extended advertising if available
                if (!capabilities.supportsExtendedAdvertising) {
                    throw new Error(`Advertisement too large: ${packetBytes.length} > ${capabilities.maxAdvertisementSize}`);
                }
                console.log('📦 Using extended advertising for large packet');
            }

            // Start platform advertising
            await this.startPlatformAdvertising(packetBytes);

            // Set up rotation schedule
            this.setupRotationSchedule(enhancedData);

            // Start periodic advertisement updates
            this.startPeriodicAdvertising();

            // Update state
            this.isAdvertising = true;
            this.isPaused = false;
            this.currentAdvertisement = enhancedData;
            this.currentPacket = packet;
            this.lastAdvertisementTime = Date.now();

            // Update statistics
            this.statistics.totalAdvertisements++;
            this.statistics.successfulAdvertisements++;

            console.log('✅ Secure BLE advertising started successfully');

        } catch (error) {
            console.error('❌ Failed to start BLE advertising:', error);
            this.statistics.failedAdvertisements++;
            this.statistics.lastError = error as Error;
            this.isAdvertising = false;
            throw error;
        }
    }

    /**
     * Stop advertising
     */
    async stopAdvertising(): Promise<void> {
        if (!this.isAdvertising) {
            return;
        }

        try {
            console.log('🛑 Stopping BLE advertising...');

            // Stop timers
            this.stopPeriodicAdvertising();
            this.stopRotationSchedule();

            // Stop platform advertising
            await this.stopPlatformAdvertising();

            // Clear state
            this.isAdvertising = false;
            this.isPaused = false;
            this.currentAdvertisement = undefined;
            this.currentPacket = undefined;

            // Clear caches
            this.signatureCache.clear();

            console.log('✅ BLE advertising stopped');

        } catch (error) {
            console.error('❌ Failed to stop BLE advertising:', error);
            throw error;
        }
    }

    /**
     * Pause advertising temporarily
     */
    async pauseAdvertising(): Promise<void> {
        if (!this.isAdvertising || this.isPaused) {
            return;
        }

        console.log('⏸️ Pausing BLE advertising');
        this.stopPeriodicAdvertising();
        await this.stopPlatformAdvertising();
        this.isPaused = true;
    }

    /**
     * Resume advertising
     */
    async resumeAdvertising(): Promise<void> {
        if (!this.isAdvertising || !this.isPaused) {
            return;
        }

        console.log('▶️ Resuming BLE advertising');

        if (this.currentPacket) {
            const packetBytes = this.serializePacket(this.currentPacket);
            await this.startPlatformAdvertising(packetBytes);
            this.startPeriodicAdvertising();
            this.isPaused = false;
        }
    }

    /**
     * Update advertisement with new data
     */
    async updateAdvertisement(data: BLEAdvertisementData): Promise<void> {
        if (!this.isAdvertising) {
            this.currentAdvertisement = data;
            return;
        }

        try {
            console.log(`🔄 Updated advertisement (sequence: ${data.sequenceNumber || this.sequenceNumber})`);

            // Validate and enhance new data
            this.validateAdvertisementData(data);
            const enhancedData = await this.enhanceAdvertisementData(data);

            // Create new packet
            const packet = await this.createAdvertisementPacket(enhancedData);
            const packetBytes = this.serializePacket(packet);

            // Update platform advertising
            await this.updatePlatformAdvertising(packetBytes);

            // Update state
            this.currentAdvertisement = enhancedData;
            this.currentPacket = packet;

            console.log('✅ Advertisement updated successfully');

        } catch (error) {
            console.error('❌ Failed to update advertisement:', error);
            throw error;
        }
    }

    /**
     * Enhance advertisement data with security features
     */
    private async enhanceAdvertisementData(data: BLEAdvertisementData): Promise<BLEAdvertisementData> {
        // Add sequence number for replay protection
        if (!data.sequenceNumber) {
            data.sequenceNumber = this.getNextSequenceNumber();
        }

        // Ensure timestamp is current
        data.timestamp = Date.now();

        // Add protocol version
        if (!data.version) {
            data.version = 2;
        }

        // Generate ephemeral ID if not present
        if (!data.ephemeralId) {
            data.ephemeralId = this.generateEphemeralId();
        }

        // Sign the advertisement if we have a key pair
        if (this.keyPair && !data.identityProof.signature) {
            data.identityProof.signature = await this.signAdvertisement(data);
        }

        return data;
    }

    /**
     * Create advertisement packet for transmission
     */
    private async createAdvertisementPacket(data: BLEAdvertisementData): Promise<AdvertisementPacket> {
        // Create capability flags
        const flags = this.createCapabilityFlags(data.capabilities);

        // Create compact mesh info
        const meshInfo: CompactMeshInfo = {
            nodeCount: Math.min(255, data.meshInfo.nodeCount),
            queueSize: Math.min(255, data.meshInfo.messageQueueSize),
            batteryLevel: data.batteryLevel || 100,
            flags: this.createMeshFlags(data)
        };

        // Create packet
        const packet: AdvertisementPacket = {
            version: data.version,
            flags,
            ephemeralId: this.hexToBytes(data.ephemeralId),
            identityHash: this.hexToBytes(data.identityProof.publicKeyHash).slice(0, 8),
            sequenceNumber: data.sequenceNumber,
            timestamp: Math.floor(data.timestamp / 1000),
            signature: this.hexToBytes(data.identityProof.signature),
            meshInfo,
            extendedData: await this.createExtendedData(data)
        };

        return packet;
    }

    /**
     * Sign advertisement for authenticity
     */
    private async signAdvertisement(data: BLEAdvertisementData): Promise<string> {
        if (!this.keyPair) {
            throw new Error('Key pair required for signing');
        }

        // Create signing data
        const signingData = this.createSigningData(data);

        // Check cache
        const cacheKey = this.hashData(signingData);
        let signature = this.signatureCache.get(cacheKey);

        if (!signature) {
            // Sign with identity key
            signature = this.keyPair.signMessage(signingData);

            // Cache signature
            this.signatureCache.set(cacheKey, signature);

            // Limit cache size
            if (this.signatureCache.size > 100) {
                const firstKey = this.signatureCache.keys().next().value;
                if (firstKey !== undefined) {
                    this.signatureCache.delete(firstKey);
                }
            }
        }

        return this.bytesToHex(signature);
    }

    /**
     * Create data for signing
     */
    private createSigningData(data: BLEAdvertisementData): Uint8Array {
        const parts = [
            data.ephemeralId,
            data.identityProof.publicKeyHash,
            data.identityProof.timestamp.toString(),
            data.identityProof.nonce,
            data.sequenceNumber.toString()
        ];

        const combined = parts.join('-');
        return new TextEncoder().encode(combined);
    }

    /**
     * Serialize packet for transmission
     */
    private serializePacket(packet: AdvertisementPacket): Uint8Array {
        // Calculate packet size
        let size = 1 + 1 + 16 + 8 + 4 + 4 + 64 + 4; // Fixed fields
        if (packet.extendedData) {
            size += packet.extendedData.length;
        }

        const buffer = new Uint8Array(size);
        const view = new DataView(buffer.buffer);
        let offset = 0;

        // Version (1 byte)
        buffer[offset++] = packet.version;

        // Flags (1 byte)
        buffer[offset++] = packet.flags;

        // Ephemeral ID (16 bytes)
        buffer.set(packet.ephemeralId, offset);
        offset += 16;

        // Identity hash (8 bytes)
        buffer.set(packet.identityHash, offset);
        offset += 8;

        // Sequence number (4 bytes)
        view.setUint32(offset, packet.sequenceNumber, false);
        offset += 4;

        // Timestamp (4 bytes)
        view.setUint32(offset, packet.timestamp, false);
        offset += 4;

        // Signature (64 bytes)
        buffer.set(packet.signature, offset);
        offset += 64;

        // Mesh info (4 bytes)
        buffer[offset++] = packet.meshInfo.nodeCount;
        buffer[offset++] = packet.meshInfo.queueSize;
        buffer[offset++] = packet.meshInfo.batteryLevel;
        buffer[offset++] = packet.meshInfo.flags;

        // Extended data (variable)
        if (packet.extendedData) {
            buffer.set(packet.extendedData, offset);
        }

        return buffer;
    }

    /**
     * Parse advertisement packet
     */
    static parseAdvertisementPacket(data: Uint8Array): AdvertisementPacket | null {
        try {
            if (data.length < 108) { // Minimum packet size
                return null;
            }

            const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
            let offset = 0;

            // Version
            const version = data[offset++];

            // Flags
            const flags = data[offset++];

            // Ephemeral ID
            const ephemeralId = data.slice(offset, offset + 16);
            offset += 16;

            // Identity hash
            const identityHash = data.slice(offset, offset + 8);
            offset += 8;

            // Sequence number
            const sequenceNumber = view.getUint32(offset, false);
            offset += 4;

            // Timestamp
            const timestamp = view.getUint32(offset, false);
            offset += 4;

            // Signature
            const signature = data.slice(offset, offset + 64);
            offset += 64;

            // Mesh info
            const meshInfo: CompactMeshInfo = {
                nodeCount: data[offset++],
                queueSize: data[offset++],
                batteryLevel: data[offset++],
                flags: data[offset++]
            };

            // Extended data
            let extendedData: Uint8Array | undefined;
            if (offset < data.length) {
                extendedData = data.slice(offset);
            }

            return {
                version,
                flags,
                ephemeralId,
                identityHash,
                sequenceNumber,
                timestamp,
                signature,
                meshInfo,
                extendedData
            };

        } catch (error) {
            console.error('❌ Error parsing advertisement packet:', error);
            return null;
        }
    }

    /**
     * Validate advertisement data
     */
    private validateAdvertisementData(data: BLEAdvertisementData): void {
        // Version check
        if (!data.version || data.version < 2) {
            throw new Error('Advertisement version must be 2 or higher');
        }

        // Identity proof validation
        if (!data.identityProof) {
            throw new Error('Identity proof required in advertisement');
        }

        if (!data.identityProof.publicKeyHash || data.identityProof.publicKeyHash.length < 16) {
            throw new Error('Invalid public key hash in identity proof');
        }

        if (!data.identityProof.nonce || data.identityProof.nonce.length < 16) {
            throw new Error('Invalid nonce in identity proof');
        }

        // Timestamp validation
        const now = Date.now();
        const timeDiff = Math.abs(now - data.timestamp);
        if (timeDiff > 300000) { // 5 minutes
            console.warn('⚠️ Advertisement timestamp differs significantly from current time');
        }

        // Capabilities validation
        if (!Array.isArray(data.capabilities)) {
            throw new Error('Capabilities must be an array');
        }

        // Mesh info validation
        if (!data.meshInfo) {
            throw new Error('Mesh information required in advertisement');
        }

        // Pre-key bundle validation if present
        if (data.identityProof.preKeyBundle) {
            this.validatePreKeyBundle(data.identityProof.preKeyBundle);
        }
    }

    /**
     * Validate pre-key bundle
     */
    private validatePreKeyBundle(bundle: PreKeyBundle): void {
        if (!bundle.identityKey || bundle.identityKey.length !== 64) {
            throw new Error('Invalid identity key in pre-key bundle');
        }

        if (!bundle.signedPreKey) {
            throw new Error('Signed pre-key required in bundle');
        }

        if (!bundle.signedPreKey.publicKey || bundle.signedPreKey.publicKey.length !== 64) {
            throw new Error('Invalid signed pre-key public key');
        }

        if (!bundle.signedPreKey.signature || bundle.signedPreKey.signature.length !== 128) {
            throw new Error('Invalid signed pre-key signature');
        }
    }

    /**
     * Set up ephemeral ID rotation schedule
     */
    private setupRotationSchedule(data: BLEAdvertisementData): void {
        // Clear existing timer
        this.stopRotationSchedule();

        // Calculate rotation interval with randomization
        const baseInterval = BLE_CONFIG.ADDRESS_ROTATION_INTERVAL;
        const randomization = Math.random() * BLE_CONFIG.ADVERTISEMENT_RANDOMIZATION;
        const interval = baseInterval + randomization;

        // Set up rotation
        this.rotationSchedule = {
            ephemeralId: data.ephemeralId,
            validFrom: Date.now(),
            validUntil: Date.now() + interval,
            nextRotation: Date.now() + interval
        };

        // Schedule rotation
        this.rotationTimer = setTimeout(() => {
            this.rotateEphemeralId();
        }, interval);

        console.log(`🔄 Ephemeral ID rotation scheduled for ${new Date(this.rotationSchedule.nextRotation).toLocaleTimeString()}`);
    }

    /**
     * Stop rotation schedule
     */
    private stopRotationSchedule(): void {
        if (this.rotationTimer) {
            clearTimeout(this.rotationTimer);
            this.rotationTimer = undefined;
        }
        this.rotationSchedule = undefined;
    }

    /**
     * Rotate ephemeral ID for privacy
     */
    private async rotateEphemeralId(): Promise<void> {
        if (!this.currentAdvertisement) {
            return;
        }

        console.log('🔄 Rotating ephemeral ID for privacy');

        // Generate new ephemeral ID
        const newEphemeralId = this.generateEphemeralId();

        // Update advertisement
        this.currentAdvertisement.ephemeralId = newEphemeralId;
        this.currentAdvertisement.sequenceNumber = this.getNextSequenceNumber();

        // Re-sign with new ephemeral ID
        if (this.keyPair) {
            this.currentAdvertisement.identityProof.signature = await this.signAdvertisement(this.currentAdvertisement);
        }

        // Update advertisement
        await this.updateAdvertisement(this.currentAdvertisement);

        // Update statistics
        this.statistics.rotations++;

        // Schedule next rotation
        this.setupRotationSchedule(this.currentAdvertisement);
    }

    /**
     * Start periodic advertising - FIXED VERSION
     */
    private startPeriodicAdvertising(): void {
        // Clear existing timer
        this.stopPeriodicAdvertising();

        // Use setInterval for consistent periodic updates
        this.advertisementTimer = setInterval(async () => {
            await this.performPeriodicAdvertisement();
        }, this.advertisementInterval);
    }

    /**
     * Stop periodic advertising
     */
    private stopPeriodicAdvertising(): void {
        if (this.advertisementTimer) {
            clearInterval(this.advertisementTimer); // Changed from clearTimeout
            this.advertisementTimer = undefined;
        }
    }

    /**
     * Perform periodic advertisement update - FIXED VERSION
     */
    private async performPeriodicAdvertisement(): Promise<void> {
        if (!this.isAdvertising || this.isPaused) {
            return;
        }

        try {
            // Check rate limiting
            if (!this.checkRateLimit()) {
                console.warn('⚠️ Advertisement rate limit reached, skipping');
                return;
            }

            // Update mesh info
            if (this.currentAdvertisement) {
                this.currentAdvertisement.meshInfo.nodeCount = await this.getNodeCount();
                this.currentAdvertisement.meshInfo.messageQueueSize = await this.getQueueSize();
                this.currentAdvertisement.sequenceNumber = this.getNextSequenceNumber();

                // Update advertisement
                await this.updateAdvertisement(this.currentAdvertisement);
            }

            // Update statistics
            const now = Date.now();
            const interval = now - this.lastAdvertisementTime;
            this.statistics.averageInterval =
                (this.statistics.averageInterval * 0.9) + (interval * 0.1);
            this.lastAdvertisementTime = now;

        } catch (error) {
            console.error('❌ Periodic advertisement failed:', error);
            this.statistics.failedAdvertisements++;
        }
        // Removed the finally block that was causing recursive timer creation
    }

    /**
     * Create capability flags byte
     */
    private createCapabilityFlags(capabilities: NodeCapability[]): number {
        let flags = 0;

        const capabilityBits: Record<NodeCapability, number> = {
            [NodeCapability.RELAY]: 0x01,
            [NodeCapability.STORAGE]: 0x02,
            [NodeCapability.BRIDGE]: 0x04,
            [NodeCapability.GROUP_CHAT]: 0x08,
            [NodeCapability.FILE_TRANSFER]: 0x10,
            [NodeCapability.VOICE_NOTES]: 0x20
        };

        for (const capability of capabilities) {
            flags |= capabilityBits[capability] || 0;
        }

        return flags;
    }

    /**
     * Create mesh flags byte
     */
    private createMeshFlags(data: BLEAdvertisementData): number {
        let flags = 0;

        // Bit 0: Has pre-keys
        if (data.identityProof.preKeyBundle) {
            flags |= 0x01;
        }

        // Bit 1: Accepting connections
        flags |= 0x02;

        // Bit 2: Low power mode
        if (data.batteryLevel && data.batteryLevel < 20) {
            flags |= 0x04;
        }

        // Bit 3: Has queued messages
        if (data.meshInfo.messageQueueSize > 0) {
            flags |= 0x08;
        }

        return flags;
    }

    /**
     * Create extended data for large advertisements
     */
    private async createExtendedData(data: BLEAdvertisementData): Promise<Uint8Array | undefined> {
        // Include pre-key bundle if present and space allows
        if (data.identityProof.preKeyBundle) {
            const bundleData = JSON.stringify(data.identityProof.preKeyBundle);
            return new TextEncoder().encode(bundleData);
        }

        return undefined;
    }

    /**
     * Check rate limiting
     */
    private checkRateLimit(): boolean {
        const now = Date.now();
        const windowStart = now - this.rateLimitWindow;

        // Reset counter if window expired
        if (this.lastAdvertisementTime < windowStart) {
            this.advertisementCount = 0;
        }

        if (this.advertisementCount >= this.maxAdvertisementsPerWindow) {
            return false;
        }

        this.advertisementCount++;
        return true;
    }

    /**
     * Generate ephemeral ID
     */
    private generateEphemeralId(): string {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return this.bytesToHex(bytes);
    }

    /**
     * Get next sequence number
     */
    private getNextSequenceNumber(): number {
        this.sequenceNumber = (this.sequenceNumber + 1) % 0xFFFFFFFF;
        return this.sequenceNumber;
    }

    /**
     * Hash data for caching
     */
    private hashData(data: Uint8Array): string {
        // Simple hash for caching
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash) + data[i];
            hash = hash & hash;
        }
        return hash.toString(36);
    }

    /**
     * Convert bytes to hex string
     */
    private bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Convert hex string to bytes
     */
    private hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    // Platform-specific methods to be implemented
    protected async getNodeCount(): Promise<number> {
        return 0; // Override in platform implementation
    }

    protected async getQueueSize(): Promise<number> {
        return 0; // Override in platform implementation
    }

    /**
     * Get advertising status and statistics
     */
    getStatus(): {
        isAdvertising: boolean;
        isPaused: boolean;
        currentData?: BLEAdvertisementData;
        rotationSchedule?: RotationSchedule;
        statistics: {
            totalAdvertisements: number;
            successfulAdvertisements: number;
            failedAdvertisements: number;
            rotations: number;
            averageInterval: number;
            lastError: Error | null;
        };
    } {
        return {
            isAdvertising: this.isAdvertising,
            isPaused: this.isPaused,
            currentData: this.currentAdvertisement,
            rotationSchedule: this.rotationSchedule,
            statistics: { ...this.statistics }
        };
    }

    /**
     * Set advertising interval
     */
    setAdvertisingInterval(interval: number): void {
        if (interval < 100 || interval > 10000) {
            throw new Error('Advertising interval must be between 100ms and 10s');
        }

        this.advertisementInterval = interval;

        // Restart periodic advertising with new interval
        if (this.isAdvertising && !this.isPaused) {
            this.startPeriodicAdvertising();
        }
    }

    /**
     * Set key pair for signing
     */
    setKeyPair(keyPair: IGhostKeyPair): void {
        this.keyPair = keyPair;

        // Clear signature cache as keys changed
        this.signatureCache.clear();
    }
}