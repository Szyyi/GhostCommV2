// core/src/ble/advertiser.ts
// Enhanced BLE Advertiser with Protocol v2 cryptographic signatures

import {
    BLEAdvertisementData,
    BLE_CONFIG,
    BLE_SECURITY_CONFIG,
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
    publicKey?: Uint8Array;           // Protocol v2: Full public key (32 bytes)
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
    protocolVersion: number;          // 1 byte (Protocol v2)
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
 * Enhanced BLE Advertiser with Protocol v2 security
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
    private maxAdvertisementsPerWindow: number = 30;

    // Performance tracking
    private statistics = {
        totalAdvertisements: 0,
        successfulAdvertisements: 0,
        failedAdvertisements: 0,
        rotations: 0,
        averageInterval: 0,
        protocolVersion: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
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
     * Start secure advertising with Protocol v2 signatures
     */
    async startAdvertising(data: BLEAdvertisementData): Promise<void> {
        if (this.isAdvertising && !this.isPaused) {
            console.log('Already advertising, updating advertisement data');
            await this.updateAdvertisement(data);
            return;
        }

        try {
            console.log(`Starting secure BLE advertisement (Protocol v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION})`);

            // Validate and enhance advertisement data for Protocol v2
            this.validateAdvertisementData(data);
            const enhancedData = await this.enhanceAdvertisementDataV2(data);

            // Create advertisement packet
            const packet = await this.createAdvertisementPacket(enhancedData);

            // Check platform capabilities
            const capabilities = await this.checkPlatformCapabilities();
            const packetBytes = this.serializePacket(packet);

            if (packetBytes.length > capabilities.maxAdvertisementSize) {
                if (!capabilities.supportsExtendedAdvertising) {
                    throw new Error(`Advertisement too large: ${packetBytes.length} > ${capabilities.maxAdvertisementSize}`);
                }
                console.log('Using extended advertising for large packet');
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

            console.log('Secure BLE advertising started successfully');

        } catch (error) {
            console.error('Failed to start BLE advertising:', error);
            this.statistics.failedAdvertisements++;
            this.statistics.lastError = error as Error;
            this.isAdvertising = false;
            throw error;
        }
    }

    /**
     * Enhance advertisement data with Protocol v2 security features
     */
    private async enhanceAdvertisementDataV2(data: BLEAdvertisementData): Promise<BLEAdvertisementData> {
        // Ensure Protocol v2
        data.version = BLE_SECURITY_CONFIG.PROTOCOL_VERSION;
        data.protocolVersion = BLE_SECURITY_CONFIG.PROTOCOL_VERSION;

        // Add sequence number for replay protection
        if (!data.sequenceNumber) {
            data.sequenceNumber = this.getNextSequenceNumber();
        }

        // Ensure timestamp is current
        data.timestamp = Date.now();

        // Generate ephemeral ID if not present
        if (!data.ephemeralId) {
            data.ephemeralId = this.generateEphemeralId();
        }

        // Protocol v2: Ensure full public key is included
        if (this.keyPair && !data.identityProof.publicKey) {
            const identityPublicKey = this.keyPair.getIdentityPublicKey();
            data.identityProof.publicKey = this.bytesToHex(identityPublicKey);
        }

        // Sign the advertisement with Protocol v2 requirements
        if (this.keyPair) {
            data.identityProof.signature = await this.signAdvertisementV2(data);
        }

        return data;
    }

    /**
     * Sign advertisement with Protocol v2 requirements
     */
    private async signAdvertisementV2(data: BLEAdvertisementData): Promise<string> {
        if (!this.keyPair) {
            throw new Error('Key pair required for Protocol v2 signing');
        }

        // Create signing data including all Protocol v2 fields
        const signingData = this.createSigningDataV2(data);

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
     * Create data for Protocol v2 signing
     */
    private createSigningDataV2(data: BLEAdvertisementData): Uint8Array {
        // Include all critical fields for Protocol v2
        const parts = [
            data.ephemeralId,
            data.identityProof.publicKeyHash,
            data.identityProof.publicKey || '', // Full public key for v2
            data.identityProof.timestamp.toString(),
            data.identityProof.nonce,
            data.sequenceNumber.toString(),
            data.version.toString()
        ];

        const combined = parts.join('-');
        return new TextEncoder().encode(combined);
    }

    /**
     * Create advertisement packet for transmission
     */
    private async createAdvertisementPacket(data: BLEAdvertisementData): Promise<AdvertisementPacket> {
        // Create capability flags
        const flags = this.createCapabilityFlags(data.capabilities);

        // Create compact mesh info with Protocol version
        const meshInfo: CompactMeshInfo = {
            nodeCount: Math.min(255, data.meshInfo.nodeCount),
            queueSize: Math.min(255, data.meshInfo.messageQueueSize),
            batteryLevel: data.batteryLevel || 100,
            flags: this.createMeshFlags(data),
            protocolVersion: BLE_SECURITY_CONFIG.PROTOCOL_VERSION
        };

        // Create packet with Protocol v2 fields
        const packet: AdvertisementPacket = {
            version: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
            flags,
            ephemeralId: this.hexToBytes(data.ephemeralId),
            identityHash: this.hexToBytes(data.identityProof.publicKeyHash).slice(0, 8),
            sequenceNumber: data.sequenceNumber,
            timestamp: Math.floor(data.timestamp / 1000),
            signature: this.hexToBytes(data.identityProof.signature),
            meshInfo,
            extendedData: await this.createExtendedDataV2(data)
        };

        // Protocol v2: Include full public key if available
        if (data.identityProof.publicKey) {
            packet.publicKey = this.hexToBytes(data.identityProof.publicKey).slice(0, 32);
        }

        return packet;
    }

    /**
     * Serialize packet for transmission with Protocol v2
     */
    private serializePacket(packet: AdvertisementPacket): Uint8Array {
        // Calculate packet size
        let size = 1 + 1 + 16 + 8 + 4 + 4 + 64 + 5; // Fixed fields (mesh info now 5 bytes)
        
        // Protocol v2: Add space for public key if present
        if (packet.publicKey) {
            size += 32;
        }
        
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

        // Protocol v2: Public key if present (32 bytes)
        if (packet.publicKey) {
            buffer.set(packet.publicKey, offset);
            offset += 32;
        }

        // Sequence number (4 bytes)
        view.setUint32(offset, packet.sequenceNumber, false);
        offset += 4;

        // Timestamp (4 bytes)
        view.setUint32(offset, packet.timestamp, false);
        offset += 4;

        // Signature (64 bytes)
        buffer.set(packet.signature, offset);
        offset += 64;

        // Mesh info (5 bytes - added protocol version)
        buffer[offset++] = packet.meshInfo.nodeCount;
        buffer[offset++] = packet.meshInfo.queueSize;
        buffer[offset++] = packet.meshInfo.batteryLevel;
        buffer[offset++] = packet.meshInfo.flags;
        buffer[offset++] = packet.meshInfo.protocolVersion;

        // Extended data (variable)
        if (packet.extendedData) {
            buffer.set(packet.extendedData, offset);
        }

        return buffer;
    }

    /**
     * Parse advertisement packet with Protocol v2 support
     */
    static parseAdvertisementPacket(data: Uint8Array): AdvertisementPacket | null {
        try {
            if (data.length < 109) { // Minimum packet size (increased for protocol version)
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

            // Protocol v2: Check if public key is included
            let publicKey: Uint8Array | undefined;
            if (version >= 2 && data.length >= offset + 32 + 76) { // Space for public key + remaining fields
                publicKey = data.slice(offset, offset + 32);
                offset += 32;
            }

            // Sequence number
            const sequenceNumber = view.getUint32(offset, false);
            offset += 4;

            // Timestamp
            const timestamp = view.getUint32(offset, false);
            offset += 4;

            // Signature
            const signature = data.slice(offset, offset + 64);
            offset += 64;

            // Mesh info (5 bytes for v2)
            const meshInfo: CompactMeshInfo = {
                nodeCount: data[offset++],
                queueSize: data[offset++],
                batteryLevel: data[offset++],
                flags: data[offset++],
                protocolVersion: version >= 2 ? data[offset++] : 1
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
                publicKey,
                sequenceNumber,
                timestamp,
                signature,
                meshInfo,
                extendedData
            };

        } catch (error) {
            console.error('Error parsing advertisement packet:', error);
            return null;
        }
    }

    /**
     * Validate advertisement data for Protocol v2
     */
    private validateAdvertisementData(data: BLEAdvertisementData): void {
        // Version check
        if (!data.version || data.version < BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            console.warn(`Advertisement version ${data.version} < required v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}`);
        }

        // Identity proof validation
        if (!data.identityProof) {
            throw new Error('Identity proof required in advertisement');
        }

        if (!data.identityProof.publicKeyHash || data.identityProof.publicKeyHash.length < 16) {
            throw new Error('Invalid public key hash in identity proof');
        }

        // Protocol v2: Warn if public key is missing
        if (BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION && !data.identityProof.publicKey) {
            console.warn('Protocol v2 requires full public key in identity proof');
        }

        if (!data.identityProof.nonce || data.identityProof.nonce.length < 16) {
            throw new Error('Invalid nonce in identity proof');
        }

        // Timestamp validation
        const now = Date.now();
        const timeDiff = Math.abs(now - data.timestamp);
        if (timeDiff > 300000) { // 5 minutes
            console.warn('Advertisement timestamp differs significantly from current time');
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
     * Create extended data for Protocol v2
     */
    private async createExtendedDataV2(data: BLEAdvertisementData): Promise<Uint8Array | undefined> {
        const extended: any = {};

        // Include pre-key bundle if present
        if (data.identityProof.preKeyBundle) {
            extended.preKeyBundle = data.identityProof.preKeyBundle;
        }

        // Include supported algorithms for v2
        extended.supportedAlgorithms = [
            CryptoAlgorithm.ED25519,
            CryptoAlgorithm.X25519,
            CryptoAlgorithm.XCHACHA20_POLY1305
        ];

        // Include protocol requirements
        extended.protocolRequirements = {
            requireSignatureVerification: BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION,
            requireMessageChaining: BLE_SECURITY_CONFIG.REQUIRE_MESSAGE_CHAINING,
            requireSequenceNumbers: BLE_SECURITY_CONFIG.REQUIRE_SEQUENCE_NUMBERS
        };

        if (Object.keys(extended).length > 0) {
            const extendedData = JSON.stringify(extended);
            return new TextEncoder().encode(extendedData);
        }

        return undefined;
    }

    /**
     * Update advertisement with Protocol v2 requirements
     */
    async updateAdvertisement(data: BLEAdvertisementData): Promise<void> {
        if (!this.isAdvertising) {
            this.currentAdvertisement = data;
            return;
        }

        try {
            console.log(`Updating advertisement (Protocol v${data.version}, sequence: ${data.sequenceNumber || this.sequenceNumber})`);

            // Validate and enhance new data for Protocol v2
            this.validateAdvertisementData(data);
            const enhancedData = await this.enhanceAdvertisementDataV2(data);

            // Create new packet
            const packet = await this.createAdvertisementPacket(enhancedData);
            const packetBytes = this.serializePacket(packet);

            // Update platform advertising
            await this.updatePlatformAdvertising(packetBytes);

            // Update state
            this.currentAdvertisement = enhancedData;
            this.currentPacket = packet;

            console.log('Advertisement updated successfully');

        } catch (error) {
            console.error('Failed to update advertisement:', error);
            throw error;
        }
    }

    /**
     * Rotate ephemeral ID for privacy
     */
    private async rotateEphemeralId(): Promise<void> {
        if (!this.currentAdvertisement) {
            return;
        }

        console.log('Rotating ephemeral ID for privacy');

        // Generate new ephemeral ID
        const newEphemeralId = this.generateEphemeralId();

        // Update advertisement
        this.currentAdvertisement.ephemeralId = newEphemeralId;
        this.currentAdvertisement.sequenceNumber = this.getNextSequenceNumber();

        // Re-sign with new ephemeral ID using Protocol v2
        if (this.keyPair) {
            this.currentAdvertisement.identityProof.signature = await this.signAdvertisementV2(this.currentAdvertisement);
        }

        // Update advertisement
        await this.updateAdvertisement(this.currentAdvertisement);

        // Update statistics
        this.statistics.rotations++;

        // Schedule next rotation
        this.setupRotationSchedule(this.currentAdvertisement);
    }

    /**
     * Stop advertising
     */
    async stopAdvertising(): Promise<void> {
        if (!this.isAdvertising) {
            return;
        }

        try {
            console.log('Stopping BLE advertising...');

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

            console.log('BLE advertising stopped');

        } catch (error) {
            console.error('Failed to stop BLE advertising:', error);
            throw error;
        }
    }

    // ... [Include all other methods unchanged from original] ...

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

    private setupRotationSchedule(data: BLEAdvertisementData): void {
        this.stopRotationSchedule();

        const baseInterval = BLE_CONFIG.ADDRESS_ROTATION_INTERVAL;
        const randomization = Math.random() * BLE_CONFIG.ADVERTISEMENT_RANDOMIZATION;
        const interval = baseInterval + randomization;

        this.rotationSchedule = {
            ephemeralId: data.ephemeralId,
            validFrom: Date.now(),
            validUntil: Date.now() + interval,
            nextRotation: Date.now() + interval
        };

        this.rotationTimer = setTimeout(() => {
            this.rotateEphemeralId();
        }, interval);

        console.log(`Ephemeral ID rotation scheduled for ${new Date(this.rotationSchedule.nextRotation).toLocaleTimeString()}`);
    }

    private stopRotationSchedule(): void {
        if (this.rotationTimer) {
            clearTimeout(this.rotationTimer);
            this.rotationTimer = undefined;
        }
        this.rotationSchedule = undefined;
    }

    private startPeriodicAdvertising(): void {
        this.stopPeriodicAdvertising();
        this.advertisementTimer = setInterval(async () => {
            await this.performPeriodicAdvertisement();
        }, this.advertisementInterval);
    }

    private stopPeriodicAdvertising(): void {
        if (this.advertisementTimer) {
            clearInterval(this.advertisementTimer);
            this.advertisementTimer = undefined;
        }
    }

    private async performPeriodicAdvertisement(): Promise<void> {
        if (!this.isAdvertising || this.isPaused) {
            return;
        }

        try {
            if (!this.checkRateLimit()) {
                console.warn('Advertisement rate limit reached, skipping');
                return;
            }

            if (this.currentAdvertisement) {
                this.currentAdvertisement.meshInfo.nodeCount = await this.getNodeCount();
                this.currentAdvertisement.meshInfo.messageQueueSize = await this.getQueueSize();
                this.currentAdvertisement.sequenceNumber = this.getNextSequenceNumber();

                await this.updateAdvertisement(this.currentAdvertisement);
            }

            const now = Date.now();
            const interval = now - this.lastAdvertisementTime;
            this.statistics.averageInterval =
                (this.statistics.averageInterval * 0.9) + (interval * 0.1);
            this.lastAdvertisementTime = now;

        } catch (error) {
            console.error('Periodic advertisement failed:', error);
            this.statistics.failedAdvertisements++;
        }
    }

    async pauseAdvertising(): Promise<void> {
        if (!this.isAdvertising || this.isPaused) {
            return;
        }

        console.log('Pausing BLE advertising');
        this.stopPeriodicAdvertising();
        await this.stopPlatformAdvertising();
        this.isPaused = true;
    }

    async resumeAdvertising(): Promise<void> {
        if (!this.isAdvertising || !this.isPaused) {
            return;
        }

        console.log('Resuming BLE advertising');

        if (this.currentPacket) {
            const packetBytes = this.serializePacket(this.currentPacket);
            await this.startPlatformAdvertising(packetBytes);
            this.startPeriodicAdvertising();
            this.isPaused = false;
        }
    }

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

    private createMeshFlags(data: BLEAdvertisementData): number {
        let flags = 0;

        if (data.identityProof.preKeyBundle) {
            flags |= 0x01;
        }

        flags |= 0x02; // Accepting connections

        if (data.batteryLevel && data.batteryLevel < 20) {
            flags |= 0x04;
        }

        if (data.meshInfo.messageQueueSize > 0) {
            flags |= 0x08;
        }

        // Protocol v2 flag
        if (data.version >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            flags |= 0x10;
        }

        return flags;
    }

    private checkRateLimit(): boolean {
        const now = Date.now();
        const windowStart = now - this.rateLimitWindow;

        if (this.lastAdvertisementTime < windowStart) {
            this.advertisementCount = 0;
        }

        if (this.advertisementCount >= this.maxAdvertisementsPerWindow) {
            return false;
        }

        this.advertisementCount++;
        return true;
    }

    private generateEphemeralId(): string {
        const bytes = new Uint8Array(16);
        crypto.getRandomValues(bytes);
        return this.bytesToHex(bytes);
    }

    private getNextSequenceNumber(): number {
        this.sequenceNumber = (this.sequenceNumber + 1) % 0xFFFFFFFF;
        return this.sequenceNumber;
    }

    private hashData(data: Uint8Array): string {
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash) + data[i];
            hash = hash & hash;
        }
        return hash.toString(36);
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

    protected async getNodeCount(): Promise<number> {
        return 0;
    }

    protected async getQueueSize(): Promise<number> {
        return 0;
    }

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
            protocolVersion: number;
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

    setAdvertisingInterval(interval: number): void {
        if (interval < 100 || interval > 10000) {
            throw new Error('Advertising interval must be between 100ms and 10s');
        }

        this.advertisementInterval = interval;

        if (this.isAdvertising && !this.isPaused) {
            this.startPeriodicAdvertising();
        }
    }

    setKeyPair(keyPair: IGhostKeyPair): void {
        this.keyPair = keyPair;
        this.signatureCache.clear();
    }
}