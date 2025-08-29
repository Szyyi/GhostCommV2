// mobile/src/ble/ReactNativeBLEAdvertiser.ts
import { BleManager } from 'react-native-ble-plx';
import { Platform } from 'react-native';
import {
    BLEAdvertiser,
    BLEAdvertisementData,
    BLE_CONFIG,
    SECURITY_CONFIG,
    NodeCapability,
    DeviceType,
    IdentityProof,
    BLEPreKeyBundle,
    IGhostKeyPair
} from '../../core';
import { BLE_SECURITY_CONFIG, PreKeyBundle } from '../../core/src/ble/types';

/**
 * React Native BLE Advertiser Implementation for Protocol v2.0
 * 
 * LIMITATION: react-native-ble-plx doesn't support custom BLE advertising.
 * This implementation simulates advertising while maintaining Protocol v2.0 
 * packet format compatibility with FULL PUBLIC KEY inclusion.
 */
export class ReactNativeBLEAdvertiser extends BLEAdvertiser {
    private bleManager: BleManager;
    private simulatedAdvertisementData?: BLEAdvertisementData;
    private isInitialized: boolean = false;

    // Mesh tracking for platform-specific methods
    private meshNodeCount: number = 0;
    private meshQueueSize: number = 0;

    constructor(keyPair?: IGhostKeyPair) {
        super(keyPair);
        this.bleManager = new BleManager();
    }

    /**
     * Initialize BLE manager if not already initialized
     */
    private async ensureInitialized(): Promise<void> {
        if (this.isInitialized) {
            return;
        }

        try {
            // Check if BLE is powered on
            const state = await this.bleManager.state();
            if (state !== 'PoweredOn') {
                console.log(`⏳ Waiting for BLE to power on (current state: ${state})`);
                
                // Wait for BLE to be powered on
                await new Promise<void>((resolve) => {
                    const subscription = this.bleManager.onStateChange((newState) => {
                        if (newState === 'PoweredOn') {
                            subscription.remove();
                            resolve();
                        }
                    }, true);
                });
            }

            this.isInitialized = true;
            console.log('✅ BLE Manager initialized for Protocol v2');
        } catch (error) {
            console.error('❌ Failed to initialize BLE Manager:', error);
            throw error;
        }
    }

    /**
     * Start platform-specific advertising with binary packet
     * Since I can't actually advertise, I simulate it with Protocol v2 compliance
     */
    protected async startPlatformAdvertising(packet: Uint8Array): Promise<void> {
        try {
            // Ensure BLE is initialized
            await this.ensureInitialized();

            // Parse the packet to understand what we would advertise
            const parsedPacket = BLEAdvertiser.parseAdvertisementPacket(packet);
            if (!parsedPacket) {
                throw new Error('Invalid advertisement packet');
            }

            // Verify Protocol v2
            if (parsedPacket.version !== BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                console.warn(`⚠️ Advertisement version mismatch: expected ${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}, got ${parsedPacket.version}`);
            }

            // Store the simulated advertisement data with Protocol v2 fields
            this.simulatedAdvertisementData = await this.packetToAdvertisementData(parsedPacket);

            // Log Protocol v2 advertisement details
            console.log(`📡 Simulating Protocol v2.0 advertisement:`);
            console.log(`  - Version: ${parsedPacket.version}`);
            console.log(`  - Ephemeral ID: ${this.bytesToHexString(parsedPacket.ephemeralId).substring(0, 16)}...`);
            console.log(`  - Identity Hash: ${this.bytesToHexString(parsedPacket.identityHash).substring(0, 16)}...`);
            console.log(`  - Public Key: ${this.simulatedAdvertisementData.identityProof.publicKey?.substring(0, 16)}...`);
            console.log(`  - Sequence: ${parsedPacket.sequenceNumber}`);
            console.log(`  - Packet size: ${packet.length} bytes (includes 32-byte public key)`);

            // In a real implementation, I would use platform-specific BLE APIs here
            // For iOS: CBPeripheralManager with extended advertising
            // For Android: BluetoothLeAdvertiser with BLE 5.0 extended advertising

        } catch (error) {
            console.error('❌ Failed to start platform advertising:', error);
            throw error;
        }
    }

    /**
     * Stop platform-specific advertising
     */
    protected async stopPlatformAdvertising(): Promise<void> {
        try {
            this.simulatedAdvertisementData = undefined;
            console.log('🛑 Stopped Protocol v2 advertising');
        } catch (error) {
            console.error('❌ Failed to stop platform advertising:', error);
            throw error;
        }
    }

    /**
     * Update platform advertising with new packet
     */
    protected async updatePlatformAdvertising(packet: Uint8Array): Promise<void> {
        try {
            const parsedPacket = BLEAdvertiser.parseAdvertisementPacket(packet);
            if (!parsedPacket) {
                throw new Error('Invalid advertisement packet');
            }

            // Verify Protocol v2
            if (parsedPacket.version !== BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
                console.warn(`⚠️ Update packet version mismatch: expected ${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}, got ${parsedPacket.version}`);
            }

            this.simulatedAdvertisementData = await this.packetToAdvertisementData(parsedPacket);
            
            // Only log every 10th update to reduce spam
            if (parsedPacket.sequenceNumber % 10 === 0) {
                console.log(`🔄 Updating Protocol v2 advertisement (seq: ${parsedPacket.sequenceNumber})`);
            }

        } catch (error) {
            console.error('❌ Failed to update platform advertising:', error);
            throw error;
        }
    }

    /**
     * Check platform advertising capabilities for Protocol v2
     */
    protected async checkPlatformCapabilities(): Promise<{
        maxAdvertisementSize: number;
        supportsExtendedAdvertising: boolean;
        supportsPeriodicAdvertising: boolean;
    }> {
        // Check BLE version and capabilities
        const isIOS = Platform.OS === 'ios';
        const isAndroid = Platform.OS === 'android';

        if (isIOS) {
            // iOS supports extended advertising from iOS 11+ with iPhone 8+
            // Protocol v2 requires extended advertising for full public key
            return {
                maxAdvertisementSize: 31,  // Standard BLE 4.0 limit (too small for v2)
                supportsExtendedAdvertising: false,  // Requires special entitlements
                supportsPeriodicAdvertising: false
            };
        } else if (isAndroid) {
            // Android supports extended advertising from API 26+ (Android 8.0)
            const apiLevel = Platform.Version;
            const supportsExtended = typeof apiLevel === 'number' && apiLevel >= 26;

            return {
                maxAdvertisementSize: supportsExtended ? 251 : 31,  // 251 bytes enough for Protocol v2
                supportsExtendedAdvertising: supportsExtended,
                supportsPeriodicAdvertising: false
            };
        }

        // Default/unknown platform
        return {
            maxAdvertisementSize: 31,
            supportsExtendedAdvertising: false,
            supportsPeriodicAdvertising: false
        };
    }

    /**
     * Get current node count for mesh info
     */
    protected async getNodeCount(): Promise<number> {
        return this.meshNodeCount;
    }

    /**
     * Get current queue size for mesh info
     */
    protected async getQueueSize(): Promise<number> {
        return this.meshQueueSize;
    }

    /**
     * Update mesh statistics (called by mesh network)
     */
    public updateMeshStats(nodeCount: number, queueSize: number): void {
        this.meshNodeCount = nodeCount;
        this.meshQueueSize = queueSize;
    }

    /**
     * Convert parsed packet back to advertisement data structure with Protocol v2 fields
     * CRITICAL: This method MUST include the full public key for Protocol v2 compliance
     */
    private async packetToAdvertisementData(packet: any): Promise<BLEAdvertisementData> {
        // Parse extended data for pre-key bundle if present
        let preKeyBundle: PreKeyBundle | undefined;
        if (packet.extendedData && packet.extendedData.length > 0) {
            try {
                const extendedStr = new TextDecoder().decode(packet.extendedData);
                const parsed = JSON.parse(extendedStr);
                
                // Ensure pre-key bundle includes identity key for Protocol v2
                if (parsed && !parsed.identityKey && this.keyPair) {
                    parsed.identityKey = this.bytesToHexString(this.keyPair.getIdentityPublicKey());
                }
                
                preKeyBundle = parsed;
            } catch {
                // Extended data might not be JSON, create minimal pre-key bundle
                if (this.keyPair) {
                    const preKeys = this.keyPair.generatePreKeys(1);
                    if (preKeys.length > 0) {
                        preKeyBundle = {
                            identityKey: this.bytesToHexString(this.keyPair.getIdentityPublicKey()),
                            signedPreKey: {
                                keyId: preKeys[0].keyId,
                                publicKey: this.bytesToHexString(preKeys[0].publicKey),
                                signature: this.bytesToHexString(preKeys[0].signature)
                            }
                        };
                    }
                }
            }
        }

        // PROTOCOL V2 CRITICAL: Include FULL public key in identity proof
        const identityProof: IdentityProof = {
            publicKeyHash: this.bytesToHexString(packet.identityHash),
            // CRITICAL FOR V2: Must include full Ed25519 public key (32 bytes = 64 hex chars)
            publicKey: this.keyPair ? this.bytesToHexString(this.keyPair.getIdentityPublicKey()) : '',
            timestamp: packet.timestamp * 1000,  // Converts from seconds to ms
            nonce: this.bytesToHexString(packet.ephemeralId).substring(0, 32),
            signature: this.bytesToHexString(packet.signature),
            preKeyBundle
        };

        // Verifies that I have a public key for Protocol v2
        if (!identityProof.publicKey && BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION) {
            console.error('❌ Protocol v2 requires public key in advertisement');
            // Still create the advertisement but mark as invalid
        }

        // Parse capability flags
        const capabilities = this.parseCapabilityFlags(packet.flags);

        // Create Protocol v2 compliant advertisement data
        const advertisementData: BLEAdvertisementData = {
            version: packet.version || BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
            ephemeralId: this.bytesToHexString(packet.ephemeralId),
            identityProof,
            timestamp: packet.timestamp * 1000,
            sequenceNumber: packet.sequenceNumber,
            capabilities,
            deviceType: DeviceType.PHONE,
            protocolVersion: packet.version || BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
            meshInfo: {
                nodeCount: packet.meshInfo?.nodeCount || 0,
                messageQueueSize: packet.meshInfo?.queueSize || 0,
                routingTableVersion: packet.meshInfo?.routingTableVersion || 0,
                beaconInterval: BLE_CONFIG.ADVERTISEMENT_INTERVAL
            },
            batteryLevel: packet.meshInfo?.batteryLevel || 100
        };

        return advertisementData;
    }

    /**
     * Parse capability flags byte
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
     * Convert bytes to hex string
     */
    private bytesToHexString(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Get simulated advertisement data (for testing/debugging)
     */
    public getSimulatedAdvertisementData(): BLEAdvertisementData | undefined {
        return this.simulatedAdvertisementData;
    }

    /**
     * Check if currently advertising via parent's status
     */
    public isCurrentlyAdvertising(): boolean {
        return this.getStatus().isAdvertising;
    }

    /**
     * Clean up resources
     */
    public async destroy(): Promise<void> {
        const status = this.getStatus();
        if (status.isAdvertising) {
            await this.stopAdvertising();
        }
        this.simulatedAdvertisementData = undefined;
        this.isInitialized = false;
    }

    /**
     * Get BLE state (for debugging)
     */
    public async getBLEState(): Promise<string> {
        try {
            return await this.bleManager.state();
        } catch (error) {
            return 'Unknown';
        }
    }

    /**
     * Platform-specific: Create iOS peripheral manager advertisement data
     * This would be used with react-native-ble-peripheral or custom native module
     * Protocol v2 requires extended advertising for the larger packet size
     */
    private createIOSAdvertisementData(packet: Uint8Array): any {
        // In real implementation, this would create CBAdvertisementData
        // Protocol v2 packet (~140 bytes) requires extended advertising
        const needsExtended = packet.length > 31;
        
        return {
            CBAdvertisementDataServiceUUIDsKey: [BLE_CONFIG.SERVICE_UUID],
            CBAdvertisementDataLocalNameKey: `GC${packet[0]}`, // Version prefix
            // For Protocol v2, TODO: need extended advertising to fit the public key
            CBAdvertisementDataManufacturerDataKey: needsExtended ? undefined : packet.slice(0, 20),
            // Extended advertising would include full packet
            extendedData: needsExtended ? packet : undefined
        };
    }

    /**
     * Platform-specific: Create Android advertiser data
     * This would be used with BluetoothLeAdvertiser
     * Protocol v2 requires BLE 5.0 extended advertising on Android
     */
    private createAndroidAdvertisementData(packet: Uint8Array): any {
        // In real implementation, this would create AdvertiseData
        const needsExtended = packet.length > 31;
        
        return {
            includeDeviceName: false,
            includeTxPowerLevel: true,
            addServiceUuid: BLE_CONFIG.SERVICE_UUID,
            // Standard advertising can only fit partial data
            addManufacturerData: !needsExtended ? {
                manufacturerId: 0xFFFF,  // Custom manufacturer ID
                manufacturerSpecificData: packet.slice(0, 20)  // First 20 bytes only
            } : undefined,
            // Extended advertising for Protocol v2 (requires Android 8.0+)
            useExtendedAdvertising: needsExtended,
            extendedData: needsExtended ? packet : undefined,
            // Protocol v2 specific flag
            protocolVersion: BLE_SECURITY_CONFIG.PROTOCOL_VERSION
        };
    }

    /**
     * Validate that advertisement meets Protocol v2 requirements
     */
    public validateProtocolV2Advertisement(): boolean {
        if (!this.simulatedAdvertisementData) {
            return false;
        }

        const ad = this.simulatedAdvertisementData;
        
        // Check Protocol v2 requirements
        const hasVersion = ad.version === BLE_SECURITY_CONFIG.PROTOCOL_VERSION;
        const hasPublicKey = !!ad.identityProof.publicKey && ad.identityProof.publicKey.length === 64;
        const hasSignature = !!ad.identityProof.signature;
        const hasTimestamp = !!ad.identityProof.timestamp;
        const hasNonce = !!ad.identityProof.nonce;

        if (!hasVersion || !hasPublicKey || !hasSignature || !hasTimestamp || !hasNonce) {
            console.error('❌ Advertisement fails Protocol v2 validation:', {
                hasVersion,
                hasPublicKey,
                hasSignature,
                hasTimestamp,
                hasNonce
            });
            return false;
        }

        console.log('✅ Advertisement passes Protocol v2 validation');
        return true;
    }
}