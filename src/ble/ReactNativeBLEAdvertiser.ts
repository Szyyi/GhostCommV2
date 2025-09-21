// mobile/src/ble/ReactNativeBLEAdvertiser.ts
import { Platform } from 'react-native';
import BLEAdvertiser from 'react-native-ble-advertiser';
import {
    BLEAdvertiser as BaseBLEAdvertiser,
    BLEAdvertisementData,
    BLE_CONFIG,
    NodeCapability,
    DeviceType,
    IGhostKeyPair,
    parseAdvertisementPacket
} from '../../core';
import { AdvertisementPacket } from '../../core/src/ble/advertiser';
import { BLE_SECURITY_CONFIG } from '../../core/src/ble/types';
import { Buffer } from 'buffer';

/**
 * React Native BLE Advertiser for Protocol v2.1
 * Uses react-native-ble-advertiser for actual BLE broadcasting
 */
export class ReactNativeBLEAdvertiser extends BaseBLEAdvertiser {
    private isInitialized: boolean = false;
    // Note: isAdvertising is handled by base class
    
    // Platform capabilities
    private capabilities = {
        maxAdvertisementSize: 31,
        supportsExtendedAdvertising: false,
        androidApiLevel: 0
    };

    // Mesh tracking
    private meshNodeCount: number = 0;
    private meshQueueSize: number = 0;

    constructor(keyPair?: IGhostKeyPair) {
        super(keyPair);
        this.checkPlatformCapabilities();
    }

    /**
     * Initialize BLE advertiser
     */
    private async ensureInitialized(): Promise<void> {
        if (this.isInitialized) {
            return;
        }

        try {
            // Request permissions on Android
            if (Platform.OS === 'android') {
                const granted = await BLEAdvertiser.requestBTPermissions();
                if (!granted) {
                    throw new Error('Bluetooth permissions not granted');
                }
                console.log('✅ Bluetooth permissions granted');
            }

            // Enable Bluetooth adapter
            await BLEAdvertiser.enableAdapter();
            
            this.isInitialized = true;
            console.log('✅ BLE Advertiser initialized');

        } catch (error) {
            console.error('❌ Failed to initialize BLE Advertiser:', error);
            throw error;
        }
    }

    /**
     * Start platform-specific advertising
     */
    protected async startPlatformAdvertising(packet: Uint8Array): Promise<void> {
        try {
            await this.ensureInitialized();

            // Stop any existing advertisement
            if (this.getStatus().isAdvertising) {
                await BLEAdvertiser.stopBroadcast();
            }

            // Parse packet for validation
            const parsedPacket = BaseBLEAdvertiser.parseAdvertisementPacket(packet);
            if (!parsedPacket) {
                throw new Error('Invalid advertisement packet');
            }

            // Set service UUID
            BLEAdvertiser.setServiceUUID(BLE_CONFIG.SERVICE_UUID);

            // Create truncated packet (BLE 4.x limited to 31 bytes)
            const truncatedPacket = this.createTruncatedPacket(packet);
            
            // Convert to hex string for the library
            const dataHex = Buffer.from(truncatedPacket).toString('hex');
            
            // Broadcast the data - this will update base class state
            await BLEAdvertiser.broadcast(
                BLE_CONFIG.SERVICE_UUID,  // Service UUID
                dataHex,                   // Data as hex string
                {}                         // Options
            );

            console.log(`📡 Started BLE advertisement:`);
            console.log(`  - Packet size: ${truncatedPacket.length} bytes`);
            console.log(`  - Service UUID: ${BLE_CONFIG.SERVICE_UUID}`);

        } catch (error) {
            console.error('❌ Failed to start advertising:', error);
            throw error;
        }
    }

    /**
     * Create truncated packet for BLE advertising
     */
    private createTruncatedPacket(fullPacket: Uint8Array): Uint8Array {
        // BLE 4.x advertising limited to 31 bytes
        // Include most important Protocol v2.1 fields:
        // - Version (1 byte)
        // - Flags (1 byte)
        // - Ephemeral ID partial (8 bytes)
        // - Identity hash (8 bytes)
        // - Sequence hint (2 bytes)
        // Total: 20 bytes
        
        const truncated = new Uint8Array(20);
        let offset = 0;

        // Version
        truncated[offset++] = fullPacket[0];
        
        // Flags
        truncated[offset++] = fullPacket[1];
        
        // Ephemeral ID (first 8 bytes)
        if (fullPacket.length >= 18) {
            truncated.set(fullPacket.slice(2, 10), offset);
            offset += 8;
        }
        
        // Identity hash (8 bytes)
        if (fullPacket.length >= 26) {
            truncated.set(fullPacket.slice(18, 26), offset);
            offset += 8;
        }
        
        // Sequence hint (2 bytes)
        if (fullPacket.length >= 60) {
            truncated[offset++] = fullPacket[58];
            truncated[offset++] = fullPacket[59];
        }

        return truncated;
    }

    /**
     * Stop platform-specific advertising
     */
    protected async stopPlatformAdvertising(): Promise<void> {
        try {
            await BLEAdvertiser.stopBroadcast();
            console.log('🛑 Stopped BLE advertising');
        } catch (error) {
            console.error('❌ Failed to stop advertising:', error);
        }
    }

    /**
     * Update platform advertising
     */
    protected async updatePlatformAdvertising(packet: Uint8Array): Promise<void> {
        // Need to restart with new packet
        await this.startPlatformAdvertising(packet);
    }

    /**
     * Check platform capabilities
     */
    protected async checkPlatformCapabilities(): Promise<{
        maxAdvertisementSize: number;
        supportsExtendedAdvertising: boolean;
        supportsPeriodicAdvertising: boolean;
    }> {
        if (Platform.OS === 'android') {
            const apiLevel = Platform.Version;
            this.capabilities.androidApiLevel = typeof apiLevel === 'number' ? apiLevel : 0;
        }

        return {
            maxAdvertisementSize: 31,
            supportsExtendedAdvertising: false,
            supportsPeriodicAdvertising: false
        };
    }

    /**
     * Get node count
     */
    protected async getNodeCount(): Promise<number> {
        return this.meshNodeCount;
    }

    /**
     * Get queue size
     */
    protected async getQueueSize(): Promise<number> {
        return this.meshQueueSize;
    }

    /**
     * Update mesh statistics
     */
    public updateMeshStats(nodeCount: number, queueSize: number): void {
        this.meshNodeCount = nodeCount;
        this.meshQueueSize = queueSize;
    }

    /**
     * Check if currently advertising
     * Note: Don't override base class private property
     */
    public isCurrentlyAdvertising(): boolean {
        return this.getStatus().isAdvertising;
    }

    /**
     * Clean up
     */
    public async destroy(): Promise<void> {
        if (this.getStatus().isAdvertising) {
            await this.stopAdvertising();
        }
        this.isInitialized = false;
    }

    /**
     * Test advertisement
     */
    public async testAdvertisement(): Promise<void> {
        try {
            console.log('🧪 Testing BLE advertisement...');
            
            const testPacket = new Uint8Array(20);
            testPacket[0] = BLE_SECURITY_CONFIG.PROTOCOL_VERSION;
            testPacket[1] = 0x01;
            
            for (let i = 2; i < 20; i++) {
                testPacket[i] = i;
            }
            
            await this.startPlatformAdvertising(testPacket);
            
            console.log('✅ Test successful');
            
            setTimeout(() => {
                this.stopPlatformAdvertising();
            }, 3000);
            
        } catch (error) {
            console.error('❌ Test failed:', error);
            throw error;
        }
    }
}