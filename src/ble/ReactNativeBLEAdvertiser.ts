// mobile/src/ble/ReactNativeBLEAdvertiser.ts
// Complete working version for react-native-ble-advertiser with iBeacon format

import { Platform, NativeModules } from 'react-native';
import BLEAdvertiser from 'react-native-ble-advertiser';
import {
    BLEAdvertiser as BaseBLEAdvertiser,
    BLE_CONFIG,
    IGhostKeyPair,
} from '../../core';
import { BLE_SECURITY_CONFIG } from '../../core/src/ble/types';
import { requestBLEPermissions } from '../utils/blePermissions';
import { Buffer } from 'buffer';

/**
 * React Native BLE Advertiser for Protocol v2.1
 * Works with react-native-ble-advertiser using iBeacon format
 */
export class ReactNativeBLEAdvertiser extends BaseBLEAdvertiser {
    private isInitialized: boolean = false;
    private isEmulator: boolean = false;
    private mockInterval?: NodeJS.Timeout;
    
    // iBeacon values derived from identity
    private uuidString: string = BLE_CONFIG.SERVICE_UUID;
    private majorValue: number = 0;
    private minorValue: number = 0;
    
    constructor(keyPair?: IGhostKeyPair) {
        super(keyPair);
        this.checkIfEmulator();
        this.generateBeaconValues();
    }

    /**
     * Check if running in emulator
     */
    private checkIfEmulator(): void {
        const isAndroidEmulator = Platform.OS === 'android' && (
            Platform.constants?.Fingerprint?.includes('generic') ||
            Platform.constants?.Model?.includes('sdk') ||
            Platform.constants?.Brand === 'google'
        );
        
        const isIOSSimulator = Platform.OS === 'ios' && (
            Platform.constants?.interfaceIdiom === 'pad' && !Platform.isPad
        );
        
        this.isEmulator = isAndroidEmulator || isIOSSimulator;
        
        if (this.isEmulator) {
            console.log('📱 Detected emulator environment - using mock advertising');
        }
    }

    /**
     * Generate major/minor values from identity
     */
    private generateBeaconValues(): void {
        if (this.keyPair) {
            const fingerprint = this.keyPair.getFingerprint();
            // Convert hex fingerprint to bytes for major/minor extraction
            const bytes = this.hexStringToBytes(fingerprint);
            
            // Use first 2 bytes for major, next 2 for minor
            this.majorValue = (bytes[0] << 8) | bytes[1];
            this.minorValue = (bytes[2] << 8) | bytes[3];
        } else {
            // Random values if no keypair
            this.majorValue = Math.floor(Math.random() * 65535);
            this.minorValue = Math.floor(Math.random() * 65535);
        }
        
        // Ensure values are valid 16-bit unsigned integers
        this.majorValue = this.majorValue & 0xFFFF;
        this.minorValue = this.minorValue & 0xFFFF;
        
        console.log(`📡 iBeacon identity: UUID=${this.uuidString}`);
        console.log(`   Major=${this.majorValue}, Minor=${this.minorValue}`);
    }

    /**
     * Helper to convert hex string to bytes
     */
    private hexStringToBytes(hex: string): Uint8Array {
        // Remove any non-hex characters
        hex = hex.replace(/[^0-9a-fA-F]/g, '');
        
        // Ensure even length
        if (hex.length % 2 !== 0) {
            hex = '0' + hex;
        }
        
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    /**
     * Initialize BLE advertiser
     */
    private async ensureInitialized(): Promise<void> {
        if (this.isInitialized) {
            return;
        }

        try {
            // Request permissions
            if (Platform.OS === 'android') {
                const granted = await requestBLEPermissions();
                if (!granted) {
                    console.warn('⚠️ BLE permissions not fully granted');
                }
            }

            // Only try BLE operations on real devices
            if (!this.isEmulator) {
                try {
                    // Set company ID for iBeacon
                    // 0x004C is Apple's company ID for iBeacon, but we'll use a test ID
                    BLEAdvertiser.setCompanyId(0xFFFF);
                    console.log('✅ Company ID set');
                } catch (error) {
                    console.warn('⚠️ Could not set company ID:', error);
                }

                // Check adapter state
                try {
                    BLEAdvertiser.getAdapterState()
                        .then((result: string) => {
                            console.log('📡 BLE Adapter state:', result);
                            if (result === 'STATE_OFF') {
                                console.log('📡 Attempting to enable Bluetooth...');
                                BLEAdvertiser.enableAdapter();
                            }
                        })
                        .catch((error: any) => {
                            console.warn('⚠️ Could not check adapter state:', error);
                        });
                } catch (error) {
                    console.warn('⚠️ Adapter state check failed:', error);
                }
            }
            
            this.isInitialized = true;
            console.log('✅ BLE Advertiser initialized');

        } catch (error) {
            console.error('❌ Failed to initialize BLE Advertiser:', error);
            this.isInitialized = true; // Continue anyway
        }
    }

    /**
     * Start platform-specific advertising
     */
    protected async startPlatformAdvertising(packet: Uint8Array): Promise<void> {
        try {
            await this.ensureInitialized();

            // Use mock advertising in emulator
            if (this.isEmulator) {
                console.log('🎭 Emulator: Starting mock advertising');
                this.startMockAdvertising();
                return;
            }

            // Stop any existing advertisement
            try {
                BLEAdvertiser.stopBroadcast();
            } catch (e) {
                // Ignore if not advertising
            }

            // Extract identity from packet to update major/minor if needed
            if (packet.length >= 4) {
                // Update major/minor from packet data for identity correlation
                this.majorValue = (packet[0] << 8) | packet[1];
                this.minorValue = (packet[2] << 8) | packet[3];
                
                // Ensure valid range
                this.majorValue = this.majorValue & 0xFFFF;
                this.minorValue = this.minorValue & 0xFFFF;
            }

            console.log(`📡 Starting iBeacon broadcast:`);
            console.log(`   UUID: ${this.uuidString}`);
            console.log(`   Major: ${this.majorValue} (0x${this.majorValue.toString(16).padStart(4, '0')})`);
            console.log(`   Minor: ${this.minorValue} (0x${this.minorValue.toString(16).padStart(4, '0')})`);

            // The react-native-ble-advertiser broadcast method signature:
            // broadcast(uuid: string, major: number, minor: number, options?: object)
            // Note: The library converts the numbers internally, we pass them as numbers
            
            // Call with promise handling
            const broadcastPromise = BLEAdvertiser.broadcast(
                this.uuidString,
                this.majorValue.toString(),
                this.minorValue.toString()
            );

            // Handle the promise if it exists
            if (broadcastPromise && typeof broadcastPromise.then === 'function') {
                await broadcastPromise
                    .then(() => {
                        console.log('✅ iBeacon broadcasting started successfully');
                    })
                    .catch((error: any) => {
                        console.error('❌ Broadcast error:', error);
                        console.log('🎭 Falling back to mock advertising');
                        this.startMockAdvertising();
                    });
            } else {
                // If broadcast doesn't return a promise, assume it worked
                console.log('✅ iBeacon broadcast initiated (synchronous)');
            }

        } catch (error) {
            console.error('❌ Failed to start advertising:', error);
            console.log('🎭 Falling back to mock advertising');
            this.startMockAdvertising();
        }
    }

    /**
     * Start mock advertising for emulator/fallback
     */
    private startMockAdvertising(): void {
        if (this.mockInterval) {
            clearInterval(this.mockInterval);
        }

        console.log('🎭 Starting mock advertisement');
        
        // Log initial broadcast
        console.log(`🎭 Mock broadcasting: UUID=${this.uuidString}, Major=${this.majorValue}, Minor=${this.minorValue}`);
        
        // Simulate periodic broadcasts
        this.mockInterval = setInterval(() => {
            console.log(`🎭 Mock beacon pulse: ${new Date().toLocaleTimeString()}`);
        }, 5000); // Every 5 seconds
    }

    /**
     * Stop platform-specific advertising
     */
    protected async stopPlatformAdvertising(): Promise<void> {
        try {
            // Clear mock interval if exists
            if (this.mockInterval) {
                clearInterval(this.mockInterval);
                this.mockInterval = undefined;
                console.log('🎭 Stopped mock advertising');
            }

            // Only try to stop real advertising on real devices
            if (!this.isEmulator) {
                try {
                    BLEAdvertiser.stopBroadcast();
                    console.log('🛑 Stopped iBeacon broadcasting');
                } catch (error) {
                    // Might fail if not broadcasting, ignore
                    console.warn('⚠️ Stop broadcast warning:', error);
                }
            }
        } catch (error) {
            console.error('❌ Failed to stop advertising:', error);
        }
    }

    /**
     * Update platform advertising
     */
    protected async updatePlatformAdvertising(packet: Uint8Array): Promise<void> {
        // iBeacon doesn't support updates, need to restart
        console.log('📡 Updating advertisement (restart required for iBeacon)');
        await this.stopPlatformAdvertising();
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
        // iBeacon has fixed format with limited data
        return {
            maxAdvertisementSize: 31, // iBeacon is within BLE 4.x limits
            supportsExtendedAdvertising: false,
            supportsPeriodicAdvertising: false
        };
    }

    /**
     * Get node count (mesh info)
     */
    protected async getNodeCount(): Promise<number> {
        // This would come from your mesh network manager
        return 0;
    }

    /**
     * Get queue size (mesh info)
     */
    protected async getQueueSize(): Promise<number> {
        // This would come from your message queue
        return 0;
    }

    /**
     * Check if currently advertising
     */
    public isCurrentlyAdvertising(): boolean {
        return this.getStatus().isAdvertising || this.mockInterval !== undefined;
    }

    /**
     * Check if running in mock mode
     */
    public isInMockMode(): boolean {
        return this.isEmulator || this.mockInterval !== undefined;
    }

    /**
     * Get iBeacon values for debugging
     */
    public getBeaconValues(): { uuid: string; major: number; minor: number } {
        return {
            uuid: this.uuidString,
            major: this.majorValue,
            minor: this.minorValue
        };
    }

    /**
     * Clean up resources
     */
    public async destroy(): Promise<void> {
        if (this.mockInterval) {
            clearInterval(this.mockInterval);
            this.mockInterval = undefined;
        }
        
        if (this.getStatus().isAdvertising) {
            await this.stopAdvertising();
        }
        
        this.isInitialized = false;
        console.log('🧹 BLE Advertiser destroyed');
    }
}