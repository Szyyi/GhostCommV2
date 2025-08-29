// mobile/src/ble/ReactNativeBLEScanner.ts
import { BleManager, Device, ScanMode } from 'react-native-ble-plx';
import { Platform } from 'react-native';
import {
    BLEScanner,
    ScanConfig,
    ScanFilter,
    BLE_CONFIG,
    IGhostKeyPair
} from '../../core';

/**
 * React Native BLE Scanner Implementation
 * 
 * This class ONLY implements platform-specific scanning operations.
 * All Protocol v2 verification, public key extraction, and security features
 * are handled by the base BLEScanner class.
 */
export class ReactNativeBLEScanner extends BLEScanner {
    private bleManager: BleManager;
    private scanSubscription?: any;
    private discoveredDevices: Map<string, Device> = new Map();
    private currentConfig?: ScanConfig;

    constructor(keyPair?: IGhostKeyPair, bleManager?: BleManager) {
        super(keyPair);
        this.bleManager = bleManager || new BleManager();
    }

    /**
     * Platform-specific: Start BLE scanning
     * The base class handles all Protocol v2 verification
     */
    protected async startPlatformScanning(config: ScanConfig): Promise<void> {
        try {
            console.log(' Starting React Native BLE scanning...');
            
            // Store config for potential resume operations
            this.currentConfig = config;

            // Convert config to react-native-ble-plx options
            const scanOptions = {
                allowDuplicates: config.duplicates || false,
                scanMode: config.activeScan ? ScanMode.LowLatency : ScanMode.Balanced,
                matchMode: 'aggressive' as const,
                matchNumber: 'max' as const,
                reportDelay: 0
            };

            // Start scanning with optional service UUID filter
            this.scanSubscription = this.bleManager.startDeviceScan(
                [BLE_CONFIG.SERVICE_UUID], // Filter for GhostComm service
                scanOptions,
                (error, device) => {
                    if (error) {
                        console.error('❌ BLE scan error:', error);
                        return;
                    }

                    if (device) {
                        this.handleDeviceDiscovered(device);
                    }
                }
            );

            console.log(' React Native BLE scanning started');

        } catch (error) {
            console.error(' Failed to start scanning:', error);
            throw error;
        }
    }

    /**
     * Platform-specific: Stop BLE scanning
     */
    protected async stopPlatformScanning(): Promise<void> {
        try {
            if (this.scanSubscription) {
                this.scanSubscription.remove();
                this.scanSubscription = undefined;
            }

            this.bleManager.stopDeviceScan();
            this.discoveredDevices.clear();
            this.currentConfig = undefined;

            console.log(' React Native BLE scanning stopped');

        } catch (error) {
            console.error(' Failed to stop scanning:', error);
            throw error;
        }
    }

    /**
     * Platform-specific: Set scan filters
     * Note: react-native-ble-plx has limited filter support
     */
    protected async setPlatformScanFilters(filters: ScanFilter[]): Promise<void> {
        // react-native-ble-plx doesn't support dynamic filtering beyond service UUIDs
        // Filters are applied by the base class after receiving scan results
        console.log(` Scan filters configured (${filters.length} filters) - will be applied by base class`);
    }

    /**
     * Platform-specific: Check scanning capabilities
     */
    protected async checkPlatformCapabilities(): Promise<{
        maxScanFilters: number;
        supportsActiveScan: boolean;
        supportsContinuousScan: boolean;
        supportsBackgroundScan: boolean;
    }> {
        const state = await this.bleManager.state();
        const isSupported = state === 'PoweredOn';

        return {
            maxScanFilters: 1, // react-native-ble-plx only supports service UUID filtering
            supportsActiveScan: isSupported,
            supportsContinuousScan: isSupported,
            supportsBackgroundScan: Platform.OS === 'android' // iOS has restrictions
        };
    }

    /**
     * Handle discovered device and extract raw advertisement data
     */
    private async handleDeviceDiscovered(device: Device): Promise<void> {
        try {
            // Check if it's a GhostComm device
            if (!this.isGhostCommDevice(device)) {
                return;
            }

            // Store device for reference
            this.discoveredDevices.set(device.id, device);

            // Extract raw advertisement data
            const rawData = this.extractRawAdvertisementData(device);
            if (!rawData) {
                console.log(`⚠️ Could not extract advertisement data from device ${device.id}`);
                return;
            }

            await this.handleScanResult(
                device.id,
                rawData,
                device.rssi || -100,
                device.txPowerLevel ?? undefined // Convert null to undefined
            );

        } catch (error) {
            console.error(' Error handling discovered device:', error);
        }
    }

    /**
     * Check if device is advertising GhostComm service
     */
    private isGhostCommDevice(device: Device): boolean {
        // Check service UUIDs
        if (device.serviceUUIDs?.some(uuid => 
            uuid.toLowerCase() === BLE_CONFIG.SERVICE_UUID.toLowerCase()
        )) {
            return true;
        }

        // Check device name patterns
        if (device.name?.startsWith('GC') || device.name?.startsWith('GM')) {
            return true;
        }

        // Check manufacturer data for our ID
        if (device.manufacturerData) {
            try {
                const data = Buffer.from(device.manufacturerData, 'base64');
                // Check for our manufacturer ID (0xFFFF for testing)
                if (data.length >= 2 && data[0] === 0xFF && data[1] === 0xFF) {
                    return true;
                }
            } catch {
                // Invalid manufacturer data
            }
        }

        return false;
    }

    /**
     * Extract raw advertisement data from React Native BLE device
     */
    private extractRawAdvertisementData(device: Device): Uint8Array | null {
        // Priority 1: Manufacturer data (most complete)
        if (device.manufacturerData) {
            try {
                const data = Buffer.from(device.manufacturerData, 'base64');
                
                // Check if it's already a complete v2 packet
                if (data.length >= 108 && data[0] === 2) { // Version 2
                    return new Uint8Array(data);
                }

                // If it's partial, try to reconstruct
                if (data.length > 2) {
                    return this.reconstructPacketFromManufacturerData(data);
                }
            } catch (error) {
                console.warn('Failed to parse manufacturer data:', error);
            }
        }

        // Priority 2: Service data
        if (device.serviceData) {
            const serviceData = device.serviceData[BLE_CONFIG.SERVICE_UUID];
            if (serviceData) {
                try {
                    const data = Buffer.from(serviceData, 'base64');
                    if (data.length >= 108 && data[0] === 2) {
                        return new Uint8Array(data);
                    }
                } catch (error) {
                    console.warn('Failed to parse service data:', error);
                }
            }
        }

        // Priority 3: Construct minimal packet for compatibility
        // This allows the scanner to at least track the device
        return this.constructMinimalPacket(device);
    }

    /**
     * Reconstruct packet from partial manufacturer data
     */
    private reconstructPacketFromManufacturerData(data: Buffer): Uint8Array | null {
        // Skip manufacturer ID (first 2 bytes)
        const payload = data.slice(2);
        
        if (payload.length < 20) {
            return null; // Too small to be useful
        }

        // Create a minimal v2 packet structure (108 bytes)
        const packet = new Uint8Array(108);
        const view = new DataView(packet.buffer);
        let offset = 0;

        // Version (1 byte)
        packet[offset++] = 2;

        // Flags (1 byte) - capabilities
        packet[offset++] = 0x01; // RELAY capability

        // Ephemeral ID (16 bytes)
        const ephemeralBytes = payload.slice(0, Math.min(16, payload.length));
        packet.set(ephemeralBytes, offset);
        offset += 16;

        // Identity hash (8 bytes)
        if (payload.length > 16) {
            packet.set(payload.slice(16, Math.min(24, payload.length)), offset);
        }
        offset += 8;

        // Sequence number (4 bytes)
        view.setUint32(offset, Date.now() % 0xFFFFFFFF, false);
        offset += 4;

        // Timestamp (4 bytes)
        view.setUint32(offset, Math.floor(Date.now() / 1000), false);
        offset += 4;

        // Signature (64 bytes) - will be empty/invalid
        offset += 64;

        // Mesh info (4 bytes)
        packet[offset++] = 0; // nodeCount
        packet[offset++] = 0; // queueSize  
        packet[offset++] = 100; // batteryLevel
        packet[offset++] = 0; // flags

        return packet;
    }

    /**
     * Construct minimal packet when no advertisement data available
     * This allows basic device tracking even without proper advertisements
     */
    private constructMinimalPacket(device: Device): Uint8Array {
        const packet = new Uint8Array(108);
        const view = new DataView(packet.buffer);
        let offset = 0;

        // Version
        packet[offset++] = 2;

        // Flags
        packet[offset++] = 0x01; // RELAY

        // Ephemeral ID (16 bytes) - derive from device ID
        const deviceIdBytes = new TextEncoder().encode(device.id);
        const ephemeralId = new Uint8Array(16);
        ephemeralId.set(deviceIdBytes.slice(0, Math.min(16, deviceIdBytes.length)));
        packet.set(ephemeralId, offset);
        offset += 16;

        // Identity hash (8 bytes) - derive from device ID
        const hash = this.simpleHash(device.id);
        view.setUint32(offset, hash, false);
        view.setUint32(offset + 4, hash, false);
        offset += 8;

        // Sequence number
        view.setUint32(offset, Date.now() % 0xFFFFFFFF, false);
        offset += 4;

        // Timestamp
        view.setUint32(offset, Math.floor(Date.now() / 1000), false);
        offset += 4;

        // Signature (64 bytes) - empty (will fail verification)
        offset += 64;

        // Mesh info
        packet[offset++] = 1; // nodeCount
        packet[offset++] = 0; // queueSize
        packet[offset++] = 100; // batteryLevel
        packet[offset++] = 0; // flags

        return packet;
    }

    /**
     * Simple hash function for device ID
     */
    private simpleHash(str: string): number {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = ((hash << 5) - hash) + str.charCodeAt(i);
            hash = hash & hash;
        }
        return Math.abs(hash);
    }

    /**
     * Additional helpers for React Native
     */
    
    /**
     * Get discovered devices (React Native specific)
     */
    getDiscoveredDevices(): Map<string, Device> {
        return new Map(this.discoveredDevices);
    }

    /**
     * Check BLE scanning support
     */
    async checkScanningSupport(): Promise<{
        supported: boolean;
        bluetoothState: string;
        permissions: boolean;
    }> {
        try {
            const state = await this.bleManager.state();
            return {
                supported: state === 'PoweredOn',
                bluetoothState: state,
                permissions: true // Assumed granted if we got this far
            };
        } catch (error) {
            return {
                supported: false,
                bluetoothState: 'Unknown',
                permissions: false
            };
        }
    }

    /**
     * Pause scanning (React Native specific)
     */
    async pauseScanning(): Promise<void> {
        if (this.scanSubscription) {
            this.scanSubscription.remove();
            this.scanSubscription = undefined;
        }
        this.bleManager.stopDeviceScan();
        console.log(' Scanning paused');
    }

    /**
     * Resume scanning (React Native specific)
     */
    async resumeScanning(): Promise<void> {
        if (this.currentConfig) {
            await this.startPlatformScanning(this.currentConfig);
            console.log(' Scanning resumed');
        }
    }
}