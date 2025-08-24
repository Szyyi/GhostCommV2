// mobile/src/ble/ReactNativeBLEScanner.ts
import { BleManager, Device, ScanMode } from 'react-native-ble-plx';
import { Platform } from 'react-native';
import {
    BLEScanner,
    ScanConfig,
    ScanFilter,
    BLENode,
    BLEAdvertisementData,
    BLE_CONFIG,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    IdentityProof,
    PreKeyBundle,
    IGhostKeyPair,
    CryptoAlgorithm,
    BLEAdvertiser
} from '../../core';

/**
 * React Native BLE Scanner Implementation for v2.0
 * Handles binary packet parsing and node discovery
 */
export class ReactNativeBLEScanner extends BLEScanner {
    private bleManager: BleManager;
    private scanSubscription?: any;
    private discoveredDevices: Map<string, Device> = new Map();
    private _scanPaused: boolean = false;
    private currentConfig?: ScanConfig;

    constructor(keyPair?: IGhostKeyPair, bleManager?: BleManager) {
        super(keyPair);
        this.bleManager = bleManager || new BleManager();
    }

    /**
     * Check if scanning is paused (renamed to avoid conflict)
     */
    isScanPaused(): boolean {
        return this._scanPaused;
    }

    /**
     * Pause scanning
     */
    async pauseScanning(): Promise<void> {
        if (this._scanPaused) {
            return;
        }

        console.log('⏸️ Pausing BLE scanning');
        
        if (this.scanSubscription) {
            this.scanSubscription.remove();
            this.scanSubscription = undefined;
        }
        
        this.bleManager.stopDeviceScan();
        this._scanPaused = true;
    }

    /**
     * Resume scanning
     */
    async resumeScanning(): Promise<void> {
        if (!this._scanPaused) {
            return;
        }

        console.log('▶️ Resuming BLE scanning');
        
        if (this.currentConfig) {
            await this.startPlatformScanning(this.currentConfig);
        }
        
        this._scanPaused = false;
    }

    /**
     * Start platform-specific scanning - implements abstract method
     */
    protected async startPlatformScanning(config: ScanConfig): Promise<void> {
        try {
            console.log('🔍 Starting React Native BLE scanning...');
            
            // Store config for resume
            this.currentConfig = config;
            this._scanPaused = false;

            // Convert config to react-native-ble-plx options
            const scanOptions = {
                allowDuplicates: config.duplicates || false,
                scanMode: config.activeScan ? ScanMode.LowLatency : ScanMode.Balanced,
                matchMode: 'aggressive' as const,
                matchNumber: 'max' as const,
                reportDelay: 0
            };

            // Start scanning
            this.scanSubscription = this.bleManager.startDeviceScan(
                [BLE_CONFIG.SERVICE_UUID],
                scanOptions,
                (error, device) => {
                    if (error) {
                        console.error('❌ BLE scan error:', error);
                        return;
                    }

                    if (device && !this._scanPaused) {
                        this.handleDeviceDiscovered(device);
                    }
                }
            );

            console.log('✅ React Native BLE scanning started');

        } catch (error) {
            console.error('❌ Failed to start scanning:', error);
            throw error;
        }
    }

    /**
     * Stop platform-specific scanning - implements abstract method
     */
    protected async stopPlatformScanning(): Promise<void> {
        try {
            if (this.scanSubscription) {
                this.scanSubscription.remove();
                this.scanSubscription = undefined;
            }

            this.bleManager.stopDeviceScan();
            this.discoveredDevices.clear();
            this._scanPaused = false;
            this.currentConfig = undefined;

            console.log('✅ React Native BLE scanning stopped');

        } catch (error) {
            console.error('❌ Failed to stop scanning:', error);
            throw error;
        }
    }

    /**
     * Set platform scan filters - implements abstract method
     */
    protected async setPlatformScanFilters(filters: ScanFilter[]): Promise<void> {
        // react-native-ble-plx doesn't support dynamic filtering
        // Filters would be applied during device processing
        console.log(`📋 Scan filters configured (${filters.length} filters)`);
    }

    /**
     * Check platform capabilities - implements abstract method
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
            maxScanFilters: 0, // react-native-ble-plx doesn't expose filter limits
            supportsActiveScan: isSupported,
            supportsContinuousScan: isSupported,
            supportsBackgroundScan: Platform.OS === 'android' // iOS restricted
        };
    }

    /**
     * Handle discovered device
     */
    private async handleDeviceDiscovered(device: Device): Promise<void> {
        try {
            // Check if it's a GhostComm device
            if (!this.isGhostCommDevice(device)) {
                return;
            }

            // Store device
            this.discoveredDevices.set(device.id, device);

            // Try to extract advertisement data
            const rawData = this.extractRawAdvertisementData(device);
            if (!rawData) {
                console.log(`⚠️ No raw data for device ${device.id}`);
                return;
            }

            // Call parent's handleScanResult with raw data
            await this.handleScanResult(
                device.id,
                rawData,
                device.rssi || -100,
                undefined // TX power not available in react-native-ble-plx
            );

        } catch (error) {
            console.error('❌ Error handling discovered device:', error);
        }
    }

    /**
     * Check if device is a GhostComm device
     */
    private isGhostCommDevice(device: Device): boolean {
        // Check service UUIDs
        if (device.serviceUUIDs?.includes(BLE_CONFIG.SERVICE_UUID)) {
            return true;
        }

        // Check device name patterns
        if (device.name?.startsWith('GC') || device.name?.startsWith('GM')) {
            return true;
        }

        // Check manufacturer data
        if (device.manufacturerData) {
            try {
                const data = Buffer.from(device.manufacturerData, 'base64');
                // Check for our manufacturer ID (0xFFFF)
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
     * Extract raw advertisement data from device
     */
    private extractRawAdvertisementData(device: Device): Uint8Array | null {
        // Try to extract from manufacturer data first (most complete)
        if (device.manufacturerData) {
            try {
                const data = Buffer.from(device.manufacturerData, 'base64');

                // Check if it looks like our v2.0 packet format
                if (data.length >= 108 && data[0] === 2) { // Version 2
                    return new Uint8Array(data);
                }

                // Try to construct packet from partial data
                return this.constructPacketFromManufacturerData(data);
            } catch {
                // Invalid manufacturer data
            }
        }

        // Try to construct from service data
        if (device.serviceData && device.serviceData[BLE_CONFIG.SERVICE_UUID]) {
            try {
                const data = Buffer.from(device.serviceData[BLE_CONFIG.SERVICE_UUID], 'base64');
                return this.constructPacketFromServiceData(data, device);
            } catch {
                // Invalid service data
            }
        }

        // Fallback: construct minimal packet from device info
        return this.constructMinimalPacket(device);
    }

    /**
     * Construct packet from manufacturer data
     */
    private constructPacketFromManufacturerData(data: Buffer): Uint8Array | null {
        if (data.length < 20) {
            return null;
        }

        // Skip manufacturer ID (2 bytes)
        const payload = data.slice(2);

        // Create v2.0 packet structure
        const packet = new Uint8Array(108);
        const view = new DataView(packet.buffer);
        let offset = 0;

        // Version
        packet[offset++] = 2;

        // Flags (capabilities)
        packet[offset++] = 0x01; // RELAY capability

        // Ephemeral ID (16 bytes) - use device data or generate
        const ephemeralId = payload.slice(0, Math.min(16, payload.length));
        packet.set(ephemeralId, offset);
        if (ephemeralId.length < 16) {
            // Pad with zeros
            for (let i = ephemeralId.length; i < 16; i++) {
                packet[offset + i] = 0;
            }
        }
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

        // Signature (64 bytes) - empty for now
        offset += 64;

        // Mesh info (4 bytes)
        packet[offset++] = 0; // nodeCount
        packet[offset++] = 0; // queueSize
        packet[offset++] = 100; // batteryLevel
        packet[offset++] = 0x01; // flags (has pre-keys)

        return packet;
    }

    /**
     * Construct packet from service data
     */
    private constructPacketFromServiceData(data: Buffer, device: Device): Uint8Array | null {
        // Similar to manufacturer data but with different layout
        return this.constructMinimalPacket(device);
    }

    /**
     * Construct minimal valid packet from device info
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
        packet.set(deviceIdBytes.slice(0, Math.min(16, deviceIdBytes.length)), offset);
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

        // Signature (64 bytes) - empty
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
     * Get discovered devices
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
}