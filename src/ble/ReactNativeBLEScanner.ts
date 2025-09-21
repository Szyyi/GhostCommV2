// mobile/src/ble/ReactNativeBLEScanner.ts
import { 
    BleManager, 
    Device, 
    ScanMode,
    State,
    Subscription,
    BleError
} from 'react-native-ble-plx';
import { Platform } from 'react-native';
import {
    BLEScanner,
    ScanConfig,
    ScanFilter,
    BLE_CONFIG,
    IGhostKeyPair,
    NodeCapability,
    SECURITY_CONFIG
} from '../../core';
import { Buffer } from 'buffer';
import { BLE_SECURITY_CONFIG } from '../../core/src/ble/types';

/**
 * React Native BLE Scanner Implementation with Protocol v2.1 Compliance
 * 
 * This class implements platform-specific BLE scanning operations for React Native
 * while delegating all Protocol v2.1 security verification to the base BLEScanner class.
 * 
 * Protocol v2.1 Compliance:
 * - Extracts raw advertisement data for base class verification
 * - Supports 108-byte Protocol v2.1 packet structure
 * - Handles signature verification through base class
 * - Implements replay protection via base class
 * 
 * Platform Optimizations:
 * - Android: Duty cycle scanning, multiple scan modes
 * - iOS: Continuous scanning with system optimization
 * - Both: Service UUID filtering, duplicate management
 */
export class ReactNativeBLEScanner extends BLEScanner {
    private bleManager: BleManager;
    private scanSubscription?: Subscription;
    private discoveredDevices: Map<string, Device> = new Map();
    private currentConfig?: ScanConfig;
    
    // Performance tracking
    private scanStartTime?: number;
    private devicesScannedCount: number = 0;
    private lastScanError?: Error;
    private scanStatistics = {
        totalScanned: 0,
        ghostCommDevices: 0,
        verifiedDevices: 0,
        failedVerifications: 0
    };
    
    // Android duty cycle optimization
    private dutyCycleTimer?: NodeJS.Timeout;
    private isDutyCyclePaused: boolean = false;
    private dutyCycleConfig = {
        scanTime: 10000,  // 10 seconds scan
        pauseTime: 5000    // 5 seconds pause
    };
    
    // Duplicate filtering with sliding window
    private recentDevices: Map<string, { timestamp: number; updateCount: number }> = new Map();
    private duplicateWindow: number = 5000; // 5 seconds
    // Note: cleanupTimer is inherited from base class as protected
    private duplicateCleanupTimer?: NodeJS.Timeout;

    constructor(keyPair?: IGhostKeyPair, bleManager?: BleManager) {
        super(keyPair);
        this.bleManager = bleManager || new BleManager();
        
        // Start cleanup timer for duplicate cache
        this.startDuplicateCleanupTimer();
        
        console.log(`📡 [RN-Scanner] Initialized with Protocol v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}.1`);
    }

    /**
     * Platform-specific: Start BLE scanning
     * Configures platform-specific scanning while Protocol v2.1 verification
     * is handled by the base BLEScanner class
     */
    protected async startPlatformScanning(config: ScanConfig): Promise<void> {
        try {
            console.log('🔍 [RN-Scanner] Starting BLE scan...');
            
            // Verify BLE is ready
            const state = await this.bleManager.state();
            if (state !== State.PoweredOn) {
                throw new Error(`BLE not ready: ${state}`);
            }
            
            // Store configuration
            this.currentConfig = config;
            this.scanStartTime = Date.now();
            this.devicesScannedCount = 0;
            
            // Configure scan options based on platform and requirements
            const scanOptions = this.createOptimizedScanOptions(config);
            
            // Service UUID filter for efficiency (null scans all)
            const serviceUUIDs = config.filterByService !== false 
                ? [BLE_CONFIG.SERVICE_UUID] 
                : null;
            
            // Start scanning with error handling
            this.scanSubscription = this.bleManager.startDeviceScan(
                serviceUUIDs,
                scanOptions,
                (error, device) => {
                    if (error) {
                        this.handleScanError(error);
                        return;
                    }
                    
                    if (device) {
                        this.processDiscoveredDevice(device);
                    }
                }
            ) as any as Subscription;
            
            console.log(`✅ [RN-Scanner] Scanning started on ${Platform.OS} with mode: ${scanOptions.scanMode}`);
            
            // Setup Android duty cycle if configured
            if (Platform.OS === 'android' && config.dutyCycle !== false) {
                this.setupAndroidDutyCycle();
            }
            
        } catch (error) {
            console.error('❌ [RN-Scanner] Failed to start scanning:', error);
            this.lastScanError = error as Error;
            throw error;
        }
    }

    /**
     * Platform-specific: Stop BLE scanning
     */
    protected async stopPlatformScanning(): Promise<void> {
        try {
            console.log('🛑 [RN-Scanner] Stopping BLE scan...');
            
            // Clear duty cycle
            this.clearDutyCycle();
            
            // Remove scan subscription
            if (this.scanSubscription) {
                this.scanSubscription.remove();
                this.scanSubscription = undefined;
            }
            
            // Stop BLE scanning
            this.bleManager.stopDeviceScan();
            
            // Log statistics
            this.logScanStatistics();
            
            // Clear state
            this.discoveredDevices.clear();
            this.currentConfig = undefined;
            this.isDutyCyclePaused = false;
            
            console.log('✅ [RN-Scanner] Scanning stopped');
            
        } catch (error) {
            console.error('❌ [RN-Scanner] Error stopping scan:', error);
            throw error;
        }
    }

    /**
     * Platform-specific: Set scan filters
     * react-native-ble-plx only supports service UUID filtering at platform level
     */
    protected async setPlatformScanFilters(filters: ScanFilter[]): Promise<void> {
        // Filters are applied by base class after scan results
        console.log(`🔧 [RN-Scanner] ${filters.length} filters configured (applied by base class)`);
        
        // Check if we should restart scanning with service filter
        const hasServiceFilter = filters.some(f => f.serviceUUID);
        if (hasServiceFilter && this.currentConfig && !this.currentConfig.filterByService) {
            this.currentConfig.filterByService = true;
            // Could restart scanning here with service filter if needed
        }
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
        const isPoweredOn = state === State.PoweredOn;
        
        return {
            maxScanFilters: 1, // Service UUID only
            supportsActiveScan: isPoweredOn,
            supportsContinuousScan: Platform.OS === 'ios' ? isPoweredOn : isPoweredOn,
            supportsBackgroundScan: Platform.OS === 'android' // iOS needs special entitlements
        };
    }

    /**
     * Create optimized scan options based on platform and config
     */
    private createOptimizedScanOptions(config: ScanConfig): any {
        let scanMode: ScanMode;
        
        if (Platform.OS === 'android') {
            // Android-specific scan modes
            if (config.lowPower) {
                scanMode = ScanMode.LowPower;
            } else if (config.activeScan || config.aggressive) {
                scanMode = ScanMode.LowLatency;
            } else {
                scanMode = ScanMode.Balanced;
            }
            
            return {
                allowDuplicates: config.duplicates !== false,
                scanMode,
                matchMode: config.aggressive ? 'aggressive' : 'sticky',
                numberOfMatches: config.singleDevice ? 'one' : 'few',
                reportDelay: config.batchResults ? 1000 : 0,
            };
        } else {
            // iOS options
            return {
                allowDuplicates: config.duplicates !== false,
                scanMode: ScanMode.LowLatency
            };
        }
    }

    /**
     * Process discovered device
     */
    private async processDiscoveredDevice(device: Device): Promise<void> {
        try {
            this.scanStatistics.totalScanned++;
            
            // Check duplicate with sliding window
            if (!this.shouldProcessDevice(device)) {
                return;
            }
            
            // Check if it's potentially a GhostComm device
            if (!this.isGhostCommDevice(device)) {
                return;
            }
            
            this.scanStatistics.ghostCommDevices++;
            this.devicesScannedCount++;
            
            // Store device reference
            this.discoveredDevices.set(device.id, device);
            
            // Extract Protocol v2.1 advertisement data
            const rawData = this.extractProtocolV21Data(device);
            if (!rawData) {
                console.log(`⚠️ [RN-Scanner] No valid Protocol v2.1 data from ${device.id}`);
                return;
            }
            
            // Pass to base class for Protocol v2.1 verification
            // Base class will:
            // 1. Parse the 108-byte packet
            // 2. Verify Ed25519 signature with sender's public key
            // 3. Check replay protection using sequence numbers
            // 4. Extract and validate identity proof
            // 5. Emit discovery events with verification status
            try {
                await this.handleScanResult(
                    device.id,
                    rawData,
                    device.rssi || -100,
                    device.txPowerLevel ?? undefined
                );
                this.scanStatistics.verifiedDevices++;
            } catch (error) {
                this.scanStatistics.failedVerifications++;
                console.warn('⚠️ [RN-Scanner] Verification failed:', error);
            }
            
        } catch (error) {
            console.error('❌ [RN-Scanner] Error processing device:', error);
        }
    }

    /**
     * Check if device should be processed (duplicate filtering)
     */
    private shouldProcessDevice(device: Device): boolean {
        const now = Date.now();
        const existing = this.recentDevices.get(device.id);
        
        if (existing) {
            // Check if within duplicate window
            if (now - existing.timestamp < this.duplicateWindow) {
                // Allow periodic updates for RSSI changes
                if (existing.updateCount < 3) {
                    existing.timestamp = now;
                    existing.updateCount++;
                    return true;
                }
                return false; // Too many updates, skip
            }
        }
        
        // New device or outside window
        this.recentDevices.set(device.id, {
            timestamp: now,
            updateCount: 1
        });
        
        return true;
    }

    /**
     * Check if device is advertising GhostComm service
     */
    private isGhostCommDevice(device: Device): boolean {
        // Priority 1: Service UUID match (most reliable)
        if (device.serviceUUIDs?.some(uuid => 
            uuid.toLowerCase() === BLE_CONFIG.SERVICE_UUID.toLowerCase()
        )) {
            return true;
        }
        
        // Priority 2: Service data contains our UUID
        if (device.serviceData && BLE_CONFIG.SERVICE_UUID in device.serviceData) {
            return true;
        }
        
        // Priority 3: Manufacturer data with GhostComm ID
        if (device.manufacturerData) {
            try {
                const data = Buffer.from(device.manufacturerData, 'base64');
                // Check for GhostComm manufacturer ID (0xFFFF for development)
                if (data.length >= 2 && data[0] === 0xFF && data[1] === 0xFF) {
                    return true;
                }
            } catch {
                // Invalid manufacturer data
            }
        }
        
        // Priority 4: Name patterns (least reliable, for compatibility)
        if (device.name) {
            if (device.name.startsWith('GC_') ||     // GhostComm
                device.name.startsWith('GM_') ||     // GhostMesh
                device.name.includes('Ghost')) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Extract Protocol v2.1 advertisement data (108-byte packet)
     */
    private extractProtocolV21Data(device: Device): Uint8Array | null {
        // Priority 1: Service data (most reliable on both platforms)
        if (device.serviceData && BLE_CONFIG.SERVICE_UUID in device.serviceData) {
            try {
                const serviceData = device.serviceData[BLE_CONFIG.SERVICE_UUID];
                const data = Buffer.from(serviceData, 'base64');
                
                // Validate Protocol v2.1 packet
                if (this.isValidProtocolV21Packet(data)) {
                    return new Uint8Array(data);
                }
            } catch (error) {
                console.warn('⚠️ [RN-Scanner] Invalid service data:', error);
            }
        }
        
        // Priority 2: Manufacturer data (fallback for size constraints)
        if (device.manufacturerData) {
            try {
                const data = Buffer.from(device.manufacturerData, 'base64');
                
                // Check for complete packet (2 bytes ID + 108 bytes packet)
                if (data.length >= 110) {
                    const packet = data.slice(2); // Skip manufacturer ID
                    if (this.isValidProtocolV21Packet(packet)) {
                        return new Uint8Array(packet);
                    }
                }
                
                // Try to reconstruct from partial data
                if (data.length >= 20) {
                    const reconstructed = this.reconstructProtocolV21Packet(data);
                    if (reconstructed) {
                        return reconstructed;
                    }
                }
            } catch (error) {
                console.warn('⚠️ [RN-Scanner] Invalid manufacturer data:', error);
            }
        }
        
        // Priority 3: Create minimal tracking packet (allows discovery without verification)
        return this.createMinimalProtocolV21Packet(device);
    }

    /**
     * Validate Protocol v2.1 packet structure
     */
    private isValidProtocolV21Packet(data: Buffer): boolean {
        // Check minimum size
        if (data.length < 108) {
            return false;
        }
        
        // Check version byte (must be 2 for Protocol v2.1)
        if (data[0] !== 2 && data[0] !== 0x02) {
            return false;
        }
        
        // Check flags byte is valid
        const flags = data[1];
        if (flags > 0xFF) {
            return false;
        }
        
        // Basic structure validation passed
        return true;
    }

    /**
     * Reconstruct Protocol v2.1 packet from partial manufacturer data
     */
    private reconstructProtocolV21Packet(data: Buffer): Uint8Array | null {
        // Skip manufacturer ID (first 2 bytes)
        const payload = data.slice(2);
        
        if (payload.length < 20) {
            return null; // Too small to be useful
        }
        
        // Create Protocol v2.1 packet structure (108 bytes)
        const packet = new Uint8Array(108);
        const view = new DataView(packet.buffer);
        let offset = 0;
        
        // Version (1 byte) - Protocol v2.1
        packet[offset++] = 2;
        
        // Flags (1 byte) - capabilities
        let flags = 0x01; // RELAY
        if (payload.length > 1) {
            flags = payload[1] || 0x01;
        }
        packet[offset++] = flags;
        
        // Ephemeral ID (16 bytes)
        const ephemeralId = new Uint8Array(16);
        if (payload.length >= 16) {
            ephemeralId.set(payload.slice(0, 16));
        }
        packet.set(ephemeralId, offset);
        offset += 16;
        
        // Identity hash (8 bytes)
        const identityHash = new Uint8Array(8);
        if (payload.length >= 24) {
            identityHash.set(payload.slice(16, 24));
        }
        packet.set(identityHash, offset);
        offset += 8;
        
        // Sequence number (4 bytes)
        view.setUint32(offset, Date.now() & 0xFFFFFFFF, false);
        offset += 4;
        
        // Timestamp (4 bytes)
        view.setUint32(offset, Math.floor(Date.now() / 1000), false);
        offset += 4;
        
        // Signature (64 bytes) - will fail verification but maintains structure
        offset += 64;
        
        // Mesh info (4 bytes)
        packet[offset++] = 1;   // nodeCount
        packet[offset++] = 0;   // queueSize
        packet[offset++] = 100; // batteryLevel
        packet[offset++] = 0x01; // Protocol v2.1 flag
        
        return packet;
    }

    /**
     * Create minimal Protocol v2.1 packet for basic tracking
     */
    private createMinimalProtocolV21Packet(device: Device): Uint8Array {
        const packet = new Uint8Array(108);
        const view = new DataView(packet.buffer);
        let offset = 0;
        
        // Version - Protocol v2.1
        packet[offset++] = 2;
        
        // Flags - minimal capabilities
        packet[offset++] = 0x01; // RELAY only
        
        // Ephemeral ID (16 bytes) - derive from device ID
        const deviceIdBytes = new TextEncoder().encode(device.id);
        const ephemeralId = new Uint8Array(16);
        for (let i = 0; i < Math.min(16, deviceIdBytes.length); i++) {
            ephemeralId[i] = deviceIdBytes[i];
        }
        packet.set(ephemeralId, offset);
        offset += 16;
        
        // Identity hash (8 bytes) - simple hash of device ID
        const hash = this.calculateSimpleHash(device.id);
        view.setUint32(offset, hash, false);
        view.setUint32(offset + 4, hash, false);
        offset += 8;
        
        // Sequence number (current time for uniqueness)
        view.setUint32(offset, Date.now() & 0xFFFFFFFF, false);
        offset += 4;
        
        // Timestamp
        view.setUint32(offset, Math.floor(Date.now() / 1000), false);
        offset += 4;
        
        // Signature (64 bytes) - empty (will fail Protocol v2.1 verification)
        offset += 64;
        
        // Mesh info
        packet[offset++] = 1;   // nodeCount
        packet[offset++] = 0;   // queueSize
        packet[offset++] = 100; // batteryLevel
        packet[offset++] = 0;   // flags
        
        return packet;
    }

    /**
     * Simple hash function for device ID
     */
    private calculateSimpleHash(str: string): number {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; // Convert to 32-bit integer
        }
        return Math.abs(hash);
    }

    /**
     * Setup Android duty cycle scanning for battery optimization
     */
    private setupAndroidDutyCycle(): void {
        const scheduleCycle = () => {
            this.dutyCycleTimer = setTimeout(async () => {
                if (!this.currentConfig || !this.scanSubscription) {
                    return;
                }
                
                console.log('⏸️ [RN-Scanner] Pausing for battery optimization');
                this.isDutyCyclePaused = true;
                
                // Pause scanning
                if (this.scanSubscription) {
                    this.scanSubscription.remove();
                    this.scanSubscription = undefined;
                }
                this.bleManager.stopDeviceScan();
                
                // Schedule resume
                this.dutyCycleTimer = setTimeout(async () => {
                    if (this.currentConfig && !this.scanSubscription) {
                        console.log('▶️ [RN-Scanner] Resuming scan');
                        this.isDutyCyclePaused = false;
                        
                        // Restart scanning
                        const scanOptions = this.createOptimizedScanOptions(this.currentConfig);
                        const serviceUUIDs = this.currentConfig.filterByService !== false 
                            ? [BLE_CONFIG.SERVICE_UUID] 
                            : null;
                        
                        this.scanSubscription = this.bleManager.startDeviceScan(
                            serviceUUIDs,
                            scanOptions,
                            (error, device) => {
                                if (error) {
                                    this.handleScanError(error);
                                    return;
                                }
                                if (device) {
                                    this.processDiscoveredDevice(device);
                                }
                            }
                        ) as any as Subscription;
                        
                        scheduleCycle(); // Continue cycle
                    }
                }, this.dutyCycleConfig.pauseTime);
            }, this.dutyCycleConfig.scanTime);
        };
        
        scheduleCycle();
    }

    /**
     * Clear duty cycle timer
     */
    private clearDutyCycle(): void {
        if (this.dutyCycleTimer) {
            clearTimeout(this.dutyCycleTimer);
            this.dutyCycleTimer = undefined;
        }
        this.isDutyCyclePaused = false;
    }

    /**
     * Start cleanup timer for duplicate cache (renamed to avoid conflict)
     */
    private startDuplicateCleanupTimer(): void {
        this.duplicateCleanupTimer = setInterval(() => {
            const now = Date.now();
            const expired: string[] = [];
            
            for (const [deviceId, info] of this.recentDevices) {
                if (now - info.timestamp > this.duplicateWindow * 2) {
                    expired.push(deviceId);
                }
            }
            
            for (const deviceId of expired) {
                this.recentDevices.delete(deviceId);
            }
        }, 30000); // Cleanup every 30 seconds
    }

    /**
     * Handle scan errors
     */
    private handleScanError(error: BleError): void {
        console.error('❌ [RN-Scanner] Scan error:', error);
        this.lastScanError = error as Error;
        
        // Emit error through base class (using the protected method from base)
        this.emitScanError({
            code: error.errorCode?.toString() || 'SCAN_ERROR',
            message: error.message || 'Unknown scan error',
            timestamp: Date.now()
        });
    }

    /**
     * Log scan statistics
     */
    private logScanStatistics(): void {
        if (this.scanStartTime) {
            const duration = (Date.now() - this.scanStartTime) / 1000;
            console.log(`📊 [RN-Scanner] Statistics:
  Duration: ${duration.toFixed(1)}s
  Total scanned: ${this.scanStatistics.totalScanned}
  GhostComm devices: ${this.scanStatistics.ghostCommDevices}
  Verified: ${this.scanStatistics.verifiedDevices}
  Failed verifications: ${this.scanStatistics.failedVerifications}`);
        }
    }

    // === Public React Native Specific Methods ===

    /**
     * Get discovered BLE devices
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
                supported: state !== State.Unsupported,
                bluetoothState: state,
                permissions: state === State.PoweredOn
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
     * Pause scanning (for app lifecycle)
     */
    async pauseScanning(): Promise<void> {
        if (this.scanSubscription) {
            console.log('⏸️ [RN-Scanner] Pausing scan');
            this.scanSubscription.remove();
            this.scanSubscription = undefined;
            this.bleManager.stopDeviceScan();
        }
    }

    /**
     * Resume scanning (for app lifecycle)
     */
    async resumeScanning(): Promise<void> {
        if (this.currentConfig && !this.scanSubscription) {
            console.log('▶️ [RN-Scanner] Resuming scan');
            await this.startPlatformScanning(this.currentConfig);
        }
    }

    /**
     * Get scan statistics
     */
    getScanStatistics(): typeof this.scanStatistics & {
        scanDuration: number;
        isDutyCyclePaused: boolean;
        lastError?: string;
    } {
        return {
            ...this.scanStatistics,
            scanDuration: this.scanStartTime ? Date.now() - this.scanStartTime : 0,
            isDutyCyclePaused: this.isDutyCyclePaused,
            lastError: this.lastScanError?.message
        };
    }

    /**
     * Cleanup resources
     */
    async cleanup(): Promise<void> {
        console.log('🧹 [RN-Scanner] Cleaning up...');
        
        // Stop scanning
        await this.stopPlatformScanning();
        
        // Clear duplicate cleanup timer
        if (this.duplicateCleanupTimer) {
            clearInterval(this.duplicateCleanupTimer);
            this.duplicateCleanupTimer = undefined;
        }
        
        // Clear state
        this.discoveredDevices.clear();
        this.recentDevices.clear();
        
        console.log('✅ [RN-Scanner] Cleanup complete');
    }
}