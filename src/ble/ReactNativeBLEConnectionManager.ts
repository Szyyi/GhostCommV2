// mobile/src/ble/ReactNativeBLEConnectionManager.ts
import { 
    BleManager, 
    Device, 
    Characteristic, 
    Service,
    BleError,
    ConnectionOptions
} from 'react-native-ble-plx';
import { Platform } from 'react-native';
import {
    BLEConnectionManager,
    BLE_CONFIG,
    SECURITY_CONFIG,
    ConnectionState,
    IGhostKeyPair,
    BLENode,
    BLEMessage,
    BLESession,
    BLEError as CoreBLEError,
    BLEErrorCode
} from '../../core';
import { Buffer } from 'buffer';
import { BLE_SECURITY_CONFIG } from '../../core/src/ble/types';
import { encode, decode } from '@msgpack/msgpack';

/**
 * React Native BLE Connection Manager Implementation
 * 
 * This class ONLY implements platform-specific BLE operations.
 * All Protocol v2.1 security features (signature verification, message chains,
 * Double Ratchet sessions) are handled by the base BLEConnectionManager class.
 * 
 * Responsibilities:
 * - Platform-specific BLE connection establishment
 * - Service and characteristic discovery
 * - Data transmission and reception via BLE
 * - MTU negotiation and fragmentation
 * - Connection monitoring and error recovery
 */
export class ReactNativeBLEConnectionManager extends BLEConnectionManager {
    private bleManager: BleManager;
    private devices: Map<string, Device> = new Map();
    private services: Map<string, Service> = new Map();
    private characteristics: Map<string, Map<string, Characteristic>> = new Map();
    private mtuSizes: Map<string, number> = new Map();
    private connectionNodeMap: Map<string, string> = new Map(); // connectionId -> nodeId
    private nodeConnectionMap: Map<string, string> = new Map(); // nodeId -> connectionId
    
    // Fragment reassembly buffers
    private fragmentBuffers: Map<string, {
        fragments: Map<number, Uint8Array>;
        totalFragments: number;
        receivedFragments: number;
        timestamp: number;
    }> = new Map();
    
    // Connection monitoring
    private connectionMonitors: Map<string, NodeJS.Timeout> = new Map();
    private reconnectAttempts: Map<string, number> = new Map();
    
    // Performance tracking
    private connectionLatencies: Map<string, number> = new Map();
    private lastDataReceived: Map<string, number> = new Map();

    constructor(keyPair?: IGhostKeyPair, bleManager?: BleManager) {
        super(keyPair);
        this.bleManager = bleManager || new BleManager();
        console.log(`📱 ReactNativeBLEConnectionManager initialized with Protocol v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}.1`);
    }

    /**
     * Platform-specific: Connect to a BLE device
     * The base class handles Protocol v2.1 handshake after connection
     */
    protected async connectToDevice(deviceId: string, nodeId: string): Promise<string> {
        try {
            console.log(`🔗 [RN] Connecting to device: ${deviceId} (node: ${nodeId})`);
            
            // Check if already connected
            if (this.nodeConnectionMap.has(nodeId)) {
                const existingConnectionId = this.nodeConnectionMap.get(nodeId)!;
                const device = this.devices.get(existingConnectionId);
                if (device && await device.isConnected()) {
                    console.log(`✅ [RN] Already connected to ${nodeId}`);
                    return existingConnectionId;
                }
            }

            // Connection options optimized for platform
            const options: ConnectionOptions = {
                autoConnect: Platform.OS === 'android', // Android supports auto-reconnect
                requestMTU: Platform.OS === 'android' ? BLE_CONFIG.MAX_MTU : undefined,
                refreshGatt: Platform.OS === 'android' ? 'OnConnected' : undefined,
                timeout: BLE_CONFIG.CONNECTION_TIMEOUT
            };

            // Connect with retry logic
            const device = await this.connectDeviceWithRetry(deviceId, options);
            const connectionId = device.id;
            
            console.log(`✅ [RN] Connected to device: ${connectionId}`);

            // Discover services and characteristics
            await this.discoverServices(device);

            // Store device and mappings
            this.devices.set(connectionId, device);
            this.connectionNodeMap.set(connectionId, nodeId);
            this.nodeConnectionMap.set(nodeId, connectionId);

            // Setup disconnection handler
            device.onDisconnected((error, disconnectedDevice) => {
                this.handleDisconnection(
                    disconnectedDevice?.id || connectionId,
                    nodeId,
                    error || undefined
                );
            });

            // Start connection monitoring
            this.startConnectionMonitoring(connectionId, nodeId);

            // Track connection latency
            this.connectionLatencies.set(connectionId, Date.now());

            return connectionId;

        } catch (error) {
            console.error(`❌ [RN] Failed to connect to device ${deviceId}:`, error);
            this.reconnectAttempts.delete(nodeId);
            throw this.wrapBleError(error);
        }
    }

    /**
     * Platform-specific: Disconnect from a BLE device
     */
    protected async disconnectFromDevice(connectionId: string): Promise<void> {
        try {
            console.log(`🔌 [RN] Disconnecting device: ${connectionId}`);
            
            const device = this.devices.get(connectionId);
            if (!device) {
                console.warn(`⚠️ [RN] Device not found: ${connectionId}`);
                return;
            }

            // Stop monitoring
            this.stopConnectionMonitoring(connectionId);

            // Cancel connection
            await device.cancelConnection();

            // Cleanup all state
            this.cleanupConnection(connectionId);

            console.log(`✅ [RN] Disconnected from device: ${connectionId}`);

        } catch (error) {
            console.error(`❌ [RN] Failed to disconnect from device ${connectionId}:`, error);
            // Force cleanup even on error
            this.cleanupConnection(connectionId);
            throw this.wrapBleError(error);
        }
    }

    /**
     * Platform-specific: Send data to a BLE device
     * Handles fragmentation for large messages
     */
    protected async sendDataToDevice(connectionId: string, data: Uint8Array): Promise<void> {
        try {
            const characteristics = this.characteristics.get(connectionId);
            const messageChar = characteristics?.get(BLE_CONFIG.CHARACTERISTICS.MESSAGE_EXCHANGE);
            
            if (!messageChar) {
                throw new Error(`No message characteristic for connection: ${connectionId}`);
            }

            const mtu = this.mtuSizes.get(connectionId) || BLE_CONFIG.DEFAULT_MTU;
            const maxPayloadSize = mtu - 3; // Account for BLE overhead

            // Convert to base64 for react-native-ble-plx
            const base64Data = Buffer.from(data).toString('base64');

            if (data.length <= maxPayloadSize) {
                // Send in one chunk
                await this.writeCharacteristic(messageChar, base64Data);
                console.log(`📤 [RN] Sent ${data.length} bytes to ${connectionId}`);
            } else {
                // Fragment large messages
                await this.sendFragmentedData(messageChar, data, maxPayloadSize);
                console.log(`📤 [RN] Sent ${data.length} bytes (fragmented) to ${connectionId}`);
            }

            // Update connection activity
            const nodeId = this.connectionNodeMap.get(connectionId);
            if (nodeId) {
                const connection = this.getConnection(nodeId);
                if (connection) {
                    connection.lastActivity = Date.now();
                    connection.sentMessages++;
                }
            }

        } catch (error) {
            console.error(`❌ [RN] Failed to send data to ${connectionId}:`, error);
            throw this.wrapBleError(error);
        }
    }

    /**
     * Platform-specific: Setup message receiving with notification handling
     */
    protected async setupMessageReceiving(connectionId: string, nodeId: string): Promise<void> {
        try {
            console.log(`📥 [RN] Setting up message receiving for ${nodeId}`);

            const characteristics = this.characteristics.get(connectionId);
            if (!characteristics) {
                throw new Error(`No characteristics for connection: ${connectionId}`);
            }

            // Monitor message exchange characteristic
            const messageChar = characteristics.get(BLE_CONFIG.CHARACTERISTICS.MESSAGE_EXCHANGE);
            if (messageChar) {
                await this.monitorCharacteristic(messageChar, connectionId, nodeId);
            }

            // Monitor acknowledgment characteristic if available
            const ackChar = characteristics.get(BLE_CONFIG.CHARACTERISTICS.MESSAGE_ACKNOWLEDGMENT);
            if (ackChar) {
                await this.monitorAcknowledgmentCharacteristic(ackChar, connectionId, nodeId);
            }

            console.log(`✅ [RN] Message receiving setup complete for ${nodeId}`);

        } catch (error) {
            console.error(`❌ [RN] Failed to setup message receiving for ${nodeId}:`, error);
            throw this.wrapBleError(error);
        }
    }

    /**
     * Platform-specific: Negotiate MTU size for optimal throughput
     */
    protected async negotiateMTU(connectionId: string): Promise<number> {
        try {
            const device = this.devices.get(connectionId);
            if (!device) {
                throw new Error(`Device not found: ${connectionId}`);
            }

            // Only Android supports MTU negotiation
            if (Platform.OS !== 'android') {
                const defaultMTU = 185; // iOS default
                this.mtuSizes.set(connectionId, defaultMTU);
                return defaultMTU;
            }

            const requestedMTU = BLE_CONFIG.MAX_MTU;
            console.log(`📏 [RN] Requesting MTU: ${requestedMTU} for ${connectionId}`);

            const updatedDevice = await device.requestMTU(requestedMTU);
            const actualMTU = updatedDevice.mtu || BLE_CONFIG.DEFAULT_MTU;

            this.mtuSizes.set(connectionId, actualMTU);
            console.log(`✅ [RN] MTU negotiated: ${actualMTU} bytes for ${connectionId}`);

            // Update connection info
            const nodeId = this.connectionNodeMap.get(connectionId);
            if (nodeId) {
                const connection = this.getConnection(nodeId);
                if (connection) {
                    connection.mtu = actualMTU;
                }
            }

            return actualMTU;

        } catch (error) {
            console.error(`⚠️ [RN] MTU negotiation failed for ${connectionId}:`, error);
            const defaultMTU = BLE_CONFIG.DEFAULT_MTU;
            this.mtuSizes.set(connectionId, defaultMTU);
            return defaultMTU;
        }
    }

    /**
     * Platform-specific: Get connection parameters
     */
    protected async getConnectionParameters(connectionId: string): Promise<{
        interval: number;
        latency: number;
        timeout: number;
    }> {
        const device = this.devices.get(connectionId);
        if (!device) {
            throw new Error(`Device not found: ${connectionId}`);
        }

        // react-native-ble-plx doesn't expose these directly
        // Could be extended with native module if needed
        return {
            interval: BLE_CONFIG.CONNECTION_INTERVAL_MIN,
            latency: BLE_CONFIG.CONNECTION_LATENCY,
            timeout: BLE_CONFIG.SUPERVISION_TIMEOUT
        };
    }

    /**
     * Helper: Connect with retry logic (renamed to avoid base class conflict)
     */
    private async connectDeviceWithRetry(
        deviceId: string,
        options: ConnectionOptions,
        maxRetries: number = 3
    ): Promise<Device> {
        let lastError: Error | undefined;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                console.log(`🔄 [RN] Connection attempt ${attempt}/${maxRetries} to ${deviceId}`);
                
                const device = await this.bleManager.connectToDevice(deviceId, options);
                
                // Verify connection
                if (await device.isConnected()) {
                    return device;
                }
                
                throw new Error('Device connected but not responsive');

            } catch (error) {
                lastError = error as Error;
                console.warn(`⚠️ [RN] Connection attempt ${attempt} failed:`, error);

                if (attempt < maxRetries) {
                    // Exponential backoff
                    const delay = 1000 * Math.pow(2, attempt - 1);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }

        throw lastError || new Error('Connection failed after retries');
    }

    /**
     * Helper: Discover and setup GhostComm services
     */
    private async discoverServices(device: Device): Promise<void> {
        console.log(`🔍 [RN] Discovering services for ${device.id}`);

        // Discover all services and characteristics
        await device.discoverAllServicesAndCharacteristics();

        // Find GhostComm service
        const services = await device.services();
        const ghostService = services.find(s =>
            s.uuid.toLowerCase() === BLE_CONFIG.SERVICE_UUID.toLowerCase()
        );

        if (!ghostService) {
            throw new Error(`GhostComm service not found on device: ${device.id}`);
        }

        this.services.set(device.id, ghostService);

        // Get all characteristics
        const characteristics = await ghostService.characteristics();
        const charMap = new Map<string, Characteristic>();

        for (const char of characteristics) {
            // Map known characteristics
            const uuid = char.uuid.toLowerCase();
            for (const [name, charUuid] of Object.entries(BLE_CONFIG.CHARACTERISTICS)) {
                if (uuid === charUuid.toLowerCase()) {
                    charMap.set(charUuid, char);
                    console.log(`✅ [RN] Found characteristic: ${name}`);
                    break;
                }
            }
        }

        // Verify essential characteristics
        if (!charMap.has(BLE_CONFIG.CHARACTERISTICS.MESSAGE_EXCHANGE)) {
            throw new Error(`Message exchange characteristic not found on device: ${device.id}`);
        }

        this.characteristics.set(device.id, charMap);
        console.log(`✅ [RN] Service discovery complete for ${device.id}`);
    }

    /**
     * Serialize BLE message using MessagePack for efficient binary encoding
     * Reduces message size by approximately 60% compared to JSON
     */
    private serializeBLEMessage(message: BLEMessage): Uint8Array {
        try {
            // Use MessagePack for efficient binary serialization
            const serialized = encode(message);
            
            // Log size reduction for monitoring
            if (__DEV__) {
                const jsonSize = JSON.stringify(message).length;
                const msgpackSize = serialized.byteLength;
                const reduction = ((jsonSize - msgpackSize) / jsonSize * 100).toFixed(1);
                console.log(`📦 MessagePack: ${jsonSize}B → ${msgpackSize}B (${reduction}% reduction)`);
            }
            
            return serialized;
        } catch (error) {
            console.error('MessagePack serialization failed:', error);
            // Fallback to JSON
            const jsonStr = JSON.stringify(message);
            return new TextEncoder().encode(jsonStr);
        }
    }

    /**
     * Helper to convert Uint8Array to base64 for BLE transmission
     */
    private uint8ArrayToBase64(data: Uint8Array): string {
        // React Native specific implementation
        const binary = String.fromCharCode.apply(null, Array.from(data));
        return btoa(binary);
    }

    /**
     * Helper to convert base64 back to Uint8Array
     */
    private base64ToUint8Array(base64: string): Uint8Array {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
    }

    /**
 * Deserialize BLE message from MessagePack binary format
 */
    private deserializeBLEMessage(data: Uint8Array): BLEMessage | null {
        try {
            // Try MessagePack deserialization first
            const message = decode(data) as BLEMessage;
            
            // Validate required Protocol v2.1 fields
            if (!message.messageId || !message.senderPublicKey || !message.messageSignature) {
                console.warn('Deserialized message missing required Protocol v2.1 fields');
                return null;
            }
            
            return message;
        } catch (error) {
            // Try JSON fallback for backward compatibility
            try {
                const jsonStr = new TextDecoder().decode(data);
                const message = JSON.parse(jsonStr) as BLEMessage;
                console.log('Fell back to JSON deserialization');
                return message;
            } catch (jsonError) {
                console.error('Failed to deserialize message:', error, jsonError);
                return null;
            }
        }
    }


    /**
     * Helper: Monitor characteristic for incoming data
     */
    private async monitorCharacteristic(
        characteristic: Characteristic,
        connectionId: string,
        nodeId: string
    ): Promise<void> {
        characteristic.monitor((error, char) => {
            if (error) {
                console.error(`❌ [RN] Monitor error for ${nodeId}:`, error);
                return;
            }

            if (char?.value) {
                try {
                    // Convert base64 to Uint8Array
                    const buffer = Buffer.from(char.value, 'base64');
                    const data = new Uint8Array(buffer);

                    // Update activity timestamp
                    this.lastDataReceived.set(connectionId, Date.now());

                    // Check if this is a fragment
                    if (this.isFragmentData(data)) {
                        this.handleFragmentData(data, connectionId, nodeId);
                    } else {
                        // Pass complete message to base class for Protocol v2.1 processing
                        // The base class will:
                        // 1. Verify message signature
                        // 2. Check message chain integrity
                        // 3. Process through Double Ratchet if needed
                        // 4. Invoke registered callbacks
                        this.handleIncomingMessage(data, nodeId);
                    }

                } catch (decodeError) {
                    console.error(`❌ [RN] Decode error from ${nodeId}:`, decodeError);
                }
            }
        });
    }

    /**
     * Helper: Monitor acknowledgment characteristic
     */
    private async monitorAcknowledgmentCharacteristic(
        characteristic: Characteristic,
        connectionId: string,
        nodeId: string
    ): Promise<void> {
        characteristic.monitor((error, char) => {
            if (error) {
                console.error(`❌ [RN] Ack monitor error for ${nodeId}:`, error);
                return;
            }

            if (char?.value) {
                try {
                    const buffer = Buffer.from(char.value, 'base64');
                    const data = new Uint8Array(buffer);
                    
                    // Process acknowledgment
                    console.log(`✅ [RN] Received acknowledgment from ${nodeId}`);
                    
                } catch (error) {
                    console.error(`❌ [RN] Ack decode error from ${nodeId}:`, error);
                }
            }
        });
    }

    /**
     * Helper: Send fragmented data with proper headers
     */
    private async sendFragmentedData(
        characteristic: Characteristic,
        data: Uint8Array,
        maxPayloadSize: number
    ): Promise<void> {
        // Calculate fragments
        const fragmentHeaderSize = 5; // 1 byte flags + 2 bytes total + 2 bytes index
        const maxDataSize = maxPayloadSize - fragmentHeaderSize;
        const totalFragments = Math.ceil(data.length / maxDataSize);

        console.log(`📦 [RN] Sending ${totalFragments} fragments, ${data.length} total bytes`);

        for (let i = 0; i < totalFragments; i++) {
            const start = i * maxDataSize;
            const end = Math.min(start + maxDataSize, data.length);
            const fragmentData = data.slice(start, end);

            // Create fragment with header
            const fragment = new Uint8Array(fragmentHeaderSize + fragmentData.length);
            
            // Header: [flags(1), totalFragments(2), currentIndex(2), ...data]
            fragment[0] = 0x01; // Fragment flag
            fragment[1] = (totalFragments >> 8) & 0xFF;
            fragment[2] = totalFragments & 0xFF;
            fragment[3] = (i >> 8) & 0xFF;
            fragment[4] = i & 0xFF;
            fragment.set(fragmentData, fragmentHeaderSize);

            // Convert to base64 and send
            const base64Fragment = Buffer.from(fragment).toString('base64');
            await this.writeCharacteristic(characteristic, base64Fragment);

            // Small delay between fragments to avoid overwhelming the device
            if (i < totalFragments - 1) {
                await new Promise(resolve => setTimeout(resolve, 10));
            }
        }
    }

    /**
     * Helper: Check if data is a fragment (renamed to avoid base class conflict)
     */
    private isFragmentData(data: Uint8Array): boolean {
        return data.length > 0 && data[0] === 0x01;
    }

    /**
     * Helper: Handle fragment reassembly (renamed to avoid base class conflict)
     */
    private handleFragmentData(data: Uint8Array, connectionId: string, nodeId: string): void {
        if (data.length < 5) {
            console.error(`❌ [RN] Invalid fragment from ${nodeId}`);
            return;
        }

        // Parse fragment header
        const totalFragments = (data[1] << 8) | data[2];
        const currentIndex = (data[3] << 8) | data[4];
        const fragmentData = data.slice(5);

        const fragmentKey = `${connectionId}-${totalFragments}`;
        
        // Get or create fragment buffer
        let buffer = this.fragmentBuffers.get(fragmentKey);
        if (!buffer) {
            buffer = {
                fragments: new Map(),
                totalFragments,
                receivedFragments: 0,
                timestamp: Date.now()
            };
            this.fragmentBuffers.set(fragmentKey, buffer);
        }

        // Store fragment
        buffer.fragments.set(currentIndex, fragmentData);
        buffer.receivedFragments++;

        console.log(`📦 [RN] Fragment ${currentIndex + 1}/${totalFragments} received from ${nodeId}`);

        // Check if all fragments received
        if (buffer.receivedFragments === totalFragments) {
            // Reassemble message
            const reassembled = this.reassembleFragmentData(buffer);
            this.fragmentBuffers.delete(fragmentKey);

            // Pass to base class for Protocol v2.1 processing
            this.handleIncomingMessage(reassembled, nodeId);
        }

        // Cleanup old fragments (timeout after 30 seconds)
        if (Date.now() - buffer.timestamp > 30000) {
            console.warn(`⚠️ [RN] Fragment timeout for ${nodeId}`);
            this.fragmentBuffers.delete(fragmentKey);
        }
    }

    /**
     * Helper: Reassemble fragments into complete message (renamed to avoid base class conflict)
     */
    private reassembleFragmentData(buffer: {
        fragments: Map<number, Uint8Array>;
        totalFragments: number;
    }): Uint8Array {
        // Calculate total size
        let totalSize = 0;
        for (const fragment of buffer.fragments.values()) {
            totalSize += fragment.length;
        }

        // Reassemble in order
        const result = new Uint8Array(totalSize);
        let offset = 0;

        for (let i = 0; i < buffer.totalFragments; i++) {
            const fragment = buffer.fragments.get(i);
            if (fragment) {
                result.set(fragment, offset);
                offset += fragment.length;
            }
        }

        return result;
    }

    /**
     * Helper: Write to characteristic with error handling
     */
    private async writeCharacteristic(
        characteristic: Characteristic,
        base64Data: string
    ): Promise<void> {
        try {
            await characteristic.writeWithResponse(base64Data);
        } catch (error) {
            // Retry once on failure
            console.warn(`⚠️ [RN] Write failed, retrying...`);
            await new Promise(resolve => setTimeout(resolve, 100));
            await characteristic.writeWithoutResponse(base64Data);
        }
    }

    /**
     * Helper: Start connection monitoring
     */
    private startConnectionMonitoring(connectionId: string, nodeId: string): void {
        // Monitor connection health every 30 seconds
        const monitor = setInterval(async () => {
            try {
                const device = this.devices.get(connectionId);
                if (!device) {
                    this.stopConnectionMonitoring(connectionId);
                    return;
                }

                const isConnected = await device.isConnected();
                if (!isConnected) {
                    console.warn(`⚠️ [RN] Connection lost to ${nodeId}`);
                    this.handleDisconnection(connectionId, nodeId);
                }

                // Check for stale connection (no data in 2 minutes)
                const lastReceived = this.lastDataReceived.get(connectionId) || 0;
                if (Date.now() - lastReceived > 120000) {
                    console.warn(`⚠️ [RN] Connection stale to ${nodeId}`);
                    // Could send a ping here
                }

            } catch (error) {
                console.error(`❌ [RN] Monitor error for ${nodeId}:`, error);
            }
        }, 30000);

        this.connectionMonitors.set(connectionId, monitor);
    }

    /**
     * Helper: Stop connection monitoring
     */
    private stopConnectionMonitoring(connectionId: string): void {
        const monitor = this.connectionMonitors.get(connectionId);
        if (monitor) {
            clearInterval(monitor);
            this.connectionMonitors.delete(connectionId);
        }
    }

    /**
     * Helper: Handle device disconnection
     */
    private handleDisconnection(
        connectionId: string,
        nodeId: string,
        error?: BleError
    ): void {
        console.log(`🔌 [RN] Device disconnected: ${connectionId}`, error ? `Error: ${error.message}` : '');

        // Stop monitoring
        this.stopConnectionMonitoring(connectionId);

        // Update connection state in base class
        const connection = this.getConnection(nodeId);
        if (connection) {
            connection.state = ConnectionState.DISCONNECTED;
        }

        // Cleanup connection
        this.cleanupConnection(connectionId);

        // Attempt reconnection if it was unexpected
        if (error && this.shouldAttemptReconnect(nodeId)) {
            this.scheduleReconnect(nodeId, connectionId);
        }
    }

    /**
     * Helper: Determine if reconnection should be attempted
     */
    private shouldAttemptReconnect(nodeId: string): boolean {
        const attempts = this.reconnectAttempts.get(nodeId) || 0;
        return attempts < 3;
    }

    /**
     * Helper: Schedule reconnection attempt
     */
    private scheduleReconnect(nodeId: string, lastConnectionId: string): void {
        const attempts = this.reconnectAttempts.get(nodeId) || 0;
        this.reconnectAttempts.set(nodeId, attempts + 1);

        // Exponential backoff
        const delay = 1000 * Math.pow(2, attempts);

        console.log(`🔄 [RN] Scheduling reconnect to ${nodeId} in ${delay}ms (attempt ${attempts + 1})`);

        setTimeout(async () => {
            try {
                // Try to reconnect using the same device ID
                await this.connectToDevice(lastConnectionId, nodeId);
                console.log(`✅ [RN] Successfully reconnected to ${nodeId}`);
                this.reconnectAttempts.delete(nodeId);
            } catch (error) {
                console.error(`❌ [RN] Failed to reconnect to ${nodeId}:`, error);
                
                if (this.shouldAttemptReconnect(nodeId)) {
                    this.scheduleReconnect(nodeId, lastConnectionId);
                } else {
                    console.log(`⛔ [RN] Giving up reconnection to ${nodeId}`);
                    this.reconnectAttempts.delete(nodeId);
                }
            }
        }, delay);
    }

    /**
     * Helper: Cleanup connection state
     */
    private cleanupConnection(connectionId: string): void {
        const nodeId = this.connectionNodeMap.get(connectionId);
        
        // Clear all mappings
        this.devices.delete(connectionId);
        this.services.delete(connectionId);
        this.characteristics.delete(connectionId);
        this.mtuSizes.delete(connectionId);
        this.connectionLatencies.delete(connectionId);
        this.lastDataReceived.delete(connectionId);
        this.connectionNodeMap.delete(connectionId);
        
        if (nodeId) {
            this.nodeConnectionMap.delete(nodeId);
        }

        // Clear any fragment buffers
        for (const [key] of this.fragmentBuffers) {
            if (key.startsWith(connectionId)) {
                this.fragmentBuffers.delete(key);
            }
        }
    }

    /**
     * Helper: Wrap BLE errors with our error type
     */
    private wrapBleError(error: any): CoreBLEError {
        return {
            code: BLEErrorCode.CONNECTION_FAILED,
            message: error?.message || String(error),
            details: error,
            timestamp: Date.now()
        };
    }

    /**
     * Public: Handle incoming data (called from ReactNativeBLEManager)
     */
    public handleIncomingData(data: Uint8Array, fromNodeId: string): void {
        // Pass to base class for Protocol v2.1 processing
        this.handleIncomingMessage(data, fromNodeId);
    }

    /**
     * Public: Get device info for debugging
     */
    public async getDeviceInfo(nodeId: string): Promise<{
        id: string;
        name?: string;
        rssi?: number;
        mtu?: number;
        isConnected: boolean;
        latency?: number;
    } | null> {
        const connectionId = this.nodeConnectionMap.get(nodeId);
        if (!connectionId) {
            return null;
        }

        const device = this.devices.get(connectionId);
        if (!device) {
            return null;
        }

        const isConnected = await device.isConnected();
        const mtu = this.mtuSizes.get(connectionId);
        const connectionTime = this.connectionLatencies.get(connectionId);
        const latency = connectionTime ? Date.now() - connectionTime : undefined;

        return {
            id: device.id,
            name: device.name || undefined,
            rssi: device.rssi || undefined,
            mtu: mtu || undefined,
            isConnected,
            latency
        };
    }


    

    /**
     * Public: Validate all connections
     */
    public async validateConnections(): Promise<void> {
        console.log(`🔍 [RN] Validating ${this.devices.size} connections...`);
        
        const invalidConnections: string[] = [];

        for (const [connectionId, device] of this.devices) {
            try {
                const isConnected = await device.isConnected();
                if (!isConnected) {
                    invalidConnections.push(connectionId);
                }
            } catch {
                invalidConnections.push(connectionId);
            }
        }

        // Disconnect invalid connections
        for (const connectionId of invalidConnections) {
            const nodeId = this.connectionNodeMap.get(connectionId);
            if (nodeId) {
                console.warn(`⚠️ [RN] Removing invalid connection to ${nodeId}`);
            }
            await this.disconnectFromDevice(connectionId);
        }

        console.log(`✅ [RN] Validation complete, removed ${invalidConnections.length} invalid connections`);
    }

    /**
     * Public: Get connection statistics
     */
    public getConnectionStats(): {
        totalConnections: number;
        activeConnections: number;
        averageMTU: number;
        fragmentBuffers: number;
        reconnectAttempts: number;
    } {
        let totalMTU = 0;
        let activeCount = 0;

        for (const [connectionId, mtu] of this.mtuSizes) {
            totalMTU += mtu;
            if (this.devices.has(connectionId)) {
                activeCount++;
            }
        }

        return {
            totalConnections: this.connectionNodeMap.size,
            activeConnections: activeCount,
            averageMTU: this.mtuSizes.size > 0 ? totalMTU / this.mtuSizes.size : 0,
            fragmentBuffers: this.fragmentBuffers.size,
            reconnectAttempts: this.reconnectAttempts.size
        };
    }

    /**
     * Override cleanup to handle React Native specific resources
     */
    async cleanup(): Promise<void> {
        console.log('🧹 [RN] Cleaning up BLE connection manager...');

        // Stop all monitoring
        for (const connectionId of this.connectionMonitors.keys()) {
            this.stopConnectionMonitoring(connectionId);
        }

        // Disconnect all devices
        for (const connectionId of this.devices.keys()) {
            try {
                await this.disconnectFromDevice(connectionId);
            } catch (error) {
                console.warn(`⚠️ [RN] Error disconnecting ${connectionId}:`, error);
            }
        }

        
        // Clear all state
        this.devices.clear();
        this.services.clear();
        this.characteristics.clear();
        this.mtuSizes.clear();
        this.connectionNodeMap.clear();
        this.nodeConnectionMap.clear();
        this.fragmentBuffers.clear();
        this.connectionMonitors.clear();
        this.reconnectAttempts.clear();
        this.connectionLatencies.clear();
        this.lastDataReceived.clear();

        // Call parent cleanup
        await super.cleanup();

        console.log('✅ [RN] Connection manager cleanup complete');
    }
}