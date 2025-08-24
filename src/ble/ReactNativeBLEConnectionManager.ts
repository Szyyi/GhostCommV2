// mobile/src/ble/ReactNativeBLEConnectionManager.ts
import { BleManager, Device, Characteristic } from 'react-native-ble-plx';
import { Platform } from 'react-native';
import {
    BLEConnectionManager,
    BLENode,
    BLESession,
    ConnectionState,
    BLE_CONFIG,
    BLEMessage,
    MessageFragment,
    RelaySignature,
    IGhostKeyPair,
    SessionKeys
} from '../../core';

/**
 * React Native BLE Connection Manager Implementation for v2.0
 * Handles Double Ratchet sessions, fragmentation, and mesh routing
 */
export class ReactNativeBLEConnectionManager extends BLEConnectionManager {
    private bleManager: BleManager;
    private devices: Map<string, Device> = new Map(); // connectionId -> Device
    private characteristics: Map<string, Characteristic> = new Map(); // connectionId -> messageChar
    private fragmentBuffers: Map<string, Map<number, Uint8Array>> = new Map(); // connectionId -> fragments
    private mtuSizes: Map<string, number> = new Map(); // connectionId -> MTU

    constructor(keyPair?: IGhostKeyPair, bleManager?: BleManager) {
        super(keyPair);
        this.bleManager = bleManager || new BleManager();
    }

    /**
     * Connect to a BLE device - implements abstract method
     */
    protected async connectToDevice(deviceId: string, nodeId: string): Promise<string> {
        try {
            console.log(`🔗 Connecting to device: ${deviceId} (node: ${nodeId})`);

            // Connect with optimal parameters
            const device = await this.bleManager.connectToDevice(deviceId, {
                autoConnect: false,
                requestMTU: BLE_CONFIG.MAX_MTU,
                refreshGatt: 'OnConnected',
                timeout: BLE_CONFIG.CONNECTION_TIMEOUT
            });

            const connectionId = device.id;
            console.log(`✅ Connected to device: ${connectionId}`);

            // Discover services
            await device.discoverAllServicesAndCharacteristics();

            // Setup GhostComm service
            await this.setupGhostCommService(device);

            // Store device
            this.devices.set(connectionId, device);

            // Set up disconnect handler
            device.onDisconnected((error, disconnectedDevice) => {
                return this.handleDisconnection(disconnectedDevice?.id || connectionId, nodeId, error || undefined);
            });

            return connectionId;

        } catch (error) {
            console.error(`❌ Failed to connect to device ${deviceId}:`, error);
            throw error;
        }
    }

    /**
     * Disconnect from device - implements abstract method
     */
    protected async disconnectFromDevice(connectionId: string): Promise<void> {
        try {
            const device = this.devices.get(connectionId);
            if (!device) {
                return;
            }

            await device.cancelConnection();

            // Cleanup
            this.devices.delete(connectionId);
            this.characteristics.delete(connectionId);
            this.fragmentBuffers.delete(connectionId);
            this.mtuSizes.delete(connectionId);

            console.log(`✅ Disconnected from device: ${connectionId}`);

        } catch (error) {
            console.error(`❌ Failed to disconnect from device ${connectionId}:`, error);
            throw error;
        }
    }

    /**
     * Send data to device - implements abstract method
     */
    protected async sendDataToDevice(connectionId: string, data: Uint8Array): Promise<void> {
        try {
            const characteristic = this.characteristics.get(connectionId);
            if (!characteristic) {
                throw new Error(`No characteristic for connection: ${connectionId}`);
            }

            const mtu = this.mtuSizes.get(connectionId) || BLE_CONFIG.DEFAULT_MTU;
            const maxChunkSize = mtu - 3; // ATT overhead

            // Convert to base64 for BLE transmission
            const base64Data = Buffer.from(data).toString('base64');

            if (base64Data.length <= maxChunkSize) {
                // Single write
                await characteristic.writeWithResponse(base64Data);
            } else {
                // Fragment and send
                await this.sendFragmented(characteristic, base64Data, maxChunkSize);
            }

            console.log(`📤 Sent ${data.length} bytes to connection: ${connectionId}`);

        } catch (error) {
            console.error(`❌ Failed to send data to ${connectionId}:`, error);
            throw error;
        }
    }

    /**
     * Setup message receiving - implements abstract method
     */
    protected async setupMessageReceiving(connectionId: string, nodeId: string): Promise<void> {
        try {
            const characteristic = this.characteristics.get(connectionId);
            if (!characteristic) {
                throw new Error(`No characteristic for connection: ${connectionId}`);
            }

            // Monitor for incoming messages
            characteristic.monitor((error, char) => {
                if (error) {
                    console.error(`❌ Monitor error for ${nodeId}:`, error);
                    return;
                }

                if (char?.value) {
                    try {
                        // Decode from base64
                        const data = Buffer.from(char.value, 'base64');

                        // Check if this is a fragment
                        if (this.isFragment(data)) {
                            this.handleIncomingFragment(connectionId, nodeId, data);
                        } else {
                            // Complete message
                            this.handleIncomingMessage(data, nodeId);
                        }
                    } catch (decodeError) {
                        console.error(`❌ Decode error from ${nodeId}:`, decodeError);
                    }
                }
            });

            console.log(`✅ Message receiving setup for node: ${nodeId}`);

        } catch (error) {
            console.error(`❌ Failed to setup message receiving for ${nodeId}:`, error);
            throw error;
        }
    }

    /**
     * Negotiate MTU - implements abstract method
     */
    protected async negotiateMTU(connectionId: string): Promise<number> {
        try {
            const device = this.devices.get(connectionId);
            if (!device) {
                throw new Error(`Device not found: ${connectionId}`);
            }

            const requestedMTU = BLE_CONFIG.MAX_MTU;
            const updatedDevice = await device.requestMTU(requestedMTU);
            const actualMTU = updatedDevice.mtu || BLE_CONFIG.DEFAULT_MTU;

            this.mtuSizes.set(connectionId, actualMTU);
            console.log(`📏 MTU negotiated: ${actualMTU} for ${connectionId}`);

            return actualMTU;

        } catch (error) {
            console.error(`❌ MTU negotiation failed for ${connectionId}:`, error);
            return BLE_CONFIG.DEFAULT_MTU;
        }
    }

    /**
     * Get connection parameters - implements abstract method
     */
    protected async getConnectionParameters(connectionId: string): Promise<{
        interval: number;
        latency: number;
        timeout: number;
    }> {
        // React Native BLE PLX doesn't expose these directly
        // Return defaults based on platform
        const device = this.devices.get(connectionId);
        if (!device) {
            throw new Error(`Device not found: ${connectionId}`);
        }

        // These would be retrieved via native module in production
        return {
            interval: BLE_CONFIG.CONNECTION_INTERVAL_MIN,
            latency: BLE_CONFIG.CONNECTION_LATENCY,
            timeout: BLE_CONFIG.SUPERVISION_TIMEOUT
        };
    }

    /**
     * Setup GhostComm BLE service
     */
    private async setupGhostCommService(device: Device): Promise<void> {
        const services = await device.services();
        const ghostService = services.find(s =>
            s.uuid.toLowerCase() === BLE_CONFIG.SERVICE_UUID.toLowerCase()
        );

        if (!ghostService) {
            throw new Error(`GhostComm service not found on device: ${device.id}`);
        }

        const characteristics = await ghostService.characteristics();

        // Find message exchange characteristic
        const messageChar = characteristics.find(c =>
            c.uuid.toLowerCase() === BLE_CONFIG.CHARACTERISTICS.MESSAGE_EXCHANGE.toLowerCase()
        );

        if (!messageChar) {
            throw new Error(`Message characteristic not found on device: ${device.id}`);
        }

        this.characteristics.set(device.id, messageChar);
        console.log(`✅ GhostComm service setup complete for: ${device.id}`);
    }

    /**
     * Send fragmented data
     */
    private async sendFragmented(
        characteristic: Characteristic,
        base64Data: string,
        maxChunkSize: number
    ): Promise<void> {
        const totalChunks = Math.ceil(base64Data.length / maxChunkSize);
        const fragmentId = Math.random().toString(36).substring(7);

        for (let i = 0; i < totalChunks; i++) {
            const start = i * maxChunkSize;
            const end = Math.min(start + maxChunkSize, base64Data.length);
            const chunk = base64Data.slice(start, end);

            // Add fragment header: [FRAG:id:index:total:data]
            const fragmentData = `FRAG:${fragmentId}:${i}:${totalChunks}:${chunk}`;
            await characteristic.writeWithResponse(fragmentData);

            if (i < totalChunks - 1) {
                await new Promise(resolve => setTimeout(resolve, 10));
            }
        }

        console.log(`📦 Sent ${totalChunks} fragments`);
    }

    /**
     * Check if data is a fragment
     */
    private isFragment(data: Uint8Array): boolean {
        const str = new TextDecoder().decode(data.slice(0, 5));
        return str === 'FRAG:';
    }

    /**
     * Handle incoming fragment
     */
    private handleIncomingFragment(connectionId: string, nodeId: string, data: Uint8Array): void {
        const str = new TextDecoder().decode(data);
        const parts = str.split(':');

        if (parts.length < 5) {
            console.error('Invalid fragment format');
            return;
        }

        const [, fragmentId, indexStr, totalStr, ...dataParts] = parts;
        const index = parseInt(indexStr);
        const total = parseInt(totalStr);
        const fragmentData = dataParts.join(':');

        // Get or create fragment buffer
        if (!this.fragmentBuffers.has(connectionId)) {
            this.fragmentBuffers.set(connectionId, new Map());
        }
        const buffer = this.fragmentBuffers.get(connectionId)!;

        // Store fragment
        buffer.set(index, new TextEncoder().encode(fragmentData));

        // Check if all fragments received
        if (buffer.size === total) {
            // Reassemble
            const assembled = new Uint8Array(
                Array.from(buffer.values()).reduce((acc, val) => acc + val.length, 0)
            );
            let offset = 0;
            for (let i = 0; i < total; i++) {
                const fragment = buffer.get(i)!;
                assembled.set(fragment, offset);
                offset += fragment.length;
            }

            // Clear buffer
            this.fragmentBuffers.delete(connectionId);

            // Process complete message
            this.handleIncomingMessage(assembled, nodeId);
        }
    }

    /**
     * Handle disconnection
     */
    private handleDisconnection(connectionId: string, nodeId: string, error?: Error): void {
        console.log(`🔌 Device disconnected: ${connectionId}`);

        // Cleanup
        this.devices.delete(connectionId);
        this.characteristics.delete(connectionId);
        this.fragmentBuffers.delete(connectionId);
        this.mtuSizes.delete(connectionId);

        // Notify parent class about disconnection
        const connection = this.getConnection(nodeId);
        if (connection) {
            connection.state = ConnectionState.DISCONNECTED;
        }
    }

    /**
     * Get device info
     */
    async getDeviceInfo(connectionId: string): Promise<{
        id: string;
        name?: string;
        rssi?: number;
        mtu?: number;
        isConnected: boolean;
    } | null> {
        const device = this.devices.get(connectionId);
        if (!device) {
            return null;
        }

        const isConnected = await device.isConnected();
        const mtu = this.mtuSizes.get(connectionId);

        return {
            id: device.id,
            name: device.name || undefined,
            rssi: device.rssi || undefined,
            mtu: mtu || undefined,
            isConnected
        };
    }

    /**
     * Validate all connections
     */
    async validateConnections(): Promise<void> {
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

        // Clean up invalid connections
        for (const connectionId of invalidConnections) {
            await this.disconnectFromDevice(connectionId);
        }

        console.log(`✅ Validated connections, removed ${invalidConnections.length} invalid`);
    }
}