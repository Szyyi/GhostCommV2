// mobile/src/ble/ReactNativeBLEConnectionManager.ts
import { BleManager, Device, Characteristic } from 'react-native-ble-plx';
import { Platform } from 'react-native';
import {
    BLEConnectionManager,
    BLE_CONFIG,
    ConnectionState
} from '../../core';

/**
 * React Native BLE Connection Manager Implementation
 * 
 * This class ONLY implements platform-specific BLE operations.
 * All Protocol v2 security features (handshakes, verification, message chains)
 * are handled by the base BLEConnectionManager class.
 */
export class ReactNativeBLEConnectionManager extends BLEConnectionManager {
    private bleManager: BleManager;
    private devices: Map<string, Device> = new Map();
    private characteristics: Map<string, Characteristic> = new Map();
    private mtuSizes: Map<string, number> = new Map();
    private connectionNodeMap: Map<string, string> = new Map(); // connectionId -> nodeId

    constructor(keyPair?: any, bleManager?: BleManager) {
        super(keyPair);
        this.bleManager = bleManager || new BleManager();
    }

    /**
     * Platform-specific: Connect to a BLE device
     * The base class handles Protocol v2 handshake after connection
     */
    protected async connectToDevice(deviceId: string, nodeId: string): Promise<string> {
        try {
            console.log(`🔗 Connecting to device: ${deviceId} (node: ${nodeId})`);

            const device = await this.bleManager.connectToDevice(deviceId, {
                autoConnect: false,
                requestMTU: BLE_CONFIG.MAX_MTU,
                refreshGatt: 'OnConnected',
                timeout: BLE_CONFIG.CONNECTION_TIMEOUT
            });

            const connectionId = device.id;
            console.log(` Connected to device: ${connectionId}`);

            // Discover services and characteristics
            await device.discoverAllServicesAndCharacteristics();
            await this.setupGhostCommService(device);

            // Store device and mapping
            this.devices.set(connectionId, device);
            this.connectionNodeMap.set(connectionId, nodeId);

            // Setup disconnection handler
            device.onDisconnected((error, disconnectedDevice) => {
                this.handleDisconnection(disconnectedDevice?.id || connectionId, error || undefined);
            });

            return connectionId;

        } catch (error) {
            console.error(` Failed to connect to device ${deviceId}:`, error);
            throw error;
        }
    }

    /**
     * Platform-specific: Disconnect from a BLE device
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
            this.mtuSizes.delete(connectionId);
            this.connectionNodeMap.delete(connectionId);

            console.log(` Disconnected from device: ${connectionId}`);

        } catch (error) {
            console.error(` Failed to disconnect from device ${connectionId}:`, error);
            throw error;
        }
    }

    /**
     * Platform-specific: Send data to a BLE device
     * The base class handles Protocol v2 message creation and signing
     */
    protected async sendDataToDevice(connectionId: string, data: Uint8Array): Promise<void> {
        try {
            const characteristic = this.characteristics.get(connectionId);
            if (!characteristic) {
                throw new Error(`No characteristic for connection: ${connectionId}`);
            }

            const mtu = this.mtuSizes.get(connectionId) || BLE_CONFIG.DEFAULT_MTU;
            const maxChunkSize = mtu - 3; // BLE overhead

            // Convert to base64 for react-native-ble-plx
            const base64Data = Buffer.from(data).toString('base64');

            if (base64Data.length <= maxChunkSize) {
                // Send in one chunk
                await characteristic.writeWithResponse(base64Data);
            } else {
                // Fragment if needed
                await this.sendFragmented(characteristic, base64Data, maxChunkSize);
            }

            console.log(` Sent ${data.length} bytes to connection: ${connectionId}`);

        } catch (error) {
            console.error(` Failed to send data to ${connectionId}:`, error);
            throw error;
        }
    }

    /**
     * Platform-specific: Setup message receiving
     * The base class handles Protocol v2 verification via handleIncomingMessage
     */
    protected async setupMessageReceiving(connectionId: string, nodeId: string): Promise<void> {
        try {
            const characteristic = this.characteristics.get(connectionId);
            if (!characteristic) {
                throw new Error(`No characteristic for connection: ${connectionId}`);
            }

            // Setup notification handler
            characteristic.monitor((error, char) => {
                if (error) {
                    console.error(` Monitor error for ${nodeId}:`, error);
                    return;
                }

                if (char?.value) {
                    try {
                        const data = Buffer.from(char.value, 'base64');
                        
                        // Pass to base class for Protocol v2 handling
                        // The base class will verify signatures, check message chains, etc.
                        this.handleIncomingMessage(data, nodeId);
                        
                    } catch (decodeError) {
                        console.error(` Decode error from ${nodeId}:`, decodeError);
                    }
                }
            });

            console.log(` Message receiving setup for node: ${nodeId}`);

        } catch (error) {
            console.error(` Failed to setup message receiving for ${nodeId}:`, error);
            throw error;
        }
    }

    /**
     * Platform-specific: Negotiate MTU size
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
            console.log(` MTU negotiated: ${actualMTU} for ${connectionId}`);

            return actualMTU;

        } catch (error) {
            console.error(` MTU negotiation failed for ${connectionId}:`, error);
            return BLE_CONFIG.DEFAULT_MTU;
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

        // React Native BLE PLX doesn't expose these directly
        // Return default values
        return {
            interval: BLE_CONFIG.CONNECTION_INTERVAL_MIN,
            latency: BLE_CONFIG.CONNECTION_LATENCY,
            timeout: BLE_CONFIG.SUPERVISION_TIMEOUT
        };
    }

    /**
     * Helper: Setup GhostComm BLE service
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
        const messageChar = characteristics.find(c =>
            c.uuid.toLowerCase() === BLE_CONFIG.CHARACTERISTICS.MESSAGE_EXCHANGE.toLowerCase()
        );

        if (!messageChar) {
            throw new Error(`Message characteristic not found on device: ${device.id}`);
        }

        this.characteristics.set(device.id, messageChar);
        console.log(` GhostComm service setup complete for: ${device.id}`);
    }

    /**
     * Helper: Send fragmented data
     */
    private async sendFragmented(
        characteristic: Characteristic,
        base64Data: string,
        maxChunkSize: number
    ): Promise<void> {
        const totalChunks = Math.ceil(base64Data.length / maxChunkSize);

        for (let i = 0; i < totalChunks; i++) {
            const start = i * maxChunkSize;
            const end = Math.min(start + maxChunkSize, base64Data.length);
            const chunk = base64Data.slice(start, end);

            await characteristic.writeWithResponse(chunk);

            // Small delay between chunks to avoid overwhelming the device
            if (i < totalChunks - 1) {
                await new Promise(resolve => setTimeout(resolve, 10));
            }
        }

        console.log(` Sent ${totalChunks} fragments`);
    }

    /**
     * Helper: Handle device disconnection
     */
    private handleDisconnection(connectionId: string, error?: Error): void {
        console.log(`🔌 Device disconnected: ${connectionId}`, error ? `Error: ${error}` : '');

        // Get node ID for this connection
        const nodeId = this.connectionNodeMap.get(connectionId);

        // Cleanup local state
        this.devices.delete(connectionId);
        this.characteristics.delete(connectionId);
        this.mtuSizes.delete(connectionId);
        this.connectionNodeMap.delete(connectionId);

        // The base class will handle connection state updates and events
        if (nodeId) {
            const connection = this.getConnection(nodeId);
            if (connection) {
                connection.state = ConnectionState.DISCONNECTED;
            }
        }
    }

    /**
     * Additional helper: Get device info
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
     * Additional helper: Validate all connections
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

        // Disconnect invalid connections
        for (const connectionId of invalidConnections) {
            await this.disconnectFromDevice(connectionId);
        }

        console.log(` Validated connections, removed ${invalidConnections.length} invalid`);
    }
}