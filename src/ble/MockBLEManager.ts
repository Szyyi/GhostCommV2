// mobile/src/ble/MockBLEManager.ts
import { EventEmitter } from 'events';
import {
    BLEManager,
    BLENode,
    BLEAdvertisementData,
    BLEMessage,
    BLE_CONFIG,
    GhostKeyPair,
    MessageFactory,
    MessageType,
    MessageEncryption,
    type BLEConnectionEvent,
    type BLEMessageEvent,
    type BLEDiscoveryEvent,
    type EncryptedMessage,
    type PlaintextMessage
} from '../../core';
import { BLEAdvertiser } from '../../core';
import { BLEScanner } from '../../core';
import { BLEConnectionManager } from '../../core';
import { MeshNetwork } from '../../core';
import { debug } from '../utils/debug';

/**
 * Mock implementations of the BLE components
 */
class MockBLEAdvertiser extends BLEAdvertiser {
    protected startPlatformAdvertising(data: BLEAdvertisementData): Promise<void> {
        throw new Error('Method not implemented.');
    }
    protected stopPlatformAdvertising(): Promise<void> {
        throw new Error('Method not implemented.');
    }
    private mockIsAdvertising = false;

    async startAdvertising(data: BLEAdvertisementData): Promise<void> {
        this.mockIsAdvertising = true;
        debug.info('[MOCK] Started advertising', data);
    }

    async stopAdvertising(): Promise<void> {
        this.mockIsAdvertising = false;
        debug.info('[MOCK] Stopped advertising');
    }

    getAdvertisingStatus(): { isAdvertising: boolean } {
        return { isAdvertising: this.mockIsAdvertising };
    }
}

class MockBLEScanner extends BLEScanner {
    protected startPlatformScanning(): Promise<void> {
        throw new Error('Method not implemented.');
    }
    protected stopPlatformScanning(): Promise<void> {
        throw new Error('Method not implemented.');
    }
    private mockIsScanning = false;
    private mockDiscoveredNodes: Map<string, BLENode> = new Map();
    private mockDiscoveryCallbacks: Array<(event: BLEDiscoveryEvent) => void> = [];

    async startScanning(): Promise<void> {
        this.mockIsScanning = true;
        debug.info('[MOCK] Started scanning');
    }

    async stopScanning(): Promise<void> {
        this.mockIsScanning = false;
        debug.info('[MOCK] Stopped scanning');
    }

    getScanningStatus(): { isScanning: boolean; nodeCount: number } {
        return { isScanning: this.mockIsScanning, nodeCount: this.mockDiscoveredNodes.size };
    }

    getDiscoveredNodes(): BLENode[] {
        return Array.from(this.mockDiscoveredNodes.values());
    }

    getDiscoveredNode(nodeId: string): BLENode | undefined {
        return this.mockDiscoveredNodes.get(nodeId);
    }

    updateNodeConnectionStatus(nodeId: string, isConnected: boolean): void {
        const node = this.mockDiscoveredNodes.get(nodeId);
        if (node) {
            node.isConnected = isConnected;
        }
    }

    onNodeDiscovery(callback: (event: BLEDiscoveryEvent) => void): void {
        this.mockDiscoveryCallbacks.push(callback);
    }

    addMockNode(node: BLENode): void {
        this.mockDiscoveredNodes.set(node.id, node);
        this.mockDiscoveryCallbacks.forEach(cb => cb({
            type: 'node_discovered',
            node
        }));
    }
}

class MockBLEConnectionManager extends BLEConnectionManager {
    protected connectToDevice(deviceId: string, nodeId: string): Promise<string> {
        throw new Error('Method not implemented.');
    }
    protected disconnectFromDevice(connectionId: string): Promise<void> {
        throw new Error('Method not implemented.');
    }
    protected sendDataToDevice(connectionId: string, data: string): Promise<void> {
        throw new Error('Method not implemented.');
    }
    protected setupMessageReceiving(connectionId: string, nodeId: string): Promise<void> {
        throw new Error('Method not implemented.');
    }
    private connectedNodes: Map<string, BLENode> = new Map();
    private mockConnectionCallbacks: Array<(event: BLEConnectionEvent) => void> = [];
    private mockMessageCallbacks: Array<(message: BLEMessage, fromNodeId: string) => void> = [];

    async connectToNode(node: BLENode, deviceId: string): Promise<string> {
        this.connectedNodes.set(node.id, node);
        this.mockConnectionCallbacks.forEach(cb => cb({
            type: 'connected',
            nodeId: node.id,
            connectionId: deviceId
        }));
        return deviceId;
    }

    async sendMessage(nodeId: string, message: BLEMessage): Promise<void> {
        debug.info(`[MOCK] Sending message to ${nodeId}`, message.messageId);
        // Simulate successful send
    }

    async broadcastMessage(message: BLEMessage, excludeNodeId?: string): Promise<{ sent: number; failed: number }> {
        const nodes = Array.from(this.connectedNodes.keys()).filter(id => id !== excludeNodeId);
        debug.info(`[MOCK] Broadcasting to ${nodes.length} nodes`);
        return { sent: nodes.length, failed: 0 };
    }

    isConnectedTo(nodeId: string): boolean {
        return this.connectedNodes.has(nodeId);
    }

    async cleanup(): Promise<void> {
        this.connectedNodes.clear();
    }

    async validateConnections(): Promise<void> {
        debug.info('[MOCK] Validating connections');
    }

    async getConnectionStatistics(): Promise<{ activeConnections: number }> {
        return { activeConnections: this.connectedNodes.size };
    }

    onConnectionEvent(callback: (event: BLEConnectionEvent) => void): void {
        this.mockConnectionCallbacks.push(callback);
    }

    onMessage(callback: (message: BLEMessage, fromNodeId: string) => void): void {
        this.mockMessageCallbacks.push(callback);
    }

    simulateIncomingMessage(message: BLEMessage, fromNodeId: string): void {
        this.mockMessageCallbacks.forEach(cb => cb(message, fromNodeId));
    }
}

/**
 * Mock BLE Manager for testing in emulator
 * Extends the core BLEManager and simulates mesh network behavior
 */
export class MockBLEManager extends BLEManager {
    private mockScanner: MockBLEScanner;
    private mockConnectionManager: MockBLEConnectionManager;
    private mockAdvertiser: MockBLEAdvertiser;
    private simulationInterval?: NodeJS.Timeout;
    private mockDevices: Map<string, BLENode> = new Map();

    constructor(keyPair?: GhostKeyPair) {
        const keys = keyPair || new GhostKeyPair();
        const advertiser = new MockBLEAdvertiser();
        const scanner = new MockBLEScanner();
        const connectionManager = new MockBLEConnectionManager();

        super(keys, advertiser, scanner, connectionManager);

        this.mockAdvertiser = advertiser;
        this.mockScanner = scanner;
        this.mockConnectionManager = connectionManager;

        this.initializeMockDevices();
        debug.info('[MOCK] BLE Manager initialized for testing');
    }

    private initializeMockDevices() {
        // Create some fake devices for testing
        const mockNodes = [
            { id: 'GHOST-A1B2C3', alias: 'Alice', rssi: -45 },
            { id: 'GHOST-D4E5F6', alias: 'Bob', rssi: -62 },
            { id: 'GHOST-789ABC', alias: 'Charlie', rssi: -78 },
            { id: 'GHOST-DEF012', alias: 'Diana', rssi: -85 }
        ];

        mockNodes.forEach(nodeData => {
            // Create mock keypairs for each node
            const mockKeyPair = new GhostKeyPair();

            const node: BLENode = {
                id: nodeData.id,
                name: nodeData.alias,
                publicKey: mockKeyPair.getIdentityPublicKey(),
                encryptionKey: mockKeyPair.getEncryptionPublicKey(),
                lastSeen: Date.now(),
                rssi: nodeData.rssi,
                isConnected: false,
                connectionId: `conn-${nodeData.id}`
            };

            this.mockDevices.set(node.id, node);
        });
    }

    async initialize(): Promise<void> {
        debug.info('[MOCK] Initializing mock BLE system');
        await this.simulateDelay(500);

        // Start the parent BLE manager
        await this.start();

        // Start simulation
        this.startSimulation();
    }

    private startSimulation() {
        // Simulate discovering devices one by one
        let deviceIndex = 0;
        const devices = Array.from(this.mockDevices.values());

        const discoveryInterval = setInterval(() => {
            if (deviceIndex < devices.length) {
                const device = devices[deviceIndex];
                debug.info(`[MOCK] Discovering device: ${device.id}`);
                this.mockScanner.addMockNode(device);
                deviceIndex++;
            } else {
                clearInterval(discoveryInterval);
            }
        }, 1500);

        // Simulate network events
        this.simulationInterval = setInterval(() => {
            const events = [
                () => this.simulateDeviceRSSIChange(),
                () => this.simulateIncomingMessage(),
                () => this.simulateNewDeviceDiscovery()
            ];

            // Randomly trigger an event
            if (Math.random() > 0.7) {
                const event = events[Math.floor(Math.random() * events.length)];
                event();
            }
        }, 5000);
    }

    private simulateDeviceRSSIChange() {
        const nodes = this.mockScanner.getDiscoveredNodes();
        if (nodes.length === 0) return;

        const node = nodes[Math.floor(Math.random() * nodes.length)];
        node.rssi = -40 - Math.floor(Math.random() * 60);
        node.lastSeen = Date.now();

        debug.debug(`[MOCK] RSSI changed for ${node.id}: ${node.rssi}dBm`);
    }

    private simulateIncomingMessage() {
        const nodes = this.mockScanner.getDiscoveredNodes();
        const connectedNodes = nodes.filter(n => n.isConnected);
        if (connectedNodes.length === 0) return;

        const fromNode = connectedNodes[Math.floor(Math.random() * connectedNodes.length)];

        const mockResponses = [
            "Roger that, message received.",
            "Acknowledged. Standing by.",
            "Copy that. All systems operational.",
            "Message confirmed. Mesh stable.",
            "Signal strong. Relay active."
        ];

        // Create a mock plaintext message
        const plaintextMessage = MessageFactory.createDirectMessage(
            fromNode.id,
            this.keyPair.getFingerprint(),
            mockResponses[Math.floor(Math.random() * mockResponses.length)]
        );

        // Create a mock encrypted message (we won't actually encrypt in mock mode)
        const encryptedMessage: EncryptedMessage = {
            senderId: fromNode.id,
            recipientId: this.keyPair.getFingerprint(),
            ephemeralPublicKey: 'mock-ephemeral-key',
            nonce: 'mock-nonce',
            ciphertext: 'mock-ciphertext',
            authTag: 'mock-auth-tag',
            messageId: plaintextMessage.messageId,
            timestamp: plaintextMessage.timestamp
        };

        const bleMessage: BLEMessage = {
            messageId: encryptedMessage.messageId,
            encryptedPayload: JSON.stringify(encryptedMessage),
            ttl: Date.now() + BLE_CONFIG.MESSAGE_TTL,
            hopCount: 1
        };

        debug.info(`[MOCK] Simulating incoming message from ${fromNode.id}`);
        this.mockConnectionManager.simulateIncomingMessage(bleMessage, fromNode.id);
    }

    private simulateNewDeviceDiscovery() {
        const newNode: BLENode = {
            id: `GHOST-${Math.random().toString(36).substr(2, 6).toUpperCase()}`,
            name: `Node-${Math.floor(Math.random() * 100)}`,
            publicKey: new Uint8Array(32),
            encryptionKey: new Uint8Array(32),
            lastSeen: Date.now(),
            rssi: -40 - Math.floor(Math.random() * 50),
            isConnected: false,
            connectionId: undefined
        };

        this.mockDevices.set(newNode.id, newNode);
        debug.info(`[MOCK] New device discovered: ${newNode.id}`);
        this.mockScanner.addMockNode(newNode);
    }

    private simulateDelay(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    // Additional mock-specific methods for testing
    async connectToNode(nodeId: string): Promise<void> {
        const node = this.mockDevices.get(nodeId);
        if (!node) {
            throw new Error(`Node ${nodeId} not found`);
        }

        await this.simulateDelay(800);
        node.isConnected = true;
        await this.mockConnectionManager.connectToNode(node, node.connectionId || nodeId);
        debug.info(`[MOCK] Connected to ${nodeId}`);
    }

    async disconnectFromNode(nodeId: string): Promise<void> {
        const node = this.mockDevices.get(nodeId);
        if (node) {
            node.isConnected = false;
        }
        debug.info(`[MOCK] Disconnected from ${nodeId}`);
    }

    getDiscoveredNodes(): BLENode[] {
        return this.mockScanner.getDiscoveredNodes();
    }

    async getNetworkStats(): Promise<any> {
        const status = this.getNetworkStatus();
        const scanStatus = this.mockScanner.getScanningStatus();
        const advStatus = this.mockAdvertiser.getAdvertisingStatus();
        const connectionStats = await this.mockConnectionManager.getConnectionStatistics();

        return {
            nodeId: this.keyPair.getFingerprint(),
            discoveredNodes: status.discoveredNodes,
            activeConnections: connectionStats.activeConnections,
            messagesRelayed: status.meshStats.messagesForwarded,
            platform: 'mock',
            bleState: 'PoweredOn',
            isScanning: scanStatus.isScanning,
            isAdvertising: advStatus.isAdvertising
        };
    }

    async cleanup(): Promise<void> {
        if (this.simulationInterval) {
            clearInterval(this.simulationInterval);
        }
        await this.stop();
        debug.info('[MOCK] BLE Manager destroyed');
    }

    isReady(): boolean {
        return true;
    }

    getNodeId(): string {
        return this.keyPair.getFingerprint();
    }
}

// Export a function to detect if we should use mock
export function shouldUseMockBLE(): boolean {
    // Check if we're in an emulator or if BLE is not available
    // @ts-ignore
    const isEmulator = __DEV__ && !global.nativeCallSyncHook;
    return isEmulator || process.env.USE_MOCK_BLE === 'true';
}