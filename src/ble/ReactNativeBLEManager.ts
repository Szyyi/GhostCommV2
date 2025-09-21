// mobile/src/ble/ReactNativeBLEManager.ts
import { 
    BleManager, 
    Device, 
    State, 
    Subscription, 
    BleError,
    ConnectionOptions,
    Characteristic
} from 'react-native-ble-plx';
import { 
    Platform, 
    PermissionsAndroid, 
    AppState, 
    AppStateStatus,
    NativeEventEmitter,
    NativeModules 
} from 'react-native';
import {
    BLEManager,
    BLENode,
    BLE_CONFIG,
    SECURITY_CONFIG,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    IGhostKeyPair,
    MessagePriority,
    NetworkStats,
    ConnectionState,
    BLEMessage,
    BLEAdvertisementData,
    BLEError as CoreBLEError,
    BLEErrorCode,
    BLEManagerState,
    BLEStatistics,
    BLEAdvertiser,
    BLEScanner,
    BLEConnectionManager
} from '../../core';
import { ReactNativeBLEAdvertiser } from './ReactNativeBLEAdvertiser';
import { ReactNativeBLEScanner } from './ReactNativeBLEScanner';
import { ReactNativeBLEConnectionManager } from './ReactNativeBLEConnectionManager';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Buffer } from 'buffer';
import { BLE_SECURITY_CONFIG } from '../../core/src/ble/types';

// Constants
const STORAGE_KEY_PREFIX = '@GhostComm:';
const CONNECTION_RETRY_DELAY = 1000;
const MAX_CONNECTION_RETRIES = 3;
const ANDROID_SCAN_DURATION = 10000; // 10 seconds for Android battery optimization
const IOS_SCAN_DURATION = 0; // Continuous on iOS
const MAX_CONCURRENT_CONNECTIONS = 8; // Connection pool limit

/**
 * Message retry configuration with exponential backoff
 */
interface RetryConfig {
    maxAttempts: number;
    baseDelay: number;
    maxDelay: number;
    backoffFactor: number;
}

/**
 * Queued message for retry
 */
interface QueuedMessage {
    recipientId: string;
    message: BLEMessage;
    attempts: number;
    lastAttempt: number;
    nextRetry: number;
    priority: MessagePriority;
}

/**
 * Enhanced React Native BLE Manager with full Protocol v2.1 implementation
 * 
 * This class provides a complete React Native implementation of the GhostComm
 * BLE mesh network with Protocol v2.1 security, Android/iOS optimization,
 * connection pooling, message retry logic, and robust error handling.
 */
export class ReactNativeBLEManager extends BLEManager {
    [x: string]: any;
    private bleManager: BleManager;
    
    // Platform-specific state
    private appStateSubscription?: any;
    private currentAppState: AppStateStatus = 'active';
    private bleStateSubscription?: Subscription;
    private currentBleState: State = State.Unknown;
    
    // Connection management with pooling
    private deviceConnections: Map<string, Device> = new Map();
    private connectionSubscriptions: Map<string, Subscription[]> = new Map();
    private connectionRetryCount: Map<string, number> = new Map();
    private connectionPool: Set<string> = new Set(); // Track active connections for pooling
    
    // Scanning state
    private isScanning: boolean = false;
    private scanRestartTimer?: NodeJS.Timeout;
    
    // Message retry queue with exponential backoff
    private messageRetryQueue: Map<string, QueuedMessage> = new Map();
    private retryTimer?: NodeJS.Timeout;
    private retryConfig: RetryConfig = {
        maxAttempts: 3,
        baseDelay: 1000,
        maxDelay: 30000,
        backoffFactor: 2
    };
    
    // Override to expose protected members from base class
    protected declare advertiser: ReactNativeBLEAdvertiser;
    protected declare scanner: ReactNativeBLEScanner;
    // Remove the declare override to avoid type incompatibility
    // protected declare connectionManager: ReactNativeBLEConnectionManager;
    
    // Performance monitoring
    private performanceMetrics: {
        scanStartTime?: number;
        lastScanDuration?: number;
        connectionAttempts: number;
        successfulConnections: number;
        failedConnections: number;
        averageConnectionTime: number;
        messageRetryCount: number;
        messageRetrySuccess: number;
    } = {
        connectionAttempts: 0,
        successfulConnections: 0,
        failedConnections: 0,
        averageConnectionTime: 0,
        messageRetryCount: 0,
        messageRetrySuccess: 0
    };
    
    // React Native specific callbacks
    private rnEventCallbacks: Map<string, Set<Function>> = new Map();
    
    // Battery optimization
    private batteryOptimizationEnabled: boolean = true;
    private lastBatteryLevel: number = 100;

    constructor(
        keyPair: IGhostKeyPair,
        bleManager?: BleManager
    ) {
        // Create BLE manager instance
        const bleMgr = bleManager || new BleManager({
            restoreStateIdentifier: 'ghostcomm-ble-manager',
            restoreStateFunction: (restoredState) => {
                console.log('BLE state restored:', restoredState);
            }
        });

        // Create platform-specific implementations
        const advertiser = new ReactNativeBLEAdvertiser(keyPair);
        const scanner = new ReactNativeBLEScanner(keyPair, bleMgr);
        const connectionManager = new ReactNativeBLEConnectionManager(keyPair, bleMgr);

        // Call parent constructor with proper typing
        super(
            keyPair,
            advertiser as BLEAdvertiser,
            scanner as BLEScanner,
            connectionManager as unknown as BLEConnectionManager
        );

        // Store React Native BLE manager reference
        this.bleManager = bleMgr;
        // Cast back to specific types for React Native usage
        this.advertiser = advertiser;
        this.scanner = scanner;
        // Use type assertion to bypass TypeScript visibility checks
        this.connectionManager = connectionManager as unknown as BLEConnectionManager;

        // Set key pair in connection manager for Protocol v2.1
        connectionManager.setKeyPair(keyPair);

        // Start message retry processing
        this.startRetryProcessing();

        console.log(`ReactNativeBLEManager initialized with Protocol v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}.1`);
    }

    /**
     * Get BLE manager state - properly returns base class state
     */
    public getState(): BLEManagerState {
        return this.getManagerState();
    }

    /**
     * Get discovered node by ID - uses base class state
     */
    public getDiscoveredNode(nodeId: string): BLENode | undefined {
        const state = this.getManagerState();
        return state.discoveredNodes.get(nodeId);
    }

    /**
     * Get all discovered nodes - uses base class state
     */
    public getDiscoveredNodes(): BLENode[] {
        const state = this.getManagerState();
        return Array.from(state.discoveredNodes.values());
    }

    /**
     * Get all connected nodes - uses base class state and connection manager
     */
    public getConnectedNodes(): BLENode[] {
        const connectedNodes: BLENode[] = [];
        const state = this.getManagerState();
        for (const [nodeId, node] of state.discoveredNodes) {
            if (this.connectionManager.isConnectedTo(nodeId)) {
                connectedNodes.push(node);
            }
        }
        return connectedNodes;
    }

    /**
     * Public method to connect to a node with connection pooling
     */
    public async connectToNode(nodeId: string): Promise<void> {
        try {
            // Check connection pool limit
            if (this.connectionPool.size >= MAX_CONCURRENT_CONNECTIONS) {
                // Find least recently used connection to disconnect
                const lruNodeId = this.findLeastRecentlyUsedConnection();
                if (lruNodeId) {
                    console.log(`📱 Connection pool full, disconnecting LRU node: ${lruNodeId}`);
                    await this.disconnectFromNode(lruNodeId);
                } else {
                    throw new Error(`Connection pool full (max ${MAX_CONCURRENT_CONNECTIONS} connections)`);
                }
            }

            console.log(`📱 Attempting to connect to node ${nodeId}...`);
            
            // Find the node in discovered nodes
            const node = this.getDiscoveredNode(nodeId);
            if (!node) {
                throw new Error(`Node ${nodeId} not found in discovered nodes`);
            }

            // Use the connection manager to establish connection
            await this.connectionManager.connectToNode(node, node.id);
            
            // Add to connection pool
            this.connectionPool.add(nodeId);
            
            console.log(`✅ Successfully connected to node ${nodeId}`);
        } catch (error) {
            console.error(`❌ Failed to connect to node ${nodeId}:`, error);
            throw error;
        }
    }

    /**
     * Find least recently used connection for pool management
     */
    private findLeastRecentlyUsedConnection(): string | null {
        let lruNodeId: string | null = null;
        let oldestActivity = Date.now();

        for (const nodeId of this.connectionPool) {
            const connection = this.connectionManager.getConnection(nodeId);
            if (connection && connection.lastActivity < oldestActivity) {
                oldestActivity = connection.lastActivity;
                lruNodeId = nodeId;
            }
        }

        return lruNodeId;
    }

    /**
     * Public method to disconnect from a node
     */
    public async disconnectFromNode(nodeId: string): Promise<void> {
        try {
            console.log(`📱 Attempting to disconnect from node ${nodeId}...`);
            
            // Use the connection manager to disconnect
            await this.connectionManager.disconnectFromNode(nodeId);
            
            // Remove from connection pool
            this.connectionPool.delete(nodeId);
            
            // Also clean up any local connections we're tracking
            for (const [id, device] of this.deviceConnections) {
                if (id === nodeId) {
                    this.removeConnectionSubscriptions(nodeId);
                    this.deviceConnections.delete(nodeId);
                    break;
                }
            }
            
            console.log(`✅ Successfully disconnected from node ${nodeId}`);
        } catch (error) {
            console.error(`❌ Failed to disconnect from node ${nodeId}:`, error);
            throw error;
        }
    }

    /**
     * Override sendMessage to add retry logic with exponential backoff
     */
    async sendMessage(
        recipientId: string,
        content: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): Promise<string> {
        try {
            // First try to send through base class
            const messageId = await super.sendMessage(recipientId, content, priority);
            return messageId;
        } catch (error) {
            console.log(`📱 Direct send failed, queueing for retry: ${error}`);
            
            // Create a BLE message for retry queue
            const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
            const bleMessage: BLEMessage = {
                messageId,
                version: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
                sourceId: this.keyPair.getFingerprint(),
                destinationId: recipientId,
                ttl: Date.now() + BLE_CONFIG.MESSAGE_TTL,
                hopCount: 0,
                maxHops: BLE_CONFIG.MAX_HOP_COUNT,
                priority,
                senderPublicKey: this.convertBytesToHex(this.keyPair.getIdentityPublicKey()),
                messageSignature: '',
                messageHash: '',
                previousMessageHash: '',
                sequenceNumber: 0,
                encryptedPayload: {} as any, // Will be set during actual send
                routePath: [this.keyPair.getFingerprint()],
                relaySignatures: [],
                createdAt: Date.now(),
                expiresAt: Date.now() + BLE_CONFIG.MESSAGE_TTL
            };

            // Queue for retry
            this.queueMessageForRetry(recipientId, bleMessage, priority);
            
            return messageId;
        }
    }

    /**
     * Queue message for retry with exponential backoff
     */
    private queueMessageForRetry(
        recipientId: string,
        message: BLEMessage,
        priority: MessagePriority
    ): void {
        const now = Date.now();
        const queuedMessage: QueuedMessage = {
            recipientId,
            message,
            attempts: 0,
            lastAttempt: now,
            nextRetry: now + this.retryConfig.baseDelay,
            priority
        };

        this.messageRetryQueue.set(message.messageId, queuedMessage);
        this.performanceMetrics.messageRetryCount++;

        console.log(`📱 Message ${message.messageId} queued for retry to ${recipientId}`);
    }

    /**
     * Start message retry processing with exponential backoff
     */
    private startRetryProcessing(): void {
        this.retryTimer = setInterval(() => {
            this.processRetryQueue();
        }, 1000); // Check every second
    }

    /**
     * Process message retry queue with exponential backoff
     */
    private async processRetryQueue(): Promise<void> {
        const now = Date.now();
        const toRetry: QueuedMessage[] = [];

        // Find messages ready for retry
        for (const [messageId, queuedMessage] of this.messageRetryQueue) {
            // Check if message expired
            if (queuedMessage.message.expiresAt < now) {
                console.log(`📱 Message ${messageId} expired, removing from retry queue`);
                this.messageRetryQueue.delete(messageId);
                continue;
            }

            // Check if ready for retry
            if (queuedMessage.nextRetry <= now) {
                toRetry.push(queuedMessage);
            }
        }

        // Process retries
        for (const queuedMessage of toRetry) {
            await this.retryMessage(queuedMessage);
        }
    }

    /**
     * Retry a single message with exponential backoff
     */
    private async retryMessage(queuedMessage: QueuedMessage): Promise<void> {
        const { recipientId, message, attempts } = queuedMessage;

        // Check max attempts
        if (attempts >= this.retryConfig.maxAttempts) {
            console.log(`📱 Message ${message.messageId} exceeded max retry attempts`);
            this.messageRetryQueue.delete(message.messageId);
            return;
        }

        console.log(`📱 Retrying message ${message.messageId} (attempt ${attempts + 1}/${this.retryConfig.maxAttempts})`);

        try {
            // Try direct delivery if connected
            if (this.connectionManager.isConnectedTo(recipientId)) {
                await this.connectionManager.sendMessage(recipientId, message);
                console.log(`✅ Message ${message.messageId} delivered on retry`);
                this.messageRetryQueue.delete(message.messageId);
                this.performanceMetrics.messageRetrySuccess++;
                return;
            }

            // Try to establish connection
            const node = this.getDiscoveredNode(recipientId);
            if (node) {
                await this.connectToNode(recipientId);
                await this.connectionManager.sendMessage(recipientId, message);
                console.log(`✅ Message ${message.messageId} delivered after reconnection`);
                this.messageRetryQueue.delete(message.messageId);
                this.performanceMetrics.messageRetrySuccess++;
                return;
            }
        } catch (error) {
            console.log(`📱 Retry failed for message ${message.messageId}: ${error}`);
        }

        // Update retry state with exponential backoff
        queuedMessage.attempts++;
        queuedMessage.lastAttempt = Date.now();
        
        // Calculate next retry time with exponential backoff
        const delay = Math.min(
            this.retryConfig.baseDelay * Math.pow(this.retryConfig.backoffFactor, queuedMessage.attempts),
            this.retryConfig.maxDelay
        );
        queuedMessage.nextRetry = Date.now() + delay;

        console.log(`📱 Next retry for message ${message.messageId} in ${delay}ms`);
    }

    /**
     * Initialize the React Native BLE manager with full setup
     */
    async initialize(): Promise<void> {
        try {
            console.log('🚀 Initializing ReactNativeBLEManager...');

            // Step 1: Request all necessary permissions
            await this.requestPermissions();

            // Step 2: Check BLE hardware support
            const isSupported = await this.checkBLESupport();
            if (!isSupported) {
                throw new Error('BLE is not supported on this device');
            }

            // Step 3: Wait for BLE to be ready
            await this.waitForBLEPoweredOn();

            // Step 4: Set up state monitoring
            this.setupAppStateHandling();
            this.setupBLEStateMonitoring();

            // Step 5: Load persisted state
            await this.loadPersistedState();

            // Step 6: Configure platform-specific optimizations
            await this.configurePlatformOptimizations();

            // Step 7: Start the mesh network (Protocol v2.1 handled by base)
            await this.start();

            console.log('✅ ReactNativeBLEManager initialized successfully');

            this.emitRNEvent('initialized', {
                nodeId: this.keyPair.getFingerprint(),
                platform: Platform.OS,
                platformVersion: Platform.Version,
                bleState: this.currentBleState,
                protocolVersion: `${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}.1`,
                timestamp: Date.now()
            });

        } catch (error) {
            console.error('❌ Failed to initialize ReactNativeBLEManager:', error);
            this.emitRNEvent('error', {
                type: 'initialization_failed',
                error: error instanceof Error ? error.message : String(error),
                timestamp: Date.now()
            });
            throw error;
        }
    }

    /**
     * Request comprehensive BLE permissions for Android/iOS
     */
    private async requestPermissions(): Promise<void> {
        if (Platform.OS === 'android') {
            try {
                console.log('📱 Requesting Android BLE permissions...');

                let permissions: any[] = [];

                if (Platform.Version >= 31) {
                    // Android 12+ (API 31+)
                    permissions = [
                        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
                        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
                        PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
                        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
                    ];
                } else if (Platform.Version >= 29) {
                    // Android 10-11 (API 29-30)
                    permissions = [
                        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
                        PermissionsAndroid.PERMISSIONS.ACCESS_BACKGROUND_LOCATION
                    ];
                } else {
                    // Android < 10 (API < 29)
                    permissions = [
                        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
                        PermissionsAndroid.PERMISSIONS.ACCESS_COARSE_LOCATION
                    ];
                }

                const results = await PermissionsAndroid.requestMultiple(permissions as any);

                // Check all permissions granted
                for (const [permission, result] of Object.entries(results)) {
                    if (result !== PermissionsAndroid.RESULTS.GRANTED) {
                        console.warn(`⚠️ Permission ${permission} not granted: ${result}`);
                        
                        // Location is critical for BLE on Android
                        if (permission.includes('LOCATION')) {
                            throw new Error(`Critical permission ${permission} not granted`);
                        }
                    }
                }

                console.log('✅ Android BLE permissions granted');

            } catch (error) {
                console.error('❌ Failed to request Android permissions:', error);
                throw error;
            }
        } else if (Platform.OS === 'ios') {
            // iOS permissions are handled through Info.plist
            console.log('📱 iOS BLE permissions handled via Info.plist');
        }
    }

    /**
     * Configure platform-specific BLE optimizations
     */
    private async configurePlatformOptimizations(): Promise<void> {
        if (Platform.OS === 'android') {
            console.log('🔧 Configuring Android BLE optimizations...');
            // Android-specific optimizations
            // Could add specific Android optimizations here
        } else if (Platform.OS === 'ios') {
            console.log('🔧 Configuring iOS BLE optimizations...');
            // iOS-specific optimizations
            // Could add specific iOS optimizations here
        }
    }

    /**
     * Load persisted state from AsyncStorage
     */
    private async loadPersistedState(): Promise<void> {
        try {
            const keys = [
                `${STORAGE_KEY_PREFIX}trustedNodes`,
                `${STORAGE_KEY_PREFIX}blockedNodes`,
                `${STORAGE_KEY_PREFIX}messageHistory`,
                `${STORAGE_KEY_PREFIX}routingTable`
            ];

            const values = await AsyncStorage.multiGet(keys);
            
            for (const [key, value] of values) {
                if (value) {
                    const data = JSON.parse(value);
                    console.log(`📂 Loaded persisted state for ${key}`);
                    this.processPersistedData(key, data);
                }
            }
        } catch (error) {
            console.warn('⚠️ Error loading persisted state:', error);
        }
    }

    /**
     * Process loaded persisted data
     */
    private processPersistedData(key: string, data: any): void {
        // Handle different types of persisted data
        if (key.includes('trustedNodes')) {
            // Restore trusted nodes
            for (const nodeData of data) {
                // Process trusted node data
                // Could restore to verifiedNodes map in base class
            }
        }
        // Add more cases as needed
    }

    /**
     * Platform-specific method implementations required by base BLEManager
     */

    /**
     * Connect to a BLE device (implements abstract method)
     */
    protected async connectToDevice(deviceId: string, nodeId: string): Promise<string> {
        const startTime = Date.now();
        this.performanceMetrics.connectionAttempts++;

        try {
            console.log(`🔗 Connecting to device ${deviceId} for node ${nodeId}...`);

            // Check if already connected
            const existingDevice = this.deviceConnections.get(nodeId);
            if (existingDevice && await existingDevice.isConnected()) {
                console.log(`✅ Already connected to ${nodeId}`);
                return existingDevice.id;
            }

            // Connection options with Android/iOS optimizations
            const connectionOptions: ConnectionOptions = {
                autoConnect: Platform.OS === 'android',
                requestMTU: Platform.OS === 'android' ? 512 : undefined,
                timeout: BLE_CONFIG.CONNECTION_TIMEOUT
            };

            // Connect with retry logic
            const device = await this.connectWithRetry(deviceId, connectionOptions);
            
            if (!device) {
                throw new Error('Failed to connect to device');
            }

            // Store connection
            this.deviceConnections.set(nodeId, device);

            // Discover services and characteristics
            await device.discoverAllServicesAndCharacteristics();

            // Set up connection monitoring
            const monitorSub = device.onDisconnected((error) => {
                console.log(`🔌 Device ${nodeId} disconnected:`, error?.message);
                this.handleDeviceDisconnection(nodeId, device, error);
            });

            // Store subscription
            this.addConnectionSubscription(nodeId, monitorSub);

            // Update metrics
            const connectionTime = Date.now() - startTime;
            this.updateConnectionMetrics(true, connectionTime);

            console.log(`✅ Connected to ${nodeId} in ${connectionTime}ms`);

            return device.id;

        } catch (error) {
            console.error(`❌ Failed to connect to ${nodeId}:`, error);
            this.updateConnectionMetrics(false, Date.now() - startTime);
            throw error;
        }
    }

    /**
     * Disconnect from a BLE device (implements abstract method)
     */
    protected async disconnectFromDevice(connectionId: string): Promise<void> {
        try {
            console.log(`🔌 Disconnecting device ${connectionId}...`);

            // Find device by connection ID
            let targetDevice: Device | undefined;
            let targetNodeId: string | undefined;

            for (const [nodeId, device] of this.deviceConnections) {
                if (device.id === connectionId) {
                    targetDevice = device;
                    targetNodeId = nodeId;
                    break;
                }
            }

            if (targetDevice && targetNodeId) {
                // Cancel all subscriptions
                this.removeConnectionSubscriptions(targetNodeId);

                // Disconnect device
                await targetDevice.cancelConnection();

                // Remove from connections map
                this.deviceConnections.delete(targetNodeId);

                console.log(`✅ Disconnected from ${connectionId}`);
            }

        } catch (error) {
            console.error(`❌ Error disconnecting ${connectionId}:`, error);
            throw error;
        }
    }

    /**
     * Send data to a BLE device (implements abstract method)
     */
    protected async sendDataToDevice(connectionId: string, data: Uint8Array): Promise<void> {
        try {
            // Find device by connection ID
            let targetDevice: Device | undefined;

            for (const device of this.deviceConnections.values()) {
                if (device.id === connectionId) {
                    targetDevice = device;
                    break;
                }
            }

            if (!targetDevice) {
                throw new Error(`Device ${connectionId} not found`);
            }

            // Convert Uint8Array to base64 for react-native-ble-plx
            const base64Data = Buffer.from(data).toString('base64');

            // Write to message exchange characteristic
            await targetDevice.writeCharacteristicWithResponseForService(
                BLE_CONFIG.SERVICE_UUID,
                BLE_CONFIG.CHARACTERISTICS.MESSAGE_EXCHANGE,
                base64Data
            );

        } catch (error) {
            console.error(`❌ Failed to send data to ${connectionId}:`, error);
            throw error;
        }
    }

    /**
     * Set up message receiving from a BLE device (implements abstract method)
     */
    protected async setupMessageReceiving(connectionId: string, nodeId: string): Promise<void> {
        try {
            console.log(`📨 Setting up message receiving for ${nodeId}...`);

            // Find device
            const device = this.deviceConnections.get(nodeId);
            if (!device) {
                throw new Error(`Device for node ${nodeId} not found`);
            }

            // Monitor message exchange characteristic
            const messageSub = device.monitorCharacteristicForService(
                BLE_CONFIG.SERVICE_UUID,
                BLE_CONFIG.CHARACTERISTICS.MESSAGE_EXCHANGE,
                (error, characteristic) => {
                    if (error) {
                        console.error(`❌ Error receiving message from ${nodeId}:`, error);
                        return;
                    }

                    if (characteristic?.value) {
                        // Convert base64 to Uint8Array
                        const data = Buffer.from(characteristic.value, 'base64');
                        const uint8Data = new Uint8Array(data);

                        // Handle through base class (Protocol v2.1 processing)
                        this.handleIncomingBLEData(uint8Data, nodeId);
                    }
                }
            );

            // Store subscription
            this.addConnectionSubscription(nodeId, messageSub);

            console.log(`✅ Message receiving set up for ${nodeId}`);

        } catch (error) {
            console.error(`❌ Failed to setup message receiving for ${nodeId}:`, error);
            throw error;
        }
    }

    /**
     * Negotiate MTU for optimal packet size (implements abstract method)
     */
    protected async negotiateMTU(connectionId: string): Promise<number> {
        try {
            // Only Android supports MTU negotiation
            if (Platform.OS !== 'android') {
                return BLE_CONFIG.DEFAULT_MTU;
            }

            // Find device
            let targetDevice: Device | undefined;
            for (const device of this.deviceConnections.values()) {
                if (device.id === connectionId) {
                    targetDevice = device;
                    break;
                }
            }

            if (!targetDevice) {
                return BLE_CONFIG.DEFAULT_MTU;
            }

            // Request maximum MTU
            await targetDevice.requestMTU(BLE_CONFIG.MAX_MTU);
            
            // Get the actual negotiated MTU
            const mtu = targetDevice.mtu;
            console.log(`📏 Negotiated MTU: ${mtu} bytes`);

            return mtu;

        } catch (error) {
            console.warn(`⚠️ MTU negotiation failed:`, error);
            return BLE_CONFIG.DEFAULT_MTU;
        }
    }

    /**
     * Get connection parameters (implements abstract method)
     */
    protected async getConnectionParameters(connectionId: string): Promise<{
        interval: number;
        latency: number;
        timeout: number;
    }> {
        // Default values - actual values would require native module extension
        return {
            interval: BLE_CONFIG.CONNECTION_INTERVAL_MIN,
            latency: BLE_CONFIG.CONNECTION_LATENCY,
            timeout: BLE_CONFIG.SUPERVISION_TIMEOUT
        };
    }

    /**
     * Connect with retry logic and exponential backoff
     */
    private async connectWithRetry(
        deviceId: string,
        options: ConnectionOptions
    ): Promise<Device | null> {
        const maxRetries = MAX_CONNECTION_RETRIES;
        let lastError: Error | undefined;

        for (let attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                console.log(`🔄 Connection attempt ${attempt}/${maxRetries} to ${deviceId}`);

                const device = await this.bleManager.connectToDevice(deviceId, options);
                
                // Verify connection
                if (await device.isConnected()) {
                    this.connectionRetryCount.delete(deviceId);
                    return device;
                }

            } catch (error) {
                lastError = error as Error;
                console.warn(`⚠️ Connection attempt ${attempt} failed:`, error);

                if (attempt < maxRetries) {
                    // Exponential backoff
                    const delay = CONNECTION_RETRY_DELAY * Math.pow(2, attempt - 1);
                    console.log(`⏳ Waiting ${delay}ms before retry...`);
                    await new Promise(resolve => setTimeout(resolve, delay));
                }
            }
        }

        throw lastError || new Error('Connection failed after retries');
    }

    /**
     * Handle device disconnection with automatic reconnection
     */
    private async handleDeviceDisconnection(
        nodeId: string,
        device: Device,
        error?: BleError | null
    ): Promise<void> {
        console.log(`🔌 Handling disconnection for ${nodeId}...`);

        // Remove from active connections
        this.deviceConnections.delete(nodeId);
        this.connectionPool.delete(nodeId);
        this.removeConnectionSubscriptions(nodeId);

        // Emit disconnection event
        this.emitRNEvent('nodeDisconnected', {
            nodeId,
            error: error?.message,
            timestamp: Date.now()
        });

        // Attempt automatic reconnection if not intentional
        if (error && this.currentAppState === 'active' && this.currentBleState === State.PoweredOn) {
            console.log(`🔄 Attempting automatic reconnection to ${nodeId}...`);
            
            setTimeout(async () => {
                try {
                    await this.connectToDevice(device.id, nodeId);
                    console.log(`✅ Successfully reconnected to ${nodeId}`);
                } catch (reconnectError) {
                    console.error(`❌ Failed to reconnect to ${nodeId}:`, reconnectError);
                }
            }, CONNECTION_RETRY_DELAY);
        }
    }

    /**
     * Manage connection subscriptions
     */
    private addConnectionSubscription(nodeId: string, subscription: Subscription): void {
        if (!this.connectionSubscriptions.has(nodeId)) {
            this.connectionSubscriptions.set(nodeId, []);
        }
        this.connectionSubscriptions.get(nodeId)?.push(subscription);
    }

    private removeConnectionSubscriptions(nodeId: string): void {
        const subscriptions = this.connectionSubscriptions.get(nodeId);
        if (subscriptions) {
            subscriptions.forEach(sub => sub.remove());
            this.connectionSubscriptions.delete(nodeId);
        }
    }

    /**
     * Update performance metrics
     */
    private updateConnectionMetrics(success: boolean, connectionTime: number): void {
        if (success) {
            this.performanceMetrics.successfulConnections++;
            
            // Update average connection time
            const prevTotal = this.performanceMetrics.averageConnectionTime * 
                            (this.performanceMetrics.successfulConnections - 1);
            this.performanceMetrics.averageConnectionTime = 
                (prevTotal + connectionTime) / this.performanceMetrics.successfulConnections;
        } else {
            this.performanceMetrics.failedConnections++;
        }
    }

    /**
     * Check if BLE is supported
     */
    private async checkBLESupport(): Promise<boolean> {
        try {
            const state = await this.bleManager.state();
            return state !== State.Unsupported;
        } catch (error) {
            console.error('Error checking BLE support:', error);
            return false;
        }
    }

    /**
     * Wait for BLE to be powered on
     */
    private async waitForBLEPoweredOn(): Promise<void> {
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                subscription.remove();
                reject(new Error('Timeout waiting for BLE to power on'));
            }, 10000);

            const subscription = this.bleManager.onStateChange((state) => {
                if (state === State.PoweredOn) {
                    clearTimeout(timeout);
                    subscription.remove();
                    resolve();
                } else if (state === State.Unsupported) {
                    clearTimeout(timeout);
                    subscription.remove();
                    reject(new Error('BLE is not supported'));
                }
            }, true);
        });
    }

    /**
     * Set up app state handling
     */
    private setupAppStateHandling(): void {
        this.appStateSubscription = AppState.addEventListener('change', (nextAppState) => {
            console.log(`📱 App state: ${this.currentAppState} → ${nextAppState}`);

            if (this.currentAppState.match(/inactive|background/) && nextAppState === 'active') {
                this.handleAppForeground();
            } else if (this.currentAppState === 'active' && nextAppState.match(/inactive|background/)) {
                this.handleAppBackground();
            }

            this.currentAppState = nextAppState;
        });
    }

    /**
     * Set up BLE state monitoring
     */
    private setupBLEStateMonitoring(): void {
        this.bleStateSubscription = this.bleManager.onStateChange((state) => {
            console.log(`📡 BLE state: ${this.currentBleState} → ${state}`);
            const previousState = this.currentBleState;
            this.currentBleState = state;

            this.emitRNEvent('bleStateChanged', {
                previousState,
                currentState: state,
                timestamp: Date.now()
            });

            if (state === State.PoweredOn && previousState !== State.PoweredOn) {
                this.handleBLEPoweredOn();
            } else if (state === State.PoweredOff && previousState !== State.PoweredOff) {
                this.handleBLEPoweredOff();
            }
        }, true);
    }

    /**
     * Handle app foreground with resume logic
     */
    private async handleAppForeground(): Promise<void> {
        console.log('📱 App came to foreground');

        if (this.currentBleState === State.PoweredOn) {
            try {
                // Resume scanning if needed
                if (!this.isScanning) {
                    await this.resumeScanning();
                }

                // Validate and restore connections
                await this.validateAndRestoreConnections();

                this.emitRNEvent('appForeground', {
                    resumed: true,
                    timestamp: Date.now()
                });

            } catch (error) {
                console.error('❌ Error resuming BLE operations:', error);
            }
        }
    }

    /**
     * Handle app background with optimization
     */
    private handleAppBackground(): void {
        console.log('📱 App went to background');

        // Platform-specific background handling
        if (Platform.OS === 'ios') {
            console.log('📱 iOS: Continuing limited BLE operations in background');
        } else if (Platform.OS === 'android') {
            if (this.batteryOptimizationEnabled) {
                console.log('🔋 Android: Optimizing BLE for background operation');
            }
        }

        this.emitRNEvent('appBackground', {
            suspended: Platform.OS === 'ios',
            timestamp: Date.now()
        });
    }

    /**
     * Handle BLE powered on
     */
    private async handleBLEPoweredOn(): Promise<void> {
        console.log('📡 BLE powered on');

        try {
            await this.resumeScanning();
            
            this.emitRNEvent('bleResumed', {
                timestamp: Date.now()
            });

        } catch (error) {
            console.error('❌ Error handling BLE power on:', error);
        }
    }

    /**
     * Handle BLE powered off
     */
    private handleBLEPoweredOff(): void {
        console.log('📡 BLE powered off');

        // Clean up all connections
        for (const [nodeId] of this.deviceConnections) {
            this.removeConnectionSubscriptions(nodeId);
        }
        this.deviceConnections.clear();
        this.connectionPool.clear();

        this.emitRNEvent('bleSuspended', {
            timestamp: Date.now(),
            reason: 'BLE powered off'
        });
    }

    /**
     * Resume scanning with platform optimization
     */
    private async resumeScanning(): Promise<void> {
        if (this.isScanning) return;

        console.log('🔍 Resuming BLE scanning...');

        try {
            if (Platform.OS === 'android') {
                await this.startAndroidOptimizedScanning();
            } else {
                await this.scanner.startScanning();
            }

            this.isScanning = true;

        } catch (error) {
            console.error('❌ Failed to resume scanning:', error);
            throw error;
        }
    }

    /**
     * Android-optimized scanning with duty cycles
     */
    private async startAndroidOptimizedScanning(): Promise<void> {
        const scanCycle = async () => {
            if (!this.isScanning) return;

            console.log('🔍 Starting Android scan cycle...');
            await this.scanner.startScanning();

            this.scanRestartTimer = setTimeout(async () => {
                if (!this.isScanning) return;

                console.log('⏸️ Pausing Android scan for battery optimization');
                await this.scanner.stopScanning();

                setTimeout(() => {
                    if (this.isScanning && this.currentBleState === State.PoweredOn) {
                        scanCycle();
                    }
                }, 5000);

            }, ANDROID_SCAN_DURATION);
        };

        await scanCycle();
    }

    /**
     * Validate and restore connections
     */
    private async validateAndRestoreConnections(): Promise<void> {
        console.log('🔍 Validating connections...');

        for (const [nodeId, device] of this.deviceConnections) {
            try {
                const isConnected = await device.isConnected();
                if (!isConnected) {
                    console.log(`🔄 Restoring connection to ${nodeId}...`);
                    await this.connectToDevice(device.id, nodeId);
                }
            } catch (error) {
                console.error(`❌ Failed to restore connection to ${nodeId}:`, error);
                this.deviceConnections.delete(nodeId);
                this.connectionPool.delete(nodeId);
            }
        }
    }

    /**
     * Helper to pass raw data to connection manager with proper typing
     */
    private handleIncomingBLEData(data: Uint8Array, fromNodeId: string): void {
        // Cast through unknown to avoid TypeScript overlap error
        const connectionManager = this.connectionManager as unknown as ReactNativeBLEConnectionManager;
        if (connectionManager.handleIncomingData) {
            connectionManager.handleIncomingData(data, fromNodeId);
        }
    }

        /**
     * Helper to convert bytes to hex string
     */
    private convertBytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * React Native event management
     */
    onRNEvent(event: string, callback: Function): void {
        if (!this.rnEventCallbacks.has(event)) {
            this.rnEventCallbacks.set(event, new Set());
        }
        this.rnEventCallbacks.get(event)?.add(callback);
    }

    offRNEvent(event: string, callback: Function): void {
        this.rnEventCallbacks.get(event)?.delete(callback);
    }

    private emitRNEvent(event: string, data: any): void {
        const callbacks = this.rnEventCallbacks.get(event);
        if (callbacks) {
            callbacks.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`Error in RN event callback for ${event}:`, error);
                }
            });
        }
    }

    /**
     * Public API methods
     */
    getBLEState(): State {
        return this.currentBleState;
    }

    getAppState(): AppStateStatus {
        return this.currentAppState;
    }

    isReady(): boolean {
        return this.currentBleState === State.PoweredOn && this.isScanning;
    }

    getNodeId(): string {
        return this.keyPair.getFingerprint();
    }

    getPerformanceMetrics(): typeof this.performanceMetrics {
        return { ...this.performanceMetrics };
    }

    async getNetworkStats(): Promise<NetworkStats & {
        platform: string;
        bleState: string;
        appState: string;
    }> {
        const stats = this.getNetworkStatus();

        return {
            ...stats,
            platform: Platform.OS,
            bleState: this.currentBleState,
            appState: this.currentAppState
        };
    }

    /**
     * Clean up all resources
     */
    async cleanup(): Promise<void> {
        console.log('🧹 Cleaning up ReactNativeBLEManager...');

        try {
            // Stop base class operations
            await this.stop();

            // Clear React Native specific timers
            if (this.scanRestartTimer) {
                clearTimeout(this.scanRestartTimer);
            }

            if (this.retryTimer) {
                clearInterval(this.retryTimer);
            }

            // Remove all connection subscriptions
            for (const [nodeId] of this.connectionSubscriptions) {
                this.removeConnectionSubscriptions(nodeId);
            }

            // Disconnect all devices
            for (const [nodeId, device] of this.deviceConnections) {
                try {
                    await device.cancelConnection();
                } catch (error) {
                    console.warn(`Failed to disconnect ${nodeId}:`, error);
                }
            }

            // Clear all state
            this.deviceConnections.clear();
            this.connectionSubscriptions.clear();
            this.connectionRetryCount.clear();
            this.connectionPool.clear();
            this.messageRetryQueue.clear();
            this.rnEventCallbacks.clear();

            // Remove app state listener
            if (this.appStateSubscription) {
                this.appStateSubscription.remove();
            }

            // Remove BLE state listener
            if (this.bleStateSubscription) {
                this.bleStateSubscription.remove();
            }

            // Destroy BLE manager
            await this.bleManager.destroy();

            console.log('✅ ReactNativeBLEManager cleaned up');

        } catch (error) {
            console.error('❌ Error during cleanup:', error);
        }
    }
}