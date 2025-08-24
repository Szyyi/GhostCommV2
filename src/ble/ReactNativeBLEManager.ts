// mobile/src/ble/ReactNativeBLEManager.ts
import { BleManager, State, Subscription } from 'react-native-ble-plx';
import { Platform, PermissionsAndroid, AppState, AppStateStatus } from 'react-native';
import {
    BLEManager,
    BLEAdvertiser,
    BLEScanner,
    BLEConnectionManager,
    BLENode,
    BLEAdvertisementData,
    BLE_CONFIG,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    ConnectionState,
    BLEDiscoveryEvent,
    BLEConnectionEvent,
    BLEMessageEvent,
    IGhostKeyPair,
    MessageType,
    MessagePriority,
    NetworkStats
} from '../../core';

import { ReactNativeBLEAdvertiser } from './ReactNativeBLEAdvertiser';
import { ReactNativeBLEScanner } from './ReactNativeBLEScanner';
import { ReactNativeBLEConnectionManager } from './ReactNativeBLEConnectionManager';

/**
 * React Native BLE Manager Implementation for v2.0
 * Fully aligned with core v2.0 security architecture
 */
export class ReactNativeBLEManager extends BLEManager {
    private bleManager: BleManager;
    private rnAdvertiser: ReactNativeBLEAdvertiser;
    private rnScanner: ReactNativeBLEScanner;
    private rnConnectionManager: ReactNativeBLEConnectionManager;

    // React Native specific state
    private appStateSubscription?: any;
    private currentAppState: AppStateStatus = 'active';
    private bleStateSubscription?: Subscription;
    private currentBleState: State = State.Unknown;

    // Additional RN event callbacks
    private rnEventCallbacks: Map<string, Set<Function>> = new Map();
    getDiscoveredNodes: any;

    constructor(
        keyPair: IGhostKeyPair,
        bleManager?: BleManager
    ) {
        // Create BLE manager
        const bleMgr = bleManager || new BleManager();

        // Create platform-specific implementations
        const advertiser = new ReactNativeBLEAdvertiser(keyPair);
        const scanner = new ReactNativeBLEScanner(keyPair, bleMgr);
        const connectionManager = new ReactNativeBLEConnectionManager(keyPair, bleMgr);

        // Call parent constructor with v2.0 components
        super(keyPair, advertiser as BLEAdvertiser, scanner as unknown as BLEScanner, connectionManager as BLEConnectionManager);

        // Store React Native specific references
        this.bleManager = bleMgr;
        this.rnAdvertiser = advertiser;
        this.rnScanner = scanner;
        this.rnConnectionManager = connectionManager;

        console.log('📱 ReactNativeBLEManager v2.0 initialized');
    }

    /**
     * Initialize the React Native BLE manager
     */
    async initialize(): Promise<void> {
        try {
            console.log('🚀 Initializing ReactNativeBLEManager v2.0...');

            // Request permissions first
            await this.requestPermissions();

            // Check BLE support
            const isSupported = await this.checkBLESupport();
            if (!isSupported) {
                throw new Error('BLE is not supported on this device');
            }

            // Wait for BLE to be powered on
            await this.waitForBLEPoweredOn();

            // Set up app state handling
            this.setupAppStateHandling();

            // Set up BLE state monitoring
            this.setupBLEStateMonitoring();

            // Start the v2.0 mesh network
            await this.start();

            console.log('✅ ReactNativeBLEManager v2.0 initialized successfully');

            this.emitRNEvent('initialized', {
                nodeId: this.keyPair.getFingerprint(),
                platform: Platform.OS,
                bleState: this.currentBleState,
                version: 2
            });

        } catch (error) {
            console.error('❌ Failed to initialize ReactNativeBLEManager:', error);
            this.emitRNEvent('error', {
                type: 'initialization',
                error: error instanceof Error ? error.message : String(error)
            });
            throw error;
        }
    }

    /**
     * Request necessary permissions for BLE on Android
     */
    private async requestPermissions(): Promise<void> {
        if (Platform.OS === 'android') {
            try {
                console.log('📱 Requesting Android BLE permissions...');

                if (Platform.Version >= 31) {
                    // Android 12+
                    const permissions = [
                        PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
                        PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
                        PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
                        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
                    ];

                    const results = await PermissionsAndroid.requestMultiple(permissions);

                    for (const [permission, result] of Object.entries(results)) {
                        if (result !== PermissionsAndroid.RESULTS.GRANTED) {
                            throw new Error(`Permission ${permission} not granted`);
                        }
                    }
                } else {
                    // Android < 12
                    const permissions = [
                        PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
                    ];

                    const results = await PermissionsAndroid.requestMultiple(permissions);

                    for (const [permission, result] of Object.entries(results)) {
                        if (result !== PermissionsAndroid.RESULTS.GRANTED) {
                            throw new Error(`Permission ${permission} not granted`);
                        }
                    }
                }

                console.log('✅ Android BLE permissions granted');
            } catch (error) {
                console.error('❌ Failed to request Android permissions:', error);
                throw error;
            }
        }
        // iOS handles permissions through Info.plist
    }

    /**
     * Check if BLE is supported on this device
     */
    private async checkBLESupport(): Promise<boolean> {
        try {
            const state = await this.bleManager.state();
            return state !== State.Unsupported;
        } catch (error) {
            console.error('❌ Error checking BLE support:', error);
            return false;
        }
    }

    /**
     * Wait for BLE to be powered on
     */
    private async waitForBLEPoweredOn(): Promise<void> {
        return new Promise((resolve, reject) => {
            const checkState = async () => {
                const state = await this.bleManager.state();
                if (state === State.PoweredOn) {
                    resolve();
                } else if (state === State.Unsupported) {
                    reject(new Error('BLE is not supported'));
                }
            };

            checkState();

            const subscription = this.bleManager.onStateChange((state) => {
                if (state === State.PoweredOn) {
                    subscription.remove();
                    resolve();
                } else if (state === State.Unsupported) {
                    subscription.remove();
                    reject(new Error('BLE is not supported'));
                }
            }, true);

            setTimeout(() => {
                subscription.remove();
                reject(new Error('Timeout waiting for BLE to power on'));
            }, 10000);
        });
    }

    /**
     * Set up app state handling for background/foreground transitions
     */
    private setupAppStateHandling(): void {
        this.appStateSubscription = AppState.addEventListener('change', (nextAppState) => {
            console.log(`📱 App state changed: ${this.currentAppState} -> ${nextAppState}`);

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
            console.log(`📱 BLE state changed: ${this.currentBleState} -> ${state}`);
            const previousState = this.currentBleState;
            this.currentBleState = state;

            this.emitRNEvent('bleStateChanged', {
                previousState,
                currentState: state
            });

            if (state === State.PoweredOn) {
                this.handleBLEPoweredOn();
            } else if (state === State.PoweredOff) {
                this.handleBLEPoweredOff();
            }
        }, true);
    }

    /**
     * Handle app coming to foreground
     */
    private async handleAppForeground(): Promise<void> {
        console.log('📱 App came to foreground, resuming BLE operations...');

        if (this.currentBleState === State.PoweredOn) {
            try {
                // Resume scanning
                await this.rnScanner.resumeScanning();

                // Validate connections
                await this.rnConnectionManager.validateConnections();

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
     * Handle app going to background
     */
    private handleAppBackground(): void {
        console.log('📱 App went to background, optimizing BLE operations...');

        this.emitRNEvent('appBackground', {
            suspended: false,
            timestamp: Date.now()
        });
    }

    /**
     * Handle BLE powered on
     */
    private async handleBLEPoweredOn(): Promise<void> {
        console.log('📱 BLE powered on, resuming operations...');

        try {
            await this.rnScanner.resumeScanning();
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
        console.log('📱 BLE powered off, suspending operations...');

        try {
            this.rnScanner.pauseScanning();
        } catch (error) {
            console.error('❌ Error pausing scanner:', error);
        }

        this.emitRNEvent('bleSuspended', {
            timestamp: Date.now(),
            reason: 'BLE powered off'
        });
    }

    /**
     * Get network statistics for React Native UI
     */
    async getNetworkStats(): Promise<NetworkStats & {
        platform: string;
        bleState: string;
    }> {
        const stats = this.getNetworkStatus();

        return {
            ...stats,
            platform: Platform.OS,
            bleState: this.currentBleState
        };
    }

    /**
     * Connect to a specific node
     */
    async connectToNode(nodeId: string): Promise<void> {
        try {
            const nodes = this.getDiscoveredNodes();
            const node = nodes.find((n: { id: string; }) => n.id === nodeId);

            if (!node) {
                throw new Error(`Node ${nodeId} not found`);
            }

            // Convert to v2.0 BLENode structure
            const bleNode: BLENode = {
                id: node.id,
                name: node.name || node.id,
                identityKey: node.identityKey || new Uint8Array(32),
                encryptionKey: node.encryptionKey || new Uint8Array(32),
                isConnected: false,
                lastSeen: Date.now(),
                firstSeen: node.firstSeen || Date.now(),
                rssi: node.rssi || -100,
                verificationStatus: VerificationStatus.UNVERIFIED,
                trustScore: 0,
                protocolVersion: 2,
                capabilities: [NodeCapability.RELAY],
                deviceType: DeviceType.PHONE,
                supportedAlgorithms: [],
                isRelay: true,
                bluetoothAddress: node.id,
                batteryLevel: undefined,
                lastRSSI: 0,
                canSee: undefined
            };

            await this.connectionManager.connectToNode(bleNode, node.id);

            this.emitRNEvent('nodeConnected', {
                nodeId,
                timestamp: Date.now()
            });

        } catch (error) {
            console.error(`❌ Failed to connect to node ${nodeId}:`, error);
            this.emitRNEvent('connectionError', {
                nodeId,
                error: error instanceof Error ? error.message : String(error)
            });
            throw error;
        }
    }

    /**
     * Disconnect from a specific node
     */
    async disconnectFromNode(nodeId: string): Promise<void> {
        try {
            await this.connectionManager.disconnectFromNode(nodeId);

            this.emitRNEvent('nodeDisconnected', {
                nodeId,
                timestamp: Date.now()
            });

        } catch (error) {
            console.error(`❌ Failed to disconnect from node ${nodeId}:`, error);
            throw error;
        }
    }

    /**
     * React Native specific event emitter
     */
    onRNEvent(event: string, callback: Function): void {
        if (!this.rnEventCallbacks.has(event)) {
            this.rnEventCallbacks.set(event, new Set());
        }
        this.rnEventCallbacks.get(event)?.add(callback);
    }

    /**
     * Remove React Native event listener
     */
    offRNEvent(event: string, callback: Function): void {
        this.rnEventCallbacks.get(event)?.delete(callback);
    }

    /**
     * Emit a React Native specific event
     */
    private emitRNEvent(event: string, data: any): void {
        const callbacks = this.rnEventCallbacks.get(event);
        if (callbacks) {
            callbacks.forEach(callback => {
                try {
                    callback(data);
                } catch (error) {
                    console.error(`❌ Error in RN event callback for ${event}:`, error);
                }
            });
        }
    }

    /**
     * Get the current BLE state
     */
    getBLEState(): State {
        return this.currentBleState;
    }

    /**
     * Check if manager is ready
     */
    isReady(): boolean {
        return this.currentBleState === State.PoweredOn;
    }

    /**
     * Get the node ID (fingerprint)
     */
    getNodeId(): string {
        return this.keyPair.getFingerprint();
    }

    /**
     * Clean up resources
     */
    async cleanup(): Promise<void> {
        console.log('🧹 Cleaning up ReactNativeBLEManager...');

        try {
            await this.stop();

            if (this.appStateSubscription) {
                this.appStateSubscription.remove();
            }

            if (this.bleStateSubscription) {
                this.bleStateSubscription.remove();
            }

            this.rnEventCallbacks.clear();

            await this.rnAdvertiser.destroy();
            await this.bleManager.destroy();

            console.log('✅ ReactNativeBLEManager cleaned up');

        } catch (error) {
            console.error('❌ Error during cleanup:', error);
        }
    }
}