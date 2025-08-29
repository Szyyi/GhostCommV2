// mobile/src/ble/ReactNativeBLEManager.ts
import { BleManager, State, Subscription } from 'react-native-ble-plx';
import { Platform, PermissionsAndroid, AppState, AppStateStatus } from 'react-native';
import {
    BLEManager,
    BLENode,
    BLE_CONFIG,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    IGhostKeyPair,
    MessagePriority,
    NetworkStats
} from '../../core';

import { ReactNativeBLEAdvertiser } from './ReactNativeBLEAdvertiser';
import { ReactNativeBLEScanner } from './ReactNativeBLEScanner';
import { ReactNativeBLEConnectionManager } from './ReactNativeBLEConnectionManager';

/**
 * React Native BLE Manager Implementation
 * 
 * This class extends the base BLEManager and provides React Native specific
 * functionality like permission handling, app state management, and platform-specific
 * BLE state monitoring. All Protocol v2 security is handled by the base class.
 */
export class ReactNativeBLEManager extends BLEManager {
    private bleManager: BleManager;
    
    // React Native specific state
    private appStateSubscription?: any;
    private currentAppState: AppStateStatus = 'active';
    private bleStateSubscription?: Subscription;
    private currentBleState: State = State.Unknown;
    
    // Additional RN event callbacks
    private rnEventCallbacks: Map<string, Set<Function>> = new Map();

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

        // Call parent constructor
        super(keyPair, advertiser, scanner, connectionManager);

        // Store React Native specific reference
        this.bleManager = bleMgr;

        console.log('ReactNativeBLEManager initialized with Protocol v2');
    }

    /**
     * Initialize the React Native BLE manager
     */
    async initialize(): Promise<void> {
        try {
            console.log('Initializing ReactNativeBLEManager...');

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

            // Start the mesh network (base class handles Protocol v2)
            await this.start();

            console.log('ReactNativeBLEManager initialized successfully');

            this.emitRNEvent('initialized', {
                nodeId: this.keyPair.getFingerprint(),
                platform: Platform.OS,
                bleState: this.currentBleState,
                protocolVersion: 2
            });

        } catch (error) {
            console.error('Failed to initialize ReactNativeBLEManager:', error);
            this.emitRNEvent('error', {
                type: 'initialization',
                error: error instanceof Error ? error.message : String(error)
            });
            throw error;
        }
    }

    /**
     * Request necessary permissions for BLE
     */
    private async requestPermissions(): Promise<void> {
        if (Platform.OS === 'android') {
            try {
                console.log('Requesting Android BLE permissions...');

                const permissions = Platform.Version >= 31 ? [
                    // Android 12+
                    PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
                    PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
                    PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
                    PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
                ] : [
                    // Android < 12
                    PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION
                ];

                const results = await PermissionsAndroid.requestMultiple(permissions);

                for (const [permission, result] of Object.entries(results)) {
                    if (result !== PermissionsAndroid.RESULTS.GRANTED) {
                        throw new Error(`Permission ${permission} not granted`);
                    }
                }

                console.log('Android BLE permissions granted');
            } catch (error) {
                console.error('Failed to request Android permissions:', error);
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
            console.error('Error checking BLE support:', error);
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

            // Check initial state
            checkState();

            // Subscribe to state changes
            const subscription = this.bleManager.onStateChange((state) => {
                if (state === State.PoweredOn) {
                    subscription.remove();
                    resolve();
                } else if (state === State.Unsupported) {
                    subscription.remove();
                    reject(new Error('BLE is not supported'));
                }
            }, true);

            // Timeout after 10 seconds
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
            console.log(`App state changed: ${this.currentAppState} -> ${nextAppState}`);

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
            console.log(`BLE state changed: ${this.currentBleState} -> ${state}`);
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
        console.log('App came to foreground, resuming BLE operations...');

        if (this.currentBleState === State.PoweredOn) {
            try {
                // Resume scanning through base class
                if (!this.getScanningStatus().isScanning) {
                    await this.scanner.startScanning();
                }

                // Validate connections
                const connectionManager = this.connectionManager as ReactNativeBLEConnectionManager;
                await connectionManager.validateConnections();

                this.emitRNEvent('appForeground', {
                    resumed: true,
                    timestamp: Date.now()
                });
            } catch (error) {
                console.error('Error resuming BLE operations:', error);
            }
        }
    }

    /**
     * Handle app going to background
     */
    private handleAppBackground(): void {
        console.log('App went to background');

        // On iOS, we might want to pause scanning to save battery
        // On Android, we can continue scanning in background if permitted

        this.emitRNEvent('appBackground', {
            suspended: Platform.OS === 'ios',
            timestamp: Date.now()
        });
    }

    /**
     * Handle BLE powered on
     */
    private async handleBLEPoweredOn(): Promise<void> {
        console.log('BLE powered on, resuming operations...');

        try {
            // The base class will handle resuming operations
            if (!this.getScanningStatus().isScanning) {
                await this.scanner.startScanning();
            }
            
            this.emitRNEvent('bleResumed', {
                timestamp: Date.now()
            });
        } catch (error) {
            console.error('Error handling BLE power on:', error);
        }
    }

    /**
     * Handle BLE powered off
     */
    private handleBLEPoweredOff(): void {
        console.log('BLE powered off, suspending operations...');

        // The base class will handle stopping operations
        this.emitRNEvent('bleSuspended', {
            timestamp: Date.now(),
            reason: 'BLE powered off'
        });
    }

    /**
     * Get scanning status with React Native specific info
     */
    getScanningStatus(): any {
        const baseStatus = this.scanner.getScanningStatus();
        return {
            ...baseStatus,
            bleState: this.currentBleState,
            appState: this.currentAppState
        };
    }

    /**
     * Get network statistics with React Native specific info
     */
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
     * Connect to a specific node by ID
     */
    async connectToNode(nodeId: string): Promise<void> {
        try {
            const nodes = this.scanner.getDiscoveredNodes();
            const node = nodes.find(n => n.id === nodeId);

            if (!node) {
                throw new Error(`Node ${nodeId} not found`);
            }

            // The base connection manager handles Protocol v2
            await this.connectionManager.connectToNode(node, node.bluetoothAddress || nodeId);

            this.emitRNEvent('nodeConnected', {
                nodeId,
                timestamp: Date.now()
            });

        } catch (error) {
            console.error(`Failed to connect to node ${nodeId}:`, error);
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
            console.error(`Failed to disconnect from node ${nodeId}:`, error);
            throw error;
        }
    }

    /**
     * Send a message (convenience method)
     */
    async sendSecureMessage(
        recipientId: string,
        content: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): Promise<string> {
        // The base class handles all Protocol v2 security
        return this.sendMessage(recipientId, content, priority);
    }

    /**
     * Broadcast a message (convenience method)
     */
    async broadcastSecureMessage(
        content: string,
        priority: MessagePriority = MessagePriority.NORMAL
    ): Promise<string> {
        // The base class handles all Protocol v2 security
        return this.broadcastMessage(content, priority);
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
                    console.error(`Error in RN event callback for ${event}:`, error);
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
        return this.currentBleState === State.PoweredOn && 
               this.getScanningStatus().isScanning;
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
        console.log('Cleaning up ReactNativeBLEManager...');

        try {
            // Stop the base manager
            await this.stop();

            // Clean up React Native specific subscriptions
            if (this.appStateSubscription) {
                this.appStateSubscription.remove();
            }

            if (this.bleStateSubscription) {
                this.bleStateSubscription.remove();
            }

            // Clear callbacks
            this.rnEventCallbacks.clear();

            // Destroy BLE manager
            await this.bleManager.destroy();

            console.log('ReactNativeBLEManager cleaned up');

        } catch (error) {
            console.error('Error during cleanup:', error);
        }
    }
}