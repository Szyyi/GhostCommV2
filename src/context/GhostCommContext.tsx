// mobile/src/context/GhostCommContext.tsx
import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { ReactNativeBLEManager } from '../ble/ReactNativeBLEManager';
import {
    GhostKeyPair,
    BLENode,
    BLEConnectionEvent,
    BLEMessageEvent,
    BLEDiscoveryEvent,
    ConnectionState,
    NodeCapability,
    DeviceType,
    VerificationStatus,
    IGhostKeyPair,
    PlaintextMessage,
    MessageType,
    MessagePriority,
    NetworkStats
} from '../../core';
import { debug } from '../utils/debug';
import { SimulatedNodeManager, simulationManager } from '../testing/SimulatedNodeManager';

// System log for UI display
export interface SystemLog {
    id: string;
    timestamp: number;
    level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'DEBUG';
    message: string;
    data?: any;
}

// Stored message for UI
export interface StoredMessage {
    id: string;
    content: string;
    type: MessageType;
    status: 'QUEUED' | 'TRANSMITTING' | 'SENT' | 'DELIVERED' | 'FAILED' | 'TIMEOUT';
    timestamp: number;
    isIncoming: boolean;
    senderFingerprint?: string;
    recipientFingerprint?: string;
    attempts?: number;
    lastAttempt?: number;
}

interface GhostCommContextType {
    // Core objects
    bleManager: ReactNativeBLEManager | null;
    keyPair: IGhostKeyPair | null;
    executeCommand: (command: string) => Promise<string>;

    // State
    messages: StoredMessage[];
    discoveredNodes: Map<string, BLENode>;
    connectedNodes: Map<string, BLENode>;
    networkStats: NetworkStats;
    systemLogs: SystemLog[];
    isScanning: boolean;
    isAdvertising: boolean;
    isInitialized: boolean;

    // Actions
    sendMessage: (content: string, recipientId?: string, type?: MessageType) => Promise<void>;
    clearMessages: () => Promise<void>;
    clearLogs: () => void;
    startScanning: () => Promise<void>;
    stopScanning: () => Promise<void>;
    startAdvertising: () => Promise<void>;
    stopAdvertising: () => Promise<void>;
    connectToNode: (nodeId: string) => Promise<void>;
    disconnectFromNode: (nodeId: string) => Promise<void>;
    refreshNetwork: () => Promise<void>;
    addSystemLog: (level: SystemLog['level'], message: string, data?: any) => void;

    // Network mesh methods (for NetworkScreen)
    getNodeRoutingTable?: (nodeId: string) => Map<string, string> | undefined;
    getMessageFlow?: () => Map<string, Map<string, number>>;
}

const GhostCommContext = createContext<GhostCommContextType | undefined>(undefined);

// Create default/stub context value for development reloads
const createStubContext = (): GhostCommContextType => ({
    bleManager: null,
    keyPair: null,
    messages: [],
    discoveredNodes: new Map(),
    connectedNodes: new Map(),
    networkStats: {
        totalNodes: 0,
        activeNodes: 0,
        trustedNodes: 0,
        blockedNodes: 0,
        totalConnections: 0,
        messagesSent: 0,
        messagesReceived: 0,
        messagesRelayed: 0,
        messagesDropped: 0,
        averageHopCount: 0,
        averageLatency: 0,
        deliverySuccessRate: 1,
        networkDensity: 0,
        networkReachability: 0,
        bytesTransmitted: 0,
        bytesReceived: 0,
        averageThroughput: 0,
        uptime: Date.now(),
        lastUpdated: Date.now()
    },
    systemLogs: [],
    isScanning: false,
    isAdvertising: false,
    isInitialized: false,
    sendMessage: async () => { console.warn('Context not ready'); },
    clearMessages: async () => { console.warn('Context not ready'); },
    clearLogs: () => { console.warn('Context not ready'); },
    startScanning: async () => { console.warn('Context not ready'); },
    stopScanning: async () => { console.warn('Context not ready'); },
    startAdvertising: async () => { console.warn('Context not ready'); },
    stopAdvertising: async () => { console.warn('Context not ready'); },
    connectToNode: async () => { console.warn('Context not ready'); },
    disconnectFromNode: async () => { console.warn('Context not ready'); },
    refreshNetwork: async () => { console.warn('Context not ready'); },
    addSystemLog: () => { console.warn('Context not ready'); },
    executeCommand: async () => 'Context not ready',
    getNodeRoutingTable: () => undefined,
    getMessageFlow: () => new Map()
});

export const useGhostComm = () => {
    const context = useContext(GhostCommContext);
    
    if (!context) {
        // During development hot reloads, provide safe fallback
        if (__DEV__) {
            console.warn('useGhostComm called outside provider, returning stub');
            return createStubContext();
        }
        throw new Error('useGhostComm must be used within GhostCommProvider');
    }
    
    return context;
};

const STORAGE_KEYS = {
    MESSAGES: '@ghostcomm_messages',
    NETWORK_STATS: '@ghostcomm_network_stats',
    SYSTEM_LOGS: '@ghostcomm_system_logs',
    KEYPAIR: '@ghostcomm_keypair',
    ALIAS: '@ghostcomm_alias',
};

export const GhostCommProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [isContextReady, setIsContextReady] = useState(false);
    const [bleManager, setBleManager] = useState<ReactNativeBLEManager | null>(null);
    const [keyPair, setKeyPair] = useState<IGhostKeyPair | null>(null);
    const [messages, setMessages] = useState<StoredMessage[]>([]);
    const [discoveredNodes, setDiscoveredNodes] = useState<Map<string, BLENode>>(new Map());
    const [connectedNodes, setConnectedNodes] = useState<Map<string, BLENode>>(new Map());
    const [systemLogs, setSystemLogs] = useState<SystemLog[]>([]);
    const [isInitialized, setIsInitialized] = useState(false);
    const [isScanning, setIsScanning] = useState(false);
    const [isAdvertising, setIsAdvertising] = useState(false);
    const [alias, setAlias] = useState('anonymous');

    // Track message flows between nodes
    const messageFlowsRef = useRef<Map<string, Map<string, number>>>(new Map());

    // Track routing tables for mesh network
    const routingTablesRef = useRef<Map<string, Map<string, string>>>(new Map());

    // Use ref to avoid stale closure issues
    const scanSubscriptionRef = useRef<any>(null);

    const [networkStats, setNetworkStats] = useState<NetworkStats>({
        totalNodes: 0,
        activeNodes: 0,
        trustedNodes: 0,
        blockedNodes: 0,
        totalConnections: 0,
        messagesSent: 0,
        messagesReceived: 0,
        messagesRelayed: 0,
        messagesDropped: 0,
        averageHopCount: 0,
        averageLatency: 0,
        deliverySuccessRate: 1,
        networkDensity: 0,
        networkReachability: 0,
        bytesTransmitted: 0,
        bytesReceived: 0,
        averageThroughput: 0,
        uptime: Date.now(),
        lastUpdated: Date.now()
    });

    const addSystemLog = useCallback((
        level: SystemLog['level'],
        message: string,
        data?: any
    ) => {
        const log: SystemLog = {
            id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: Date.now(),
            level,
            message,
            data,
        };

        setSystemLogs(prev => {
            const updated = [...prev, log];
            if (updated.length > 100) {
                return updated.slice(-100);
            }
            return updated;
        });

        debug.info(`[${level}] ${message}`, data);
    }, []);

    // Event handlers
    const handleNodeDiscovered = useCallback((node: BLENode) => {
        setDiscoveredNodes(prev => {
            const updated = new Map(prev);
            updated.set(node.id, node);
            return updated;
        });

        setNetworkStats(prev => ({
            ...prev,
            totalNodes: prev.totalNodes + 1,
            lastUpdated: Date.now()
        }));

        addSystemLog('INFO', `Discovered node: ${node.id.substring(0, 8)}...`);
    }, [addSystemLog]);

    const handleNodeConnected = useCallback((nodeId: string) => {
        const node = discoveredNodes.get(nodeId);
        if (node) {
            setConnectedNodes(prev => {
                const updated = new Map(prev);
                updated.set(nodeId, node);
                return updated;
            });

            setNetworkStats(prev => ({
                ...prev,
                activeNodes: prev.activeNodes + 1,
                lastUpdated: Date.now()
            }));

            addSystemLog('SUCCESS', `Connected to ${nodeId.substring(0, 8)}...`);
        }
    }, [discoveredNodes, addSystemLog]);

    const handleNodeDisconnected = useCallback((nodeId: string) => {
        setConnectedNodes(prev => {
            const updated = new Map(prev);
            updated.delete(nodeId);
            return updated;
        });

        setNetworkStats(prev => ({
            ...prev,
            activeNodes: Math.max(0, prev.activeNodes - 1),
            lastUpdated: Date.now()
        }));

        addSystemLog('WARN', `Disconnected from ${nodeId.substring(0, 8)}...`);
    }, [addSystemLog]);

    const handleMessageReceived = useCallback((message: any, fromNodeId?: string) => {
        const newMessage: StoredMessage = {
            id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            content: message.payload || message.content || '[Empty message]',
            type: message.type || MessageType.DIRECT,
            timestamp: Date.now(),
            status: 'DELIVERED',
            isIncoming: true,
            senderFingerprint: fromNodeId,
            recipientFingerprint: keyPair?.getFingerprint(),
        };

        setMessages(prev => [...prev, newMessage]);

        // Track message flow
        if (fromNodeId) {
            const flows = messageFlowsRef.current;
            if (!flows.has(fromNodeId)) {
                flows.set(fromNodeId, new Map());
            }
            const nodeFlow = flows.get(fromNodeId)!;
            const currentCount = nodeFlow.get('received') || 0;
            nodeFlow.set('received', currentCount + 1);
        }

        setNetworkStats(prev => ({
            ...prev,
            messagesReceived: prev.messagesReceived + 1,
            bytesReceived: prev.bytesReceived + (newMessage.content?.length || 0),
            lastUpdated: Date.now()
        }));

        addSystemLog('SUCCESS', `Message from ${fromNodeId?.substring(0, 8) || 'unknown'}`);
    }, [keyPair, addSystemLog]);

    const handleMessageSent = useCallback((messageId: string) => {
        setMessages(prev =>
            prev.map(msg =>
                msg.id === messageId ? { ...msg, status: 'SENT' } : msg
            )
        );
    }, []);

    const handleMessageFailed = useCallback((messageId: string) => {
        setMessages(prev =>
            prev.map(msg =>
                msg.id === messageId ? { ...msg, status: 'FAILED' } : msg
            )
        );

        setNetworkStats(prev => ({
            ...prev,
            messagesDropped: prev.messagesDropped + 1,
            lastUpdated: Date.now()
        }));
    }, []);

    const handleBLEEvent = useCallback((event: BLEConnectionEvent | BLEMessageEvent | BLEDiscoveryEvent) => {
        switch (event.type) {
            case 'node_discovered':
                const discEvent = event as BLEDiscoveryEvent;
                handleNodeDiscovered(discEvent.node);
                break;

            case 'connected':
                const connEvent = event as BLEConnectionEvent;
                handleNodeConnected(connEvent.nodeId);
                break;

            case 'disconnected':
                const disconnEvent = event as BLEConnectionEvent;
                handleNodeDisconnected(disconnEvent.nodeId);
                break;

            case 'message_received':
                const msgEvent = event as BLEMessageEvent;
                handleMessageReceived(msgEvent.message, msgEvent.fromNodeId);
                break;

            case 'message_sent':
                const sentEvent = event as BLEMessageEvent;
                handleMessageSent(sentEvent.message.messageId);
                break;

            case 'message_failed':
                const failEvent = event as BLEMessageEvent;
                handleMessageFailed(failEvent.message.messageId);
                break;
        }
    }, [handleNodeDiscovered, handleNodeConnected, handleNodeDisconnected, handleMessageReceived, handleMessageSent, handleMessageFailed]);

    // Load stored data
    const loadStoredData = useCallback(async () => {
        try {
            const [storedMessages, storedStats, storedLogs] = await Promise.all([
                AsyncStorage.getItem(STORAGE_KEYS.MESSAGES),
                AsyncStorage.getItem(STORAGE_KEYS.NETWORK_STATS),
                AsyncStorage.getItem(STORAGE_KEYS.SYSTEM_LOGS),
            ]);

            if (storedMessages) {
                const msgs = JSON.parse(storedMessages);
                setMessages(msgs);
                addSystemLog('INFO', `Loaded ${msgs.length} messages`);
            }

            if (storedStats) {
                setNetworkStats(JSON.parse(storedStats));
            }

            if (storedLogs) {
                setSystemLogs(JSON.parse(storedLogs).slice(-50));
            }
        } catch (error) {
            addSystemLog('WARN', 'Failed to load some data', error);
        }
    }, [addSystemLog]);

    // Action implementations
    const sendMessage = useCallback(async (
        content: string,
        recipientId?: string,
        type: MessageType = MessageType.DIRECT
    ) => {
        if (!bleManager || !keyPair) {
            throw new Error('BLE Manager not initialized');
        }

        const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        const newMessage: StoredMessage = {
            id: messageId,
            content,
            type,
            timestamp: Date.now(),
            status: 'QUEUED',
            isIncoming: false,
            senderFingerprint: keyPair.getFingerprint(),
            recipientFingerprint: recipientId,
            attempts: 0,
            lastAttempt: Date.now(),
        };

        setMessages(prev => [...prev, newMessage]);

        // Track message flow
        if (recipientId) {
            const flows = messageFlowsRef.current;
            if (!flows.has(recipientId)) {
                flows.set(recipientId, new Map());
            }
            const nodeFlow = flows.get(recipientId)!;
            const currentCount = nodeFlow.get('sent') || 0;
            nodeFlow.set('sent', currentCount + 1);
        }

        try {
            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'TRANSMITTING' } : msg
                )
            );

            let bleMessageId: string;
            if (type === MessageType.BROADCAST) {
                bleMessageId = await bleManager.broadcastMessage(content, MessagePriority.NORMAL);
            } else if (recipientId) {
                bleMessageId = await bleManager.sendMessage(recipientId, content, MessagePriority.NORMAL);
            } else {
                throw new Error('Recipient required for direct message');
            }

            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'SENT' } : msg
                )
            );

            setNetworkStats(prev => ({
                ...prev,
                messagesSent: prev.messagesSent + 1,
                bytesTransmitted: prev.bytesTransmitted + content.length,
                lastUpdated: Date.now()
            }));

        } catch (error) {
            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'FAILED' } : msg
                )
            );

            setNetworkStats(prev => ({
                ...prev,
                messagesDropped: prev.messagesDropped + 1,
                lastUpdated: Date.now()
            }));

            throw error;
        }
    }, [bleManager, keyPair]);

    const clearMessages = useCallback(async () => {
        setMessages([]);
        await AsyncStorage.removeItem(STORAGE_KEYS.MESSAGES);
        addSystemLog('INFO', 'Messages cleared');
    }, [addSystemLog]);

    const clearLogs = useCallback(() => {
        setSystemLogs([]);
        AsyncStorage.removeItem(STORAGE_KEYS.SYSTEM_LOGS).catch(console.error);
    }, []);

    const startScanning = useCallback(async () => {
        if (!bleManager || isScanning) return;
        try {
            // Clean up any existing subscription properly
            if (scanSubscriptionRef.current) {
                try {
                    if (typeof scanSubscriptionRef.current.remove === 'function') {
                        scanSubscriptionRef.current.remove();
                    } else if (typeof scanSubscriptionRef.current.unsubscribe === 'function') {
                        scanSubscriptionRef.current.unsubscribe();
                    }
                } catch (e) {
                    console.warn('Failed to clean up previous scan subscription:', e);
                }
                scanSubscriptionRef.current = null;
            }

            const subscription = await bleManager.start();
            scanSubscriptionRef.current = subscription;
            setIsScanning(true);
            addSystemLog('SUCCESS', 'Scanning started');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to start scanning', error);
        }
    }, [bleManager, isScanning, addSystemLog]);

    const stopScanning = useCallback(async () => {
        if (!bleManager || !isScanning) return;
        try {
            // Clean up subscription properly
            if (scanSubscriptionRef.current) {
                try {
                    if (typeof scanSubscriptionRef.current.remove === 'function') {
                        scanSubscriptionRef.current.remove();
                    } else if (typeof scanSubscriptionRef.current.unsubscribe === 'function') {
                        scanSubscriptionRef.current.unsubscribe();
                    }
                } catch (e) {
                    console.warn('Failed to clean up scan subscription:', e);
                }
                scanSubscriptionRef.current = null;
            }

            await bleManager.stop();
            setIsScanning(false);
            addSystemLog('INFO', 'Scanning stopped');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to stop scanning', error);
        }
    }, [bleManager, isScanning, addSystemLog]);

    const startAdvertising = useCallback(async () => {
        if (!bleManager || isAdvertising) return;
        try {
            await bleManager.start();
            setIsAdvertising(true);
            addSystemLog('SUCCESS', 'Advertising started');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to start advertising', error);
        }
    }, [bleManager, isAdvertising, addSystemLog]);

    const stopAdvertising = useCallback(async () => {
        if (!bleManager || !isAdvertising) return;
        try {
            await bleManager.stop();
            setIsAdvertising(false);
            addSystemLog('INFO', 'Advertising stopped');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to stop advertising', error);
        }
    }, [bleManager, isAdvertising, addSystemLog]);

        const connectToNode = useCallback(async (nodeId: string) => {
        // For simulated nodes, just update the state
        if (nodeId.startsWith('SIM_') || nodeId.startsWith('ECHO_') || nodeId.startsWith('PATROL_') || nodeId.startsWith('SQUAD_')) {
            const node = discoveredNodes.get(nodeId);
            if (node) {
                node.isConnected = true;
                handleNodeConnected(nodeId);
            }
            return;
        }
        
        // For real BLE nodes
        if (!bleManager) throw new Error('BLE not initialized');
        await bleManager.connectToNode(nodeId);
    }, [bleManager, discoveredNodes, handleNodeConnected]);

    const disconnectFromNode = useCallback(async (nodeId: string) => {
        if (!bleManager) throw new Error('BLE not initialized');
        await bleManager.disconnectFromNode(nodeId);
    }, [bleManager]);

    const refreshNetwork = useCallback(async () => {
        addSystemLog('INFO', 'Refreshing network...');
        setDiscoveredNodes(new Map());
        setConnectedNodes(new Map());

        if (bleManager && isScanning) {
            await stopScanning();
            await startScanning();
        }
    }, [bleManager, isScanning, stopScanning, startScanning, addSystemLog]);

    // Network mesh methods
    const getNodeRoutingTable = useCallback((nodeId: string): Map<string, string> | undefined => {
        return routingTablesRef.current.get(nodeId);
    }, []);

    const getMessageFlow = useCallback((): Map<string, Map<string, number>> => {
        return new Map(messageFlowsRef.current);
    }, []);

    // Command execution implementation
    // Command execution implementation
    const executeCommand = useCallback(async (command: string): Promise<string> => {
    const parts = command.trim().split(/\s+/);
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1);

    try {
        switch (cmd) {
            case 'help':
            case '?':
                return `
NETWORK ─────────────────────────────────
  scan                Start BLE scanning
  stop                Stop scanning/advertising  
  beacon              Start advertising
  nodes               List discovered nodes
  connect <id>        Connect to node
  disconnect <id>     Disconnect from node
  refresh             Refresh network

MESSAGING ───────────────────────────────
  send <msg>          Broadcast message
  dm <id> <msg>       Direct message to node
  messages            Show message history
  clear-messages      Clear all messages

SIMULATION ──────────────────────────────
  simulate <n>        Create n simulated nodes
  squad <size>        Deploy tactical squad
  base                Create base network
  convoy <size>       Deploy convoy formation
  echo                Create echo responder
  emergency           Activate emergency beacon
  loopback <msg>      Test with loopback
  stress <n> <m>      Stress test (n nodes, m msgs)
  scenario <type>     Run preset scenarios
  fragment            Simulate network split

SYSTEM ──────────────────────────────────
  status              Show system status
  stats               Network statistics
  logs                Show recent logs
  clear-logs          Clear system logs
  identity            Show node identity
  alias <name>        Set node alias
  export              Export keypair
  ping <id>           Ping a node
  test                Run diagnostics
  mesh                Show mesh topology
  clear               Clear terminal

Type 'help' or '?' for this guide`;

            case 'simulate':
            case 'sim':
                const simCount = parseInt(args[0]) || 1;
                const simNodes = [];
                
                for (let i = 0; i < simCount; i++) {
                    const node = simulationManager.createSimulatedNode({
                        profile: {
                            type: 'patrol',
                            movement: 'mobile',
                            responsePattern: 'tactical',
                            batteryDrain: 0.1
                        },
                        autoRespond: true
                    });
                    simNodes.push(node);
                    handleNodeDiscovered(node);
                }
                
                return `✓ Deployed ${simCount} tactical node(s):\n${simNodes.map(n => {
                    const signal = n.rssi > -60 ? 'STRONG' : n.rssi > -75 ? 'MEDIUM' : 'WEAK';
                    return `  • ${n.name} [${signal}] ${n.rssi.toFixed(0)}dBm`;
                }).join('\n')}`;

            case 'squad':
                const squadSize = parseInt(args[0]) || 5;
                const squadNodes = simulationManager.createTacticalSquad(squadSize);
                squadNodes.forEach(node => handleNodeDiscovered(node));
                
                return `✓ TACTICAL SQUAD DEPLOYED
  • Size: ${squadSize} units
  • Leader: ${squadNodes[0].name}
  • Formation: Active
◉ Squad is operational`;

            case 'base':
                const baseNodes = simulationManager.createBaseNetwork();
                baseNodes.forEach(node => handleNodeDiscovered(node));
                
                return `✓ BASE NETWORK ESTABLISHED
  • Main: ${baseNodes[0].name}
  • Relays: ${baseNodes.length - 1} stations
◉ Network infrastructure online`;

            case 'convoy':
                const convoySize = parseInt(args[0]) || 4;
                const convoyNodes = [];
                
                for (let i = 0; i < convoySize; i++) {
                    const node = simulationManager.createSimulatedNode({
                        name: `CONVOY-${300 + i}`,
                        profile: {
                            type: 'convoy',
                            movement: 'mobile',
                            responsePattern: 'tactical',
                            batteryDrain: 0.15
                        },
                        autoRespond: true
                    });
                    convoyNodes.push(node);
                    handleNodeDiscovered(node);
                }
                
                // Start convoy movement
                simulationManager.simulateConvoyMovement('convoy', 2);
                
                return `✓ CONVOY DEPLOYED
  • Vehicles: ${convoySize}
  • Lead: ${convoyNodes[0].name}
  • Status: Mobile
◉ Convoy in motion...`;

            case 'emergency':
            case 'sos':
                const beacon = simulationManager.createEmergencyBeacon(true);
                handleNodeDiscovered(beacon);
                
                // Send emergency broadcasts
                let sosCount = 0;
                const sosInterval = setInterval(() => {
                    handleMessageReceived({
                        content: `EMERGENCY: Unit requires immediate assistance! GPS: Unknown [${sosCount + 1}/5]`,
                        type: MessageType.BROADCAST
                    }, beacon.id);
                    
                    sosCount++;
                    if (sosCount >= 5) {
                        clearInterval(sosInterval);
                        addSystemLog('WARN', 'Emergency broadcast sequence complete');
                    }
                }, 2000);
                
                return `⚠ EMERGENCY BEACON ACTIVATED
  • Callsign: ${beacon.name}
  • Signal: ${beacon.rssi}dBm
  • Battery: ${beacon.batteryLevel}%
◉ Broadcasting distress signal...`;

            case 'echo':
                const echoNode = simulationManager.createSimulatedNode({
                    name: `ECHO-${Math.floor(100 + Math.random() * 900)}`,
                    rssi: -55,
                    profile: {
                        type: 'relay',
                        movement: 'static',
                        responsePattern: 'echo',
                        batteryDrain: 0.05
                    },
                    autoRespond: true
                });
                
                handleNodeDiscovered(echoNode);
                
                setTimeout(() => {
                    handleNodeConnected(echoNode.id);
                    addSystemLog('SUCCESS', `${echoNode.name} online and responding`);
                }, 1000);
                
                return `✓ Echo station ${echoNode.name} deployed
◉ Auto-connect in 1 second...`;

            case 'connect':
            if (args.length === 0) {
                return '⚠ Usage: connect <node_id or partial_name>';
            }
            
            const searchTerm = args.join(' ').toLowerCase();
            let targetNode: BLENode | undefined;
            
            // Search by partial ID or name
            discoveredNodes.forEach(node => {
                if (node.id.toLowerCase().includes(searchTerm) || 
                    node.name.toLowerCase().includes(searchTerm)) {
                    targetNode = node;
                }
            });
            
            if (!targetNode) {
                return `⚠ Node not found: ${searchTerm}`;
            }
            
            if (connectedNodes.has(targetNode.id)) {
                return `⚠ Already connected to ${targetNode.name}`;
            }
            
            // For simulated nodes, just update the state directly
            targetNode.isConnected = true;
            setConnectedNodes(prev => {
                const updated = new Map(prev);
                if (targetNode) {
                    updated.set(targetNode.id, targetNode);
                }
                return updated;
            });
            
            addSystemLog('SUCCESS', `Connected to ${targetNode.name}`);
            
            return `✓ Connected to ${targetNode.name}
        • Signal: ${targetNode.rssi}dBm
        • Battery: ${targetNode.batteryLevel}%`;

            case 'disconnect':
                if (args.length === 0) {
                    return '⚠ Usage: disconnect <node_id or partial_name>';
                }
                
                const disconnectSearch = args.join(' ').toLowerCase();
                let disconnectTarget: BLENode | undefined;
                
                connectedNodes.forEach(node => {
                    if (node.id.toLowerCase().includes(disconnectSearch) || 
                        node.name.toLowerCase().includes(disconnectSearch)) {
                        disconnectTarget = node;
                    }
                });
                
                if (!disconnectTarget) {
                    return `⚠ Not connected to: ${disconnectSearch}`;
                }
                
                await disconnectFromNode(disconnectTarget.id);
                handleNodeDisconnected(disconnectTarget.id);
                
                return `✓ Disconnected from ${disconnectTarget.name}`;

            case 'ping':
                if (args.length === 0) {
                    return '⚠ Usage: ping <node_id or partial_name>';
                }
                
                const pingSearch = args.join(' ').toLowerCase();
                let pingTarget: BLENode | undefined;
                
                connectedNodes.forEach(node => {
                    if (node.id.toLowerCase().includes(pingSearch) || 
                        node.name.toLowerCase().includes(pingSearch)) {
                        pingTarget = node;
                    }
                });
                
                if (!pingTarget) {
                    return `⚠ Not connected to: ${pingSearch}`;
                }
                
                const pingStart = Date.now();
                await sendMessage('PING', pingTarget.id, MessageType.DIRECT);
                
                // Simulate response
                setTimeout(() => {
                    const responseTime = Date.now() - pingStart;
                    handleMessageReceived({
                        content: `PONG - Response time: ${responseTime}ms`,
                        type: MessageType.DIRECT
                    }, pingTarget!.id);
                }, 100 + Math.random() * 200);
                
                return `✓ Ping sent to ${pingTarget.name}`;

            case 'dm':
            case 'direct':
                if (args.length < 2) {
                    return '⚠ Usage: dm <node_name> <message>';
                }
                
                const dmSearch = args[0].toLowerCase();
                const dmMessage = args.slice(1).join(' ');
                let dmTarget: BLENode | undefined;
                
                discoveredNodes.forEach(node => {
                    if (node.name.toLowerCase().includes(dmSearch)) {
                        dmTarget = node;
                    }
                });
                
                if (!dmTarget) {
                    return `⚠ Node not found: ${dmSearch}`;
                }
                
                await sendMessage(dmMessage, dmTarget.id, MessageType.DIRECT);
                
                // Simulate response if node has auto-respond
                const response = simulationManager.handleMessage(dmTarget.id, dmMessage);
                if (response) {
                    setTimeout(() => {
                        handleMessageReceived({
                            content: response,
                            type: MessageType.DIRECT
                        }, dmTarget!.id);
                    }, 500 + Math.random() * 1000);
                }
                
                return `✓ Message sent to ${dmTarget.name}: "${dmMessage}"`;

            case 'send':
            case 'broadcast':
                if (args.length === 0) {
                    return '⚠ Usage: send <message>';
                }
                
                const broadcastMsg = args.join(' ');
                await sendMessage(broadcastMsg, undefined, MessageType.BROADCAST);
                
                // Simulate responses from auto-responding nodes
                discoveredNodes.forEach(node => {
                    const response = simulationManager.handleMessage(node.id, broadcastMsg);
                    if (response && Math.random() > 0.5) {
                        setTimeout(() => {
                            handleMessageReceived({
                                content: response,
                                type: MessageType.BROADCAST
                            }, node.id);
                        }, 500 + Math.random() * 2000);
                    }
                });
                
                return `✓ Broadcasting: "${broadcastMsg}"`;

            case 'fragment':
                const groupASize = parseInt(args[0]) || 3;
                const groupBSize = parseInt(args[1]) || 3;
                
                const allNodes = Array.from(discoveredNodes.keys());
                const groupA = allNodes.slice(0, groupASize);
                const groupB = allNodes.slice(groupASize, groupASize + groupBSize);
                
                simulationManager.simulateNetworkSplit(groupA, groupB);
                
                return `✓ NETWORK FRAGMENTATION SIMULATED
  • Group A: ${groupA.length} nodes
  • Group B: ${groupB.length} nodes
◉ Groups are now isolated`;

            case 'stress':
                const nodeCount = parseInt(args[0]) || 5;
                const messageCount = parseInt(args[1]) || 10;
                const duration = parseInt(args[2]) || 5000;
                
                // Create stress test nodes
                const stressNodes: any[] = [];
                for (let i = 0; i < nodeCount; i++) {
                    const node = simulationManager.createSimulatedNode({
                        name: `STRESS-${400 + i}`,
                        profile: {
                            type: 'patrol',
                            movement: 'random',
                            responsePattern: 'tactical',
                            batteryDrain: 0.2
                        },
                        autoRespond: true
                    });
                    stressNodes.push(node);
                    handleNodeDiscovered(node);
                }
                
                // Generate message traffic
                let msgSent = 0;
                const messageInterval = duration / messageCount;
                const stressInterval = setInterval(() => {
                    const fromNode = stressNodes[Math.floor(Math.random() * stressNodes.length)];
                    const messageTypes = [
                        'Status report: Sector clear',
                        'Position: Grid reference updated',
                        'Request: Ammunition resupply',
                        'Alert: Hostile contact',
                        'Confirm: Objective achieved'
                    ];
                    
                    handleMessageReceived({
                        content: messageTypes[Math.floor(Math.random() * messageTypes.length)],
                        type: Math.random() > 0.7 ? MessageType.BROADCAST : MessageType.DIRECT
                    }, fromNode.id);
                    
                    msgSent++;
                    if (msgSent >= messageCount) {
                        clearInterval(stressInterval);
                        addSystemLog('SUCCESS', `Stress test complete: ${msgSent} messages`);
                    }
                }, messageInterval);
                
                return `✓ STRESS TEST INITIATED
  • Nodes: ${nodeCount}
  • Messages: ${messageCount}
  • Duration: ${duration}ms
  • Rate: ${(1000/messageInterval).toFixed(1)} msg/sec
◉ Test running...`;

            case 'scenario':
                const scenarioType = args[0] || 'list';
                
                switch (scenarioType) {
                    case 'patrol':
                        const patrolSquad = simulationManager.createTacticalSquad(3);
                        patrolSquad.forEach(node => handleNodeDiscovered(node));
                        
                        // Simulate patrol messages
                        let patrolMsg = 0;
                        const patrolInterval = setInterval(() => {
                            const messages = [
                                'Checkpoint Alpha secure',
                                'Moving to next waypoint',
                                'No hostile activity detected',
                                'Patrol route 50% complete'
                            ];
                            
                            handleMessageReceived({
                                content: messages[patrolMsg % messages.length],
                                type: MessageType.BROADCAST
                            }, patrolSquad[0].id);
                            
                            patrolMsg++;
                            if (patrolMsg >= 10) {
                                clearInterval(patrolInterval);
                            }
                        }, 3000);
                        
                        return `✓ PATROL SCENARIO ACTIVE
  • Squad: ${patrolSquad.map(n => n.name).join(', ')}
  • Pattern: Standard patrol
  • Duration: 30 seconds`;

                    case 'combat':
                        // Create opposing forces
                        const friendlies = simulationManager.createTacticalSquad(4);
                        const hostiles = [];
                        
                        for (let i = 0; i < 3; i++) {
                            const hostile = simulationManager.createSimulatedNode({
                                name: `HOSTILE-${i + 1}`,
                                profile: {
                                    type: 'patrol',
                                    movement: 'random',
                                    responsePattern: 'silent',
                                    batteryDrain: 0.3
                                }
                            });
                            hostiles.push(hostile);
                        }
                        
                        [...friendlies, ...hostiles].forEach(node => handleNodeDiscovered(node));
                        
                        // Simulate combat messages
                        let combatRound = 0;
                        const combatInterval = setInterval(() => {
                            const combatMessages = [
                                'Contact! Hostile forces engaged',
                                'Taking fire from north position',
                                'Returning fire, suppressing enemy',
                                'Request immediate backup',
                                'Enemy neutralized, area secure'
                            ];
                            
                            const sender = friendlies[Math.floor(Math.random() * friendlies.length)];
                            handleMessageReceived({
                                content: combatMessages[Math.min(combatRound, combatMessages.length - 1)],
                                type: MessageType.BROADCAST
                            }, sender.id);
                            
                            combatRound++;
                            if (combatRound >= 8) {
                                clearInterval(combatInterval);
                                addSystemLog('SUCCESS', 'Combat scenario complete');
                            }
                        }, 2000);
                        
                        return `⚠ COMBAT SCENARIO INITIATED
  • Friendlies: ${friendlies.length} units
  • Hostiles: ${hostiles.length} detected
  • Status: ENGAGED
◉ Combat in progress...`;

                    case 'list':
                    default:
                        return `Available scenarios:
  • patrol    - Mobile patrol simulation
  • combat    - Combat engagement
  • emergency - Distress beacon
  • convoy    - Vehicle convoy
  
Usage: scenario <type>`;
                }

            case 'loopback':
            case 'loop':
                const loopbackMsg = args.join(' ') || 'Loopback test message';
                
                setTimeout(() => {
                    handleMessageReceived({
                        content: `[LOOPBACK] ${loopbackMsg}`,
                        type: MessageType.DIRECT
                    }, keyPair?.getFingerprint());
                }, 500);
                
                return `✓ Loopback initiated: "${loopbackMsg}"
◉ Message will return in 500ms...`;

            case 'mesh':
            case 'topology':
            case 'topo':
                const stats = simulationManager.getNetworkStatistics();
                const nodes = Array.from(discoveredNodes.values());
                const connected = Array.from(connectedNodes.values());
                
                let output = 'TACTICAL MESH TOPOLOGY\n';
                output += '═'.repeat(40) + '\n\n';
                output += `LOCAL NODE [${alias.toUpperCase()}]\n`;
                output += `└─ ID: ${keyPair?.getFingerprint().substring(0, 12)}...\n\n`;
                
                if (connected.length > 0) {
                    output += 'CONNECTED UNITS:\n';
                    connected.forEach(node => {
                        const signal = node.rssi > -60 ? '████' : 
                                      node.rssi > -70 ? '███░' : 
                                      node.rssi > -80 ? '██░░' : '█░░░';
                        const battery = node.batteryLevel ? ` [${Math.round(node.batteryLevel)}%]` : '';
                        output += `  ${signal} ${node.name}${battery}\n`;
                        output += `      └─ ${node.rssi.toFixed(0)}dBm · ${node.deviceType}\n`;
                    });
                }
                
                const unconnected = nodes.filter(n => !connectedNodes.has(n.id));
                if (unconnected.length > 0) {
                    output += '\nIN RANGE (Unconnected):\n';
                    unconnected.slice(0, 10).forEach(node => {
                        output += `  ○ ${node.name} (${node.rssi.toFixed(0)}dBm)\n`;
                    });
                    if (unconnected.length > 10) {
                        output += `  ... and ${unconnected.length - 10} more\n`;
                    }
                }
                
                output += '\n' + '─'.repeat(40);
                output += `\nNetwork: ${nodes.length} nodes · ${connected.length} connected`;
                output += `\nAvg Signal: ${stats.averageRSSI.toFixed(0)}dBm · Avg Battery: ${stats.averageBattery.toFixed(0)}%`;
                
                return output;

            case 'stats':
                const netStats = simulationManager.getNetworkStatistics();
                const uptime = Date.now() - networkStats.uptime;
                const hours = Math.floor(uptime / (1000 * 60 * 60));
                const minutes = Math.floor((uptime % (1000 * 60 * 60)) / (1000 * 60));
                const seconds = Math.floor((uptime % (1000 * 60)) / 1000);
                return `
    SYSTEM STATUS

    Node ID    ${keyPair?.getFingerprint().substring(0, 16) || 'Unknown'}...
    Alias      ${alias}
    Uptime     ${hours}h ${minutes}m ${seconds}s

    NETWORK
    Scanning     ${isScanning ? '● Active' : '○ Inactive'}
    Advertising  ${isAdvertising ? '● Active' : '○ Inactive'}
    Discovered   ${discoveredNodes.size} nodes
    Connected    ${connectedNodes.size} nodes

    SIMULATION
    Active Nodes ${simulationManager.getSimulatedNodes().length}
    
    MESSAGES
    Sent         ${networkStats.messagesSent}
    Received     ${networkStats.messagesReceived}`;

                case 'identity':
                case 'id':
                    if (!keyPair) {
                        return '⚠ No identity loaded';
                    }
                    const fingerprint = keyPair.getFingerprint();
                    return `
    NODE IDENTITY

    Fingerprint  ${fingerprint}
    Alias        ${alias}
    Protocol     v2.0`;

                case 'alias':
                    if (args.length === 0) {
                        return `Current alias: ${alias}`;
                    }
                    const newAlias = args.join(' ');
                    setAlias(newAlias);
                    await AsyncStorage.setItem(STORAGE_KEYS.ALIAS, newAlias);
                    return `✓ Alias set to: ${newAlias}`;

                case 'export':
                    if (!keyPair) {
                        return '⚠ No keypair to export';
                    }
                    const exported = keyPair.exportKeys();
                    return `
    EXPORTED KEYPAIR
    ⚠ Keep this private and secure!

    Fingerprint: ${keyPair.getFingerprint()}
    Public Key: ${exported.publicKey.substring(0, 64)}...`;

                case 'test':
                case 'diagnostic':
                case 'diag':
                    let testOutput = 'RUNNING DIAGNOSTICS\n\n';
                    testOutput += 'BLE Manager      ' + (bleManager ? '✓ OK' : '✗ FAILED') + '\n';
                    testOutput += 'KeyPair          ' + (keyPair ? '✓ OK' : '✗ FAILED') + '\n';
                    testOutput += 'Network          ' + (discoveredNodes.size > 0 ? '✓ OK' : '⚠ No nodes') + '\n';
                    testOutput += 'Simulation       ' + (simulationManager.getSimulatedNodes().length > 0 ? '✓ Active' : '○ Inactive') + '\n';
                    testOutput += '\nDiagnostics complete';
                    return testOutput;

                case 'clear':
                case 'cls':
                    return '\x1b[2J\x1b[H';

                default:
                    return `⚠ Unknown command: ${cmd}
    → Type "help" for available commands`;
            }
        } catch (error: any) {
            addSystemLog('ERROR', `Command failed: ${cmd}`, error);
            return `✗ Error: ${error.message || 'Command execution failed'}`;
        }
    }, [
        isScanning, isAdvertising, discoveredNodes, connectedNodes, messages, systemLogs,
        networkStats, keyPair, alias, bleManager,
        startScanning, stopScanning, startAdvertising, stopAdvertising,
        connectToNode, disconnectFromNode, sendMessage, clearMessages, clearLogs,
        addSystemLog, handleNodeDiscovered, handleNodeConnected, handleNodeDisconnected, 
        handleMessageReceived, setAlias
    ]);

    // Initialize BLE and load stored data
    useEffect(() => {
        const initializeGhostComm = async () => {
            try {
                addSystemLog('INFO', 'Starting GhostComm initialization...');

                // Load alias
                const storedAlias = await AsyncStorage.getItem(STORAGE_KEYS.ALIAS);
                if (storedAlias) {
                    setAlias(storedAlias);
                }

                // Load or generate keypair
                let keys: IGhostKeyPair;
                const storedKeys = await AsyncStorage.getItem(STORAGE_KEYS.KEYPAIR);

                if (storedKeys) {
                    addSystemLog('INFO', 'Loading existing keypair');
                    const parsed = JSON.parse(storedKeys);
                    keys = GhostKeyPair.fromExported(parsed);
                } else {
                    addSystemLog('INFO', 'Generating new keypair');
                    const newKeys = new GhostKeyPair();
                    keys = newKeys as IGhostKeyPair;
                    const exported = newKeys.exportKeys();
                    await AsyncStorage.setItem(STORAGE_KEYS.KEYPAIR, JSON.stringify(exported));
                }

                setKeyPair(keys);
                addSystemLog('SUCCESS', `Node ID: ${keys.getFingerprint().substring(0, 8)}...`);

                // Create and initialize BLE manager
                const manager = new ReactNativeBLEManager(keys);
                setBleManager(manager);

                // Set up event listeners
                manager.onEvent((event: BLEConnectionEvent | BLEMessageEvent | BLEDiscoveryEvent) => {
                    handleBLEEvent(event);
                });

                manager.onRNEvent('initialized', () => {
                    addSystemLog('SUCCESS', 'BLE Manager initialized');
                });

                manager.onRNEvent('error', (data: any) => {
                    addSystemLog('ERROR', `BLE Error: ${data.error}`);
                });

                // Initialize manager
                await manager.initialize();

                // Load stored data
                await loadStoredData();

                setIsInitialized(true);
                setIsContextReady(true);
                addSystemLog('SUCCESS', 'GhostComm ready');

            } catch (error) {
                setIsContextReady(true); // Set even on error to prevent hang
                addSystemLog('ERROR', 'Failed to initialize', error);
                debug.error('Initialization failed', error);
            }
        };

        initializeGhostComm();
    }, []);

    // Clean up on unmount
    useEffect(() => {
        return () => {
            if (scanSubscriptionRef.current) {
                try {
                    if (typeof scanSubscriptionRef.current.remove === 'function') {
                        scanSubscriptionRef.current.remove();
                    } else if (typeof scanSubscriptionRef.current.unsubscribe === 'function') {
                        scanSubscriptionRef.current.unsubscribe();
                    }
                } catch (e) {
                    console.warn('Failed to clean up scan subscription on unmount:', e);
                }
            }
        };
    }, []);

    // Save data periodically
    useEffect(() => {
        if (messages.length > 0) {
            AsyncStorage.setItem(STORAGE_KEYS.MESSAGES, JSON.stringify(messages)).catch(console.error);
        }
    }, [messages]);

    useEffect(() => {
        AsyncStorage.setItem(STORAGE_KEYS.NETWORK_STATS, JSON.stringify(networkStats)).catch(console.error);
    }, [networkStats]);

    const value: GhostCommContextType = {
        bleManager,
        keyPair,
        messages,
        discoveredNodes,
        connectedNodes,
        networkStats,
        systemLogs,
        isScanning,
        isAdvertising,
        isInitialized,
        sendMessage,
        clearMessages,
        clearLogs,
        startScanning,
        stopScanning,
        startAdvertising,
        stopAdvertising,
        connectToNode,
        disconnectFromNode,
        refreshNetwork,
        addSystemLog,
        executeCommand,
        getNodeRoutingTable,
        getMessageFlow
    };

    // Don't render children until context is ready
    if (!isContextReady) {
        return null; // Or you could return a loading component here
    }

    return (
        <GhostCommContext.Provider value={value}>
            {children}
        </GhostCommContext.Provider>
    );
};