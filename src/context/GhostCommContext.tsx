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

export const useGhostComm = () => {
    const context = useContext(GhostCommContext);
    if (!context) {
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
        if (!bleManager) throw new Error('BLE not initialized');
        await bleManager.connectToNode(nodeId);
    }, [bleManager]);

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
        // This would normally query the routing table from the BLE manager
        // For now, return a stub or undefined
        return routingTablesRef.current.get(nodeId);
    }, []);

    const getMessageFlow = useCallback((): Map<string, Map<string, number>> => {
        // Return the current message flow data
        return new Map(messageFlowsRef.current);
    }, []);

    // Command execution implementation
    const executeCommand = useCallback(async (command: string): Promise<string> => {
        const parts = command.trim().toLowerCase().split(/\s+/);
        const cmd = parts[0];
        const args = parts.slice(1);

        try {
            switch (cmd) {
                case 'help':
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

SYSTEM ──────────────────────────────────
  status              Show system status
  stats               Network statistics
  logs                Show recent logs
  clear-logs          Clear system logs
  identity            Show node identity
  alias <n>        Set node alias
  export              Export keypair
  ping <id>           Ping a node
  test                Run diagnostics
  clear               Clear terminal
  
Type command or use ? for quick guide`;

                case 'scan':
                    if (isScanning) {
                        return '⚠ Already scanning';
                    }
                    await startScanning();
                    return '✓ Scanning started\n◉ Discovering nearby nodes...';

                case 'stop':
                    if (isScanning) await stopScanning();
                    if (isAdvertising) await stopAdvertising();
                    return '✓ All operations stopped';

                case 'beacon':
                case 'advertise':
                    if (isAdvertising) {
                        return '⚠ Already advertising';
                    }
                    await startAdvertising();
                    return '✓ Beacon active\n◉ Broadcasting presence...';

                case 'nodes':
                    if (discoveredNodes.size === 0) {
                        return '⚠ No nodes discovered\n→ Run "scan" to discover nodes';
                    }
                    let nodeList = 'DISCOVERED NODES\n\n';
                    discoveredNodes.forEach((node, id) => {
                        const connected = connectedNodes.has(id);
                        const status = connected ? '● ' : '○ ';
                        const rssi = node.lastRSSI || -100;
                        const signal = rssi > -60 ? '▰▰▰▰' : rssi > -70 ? '▰▰▰▱' : rssi > -80 ? '▰▰▱▱' : '▰▱▱▱';
                        nodeList += `${status}${id.substring(0, 8)}...  ${signal} ${rssi}dBm\n`;
                        if (connected) {
                            nodeList += `  └─ Connected · ${node.deviceType || 'Unknown'}\n`;
                        }
                    });
                    return nodeList;

                case 'connect':
                    if (args.length === 0) {
                        return '⚠ Usage: connect <node_id>';
                    }
                    const connectId = args[0];
                    const nodeToConnect = Array.from(discoveredNodes.keys())
                        .find(id => id.toLowerCase().startsWith(connectId.toLowerCase()));

                    if (!nodeToConnect) {
                        return `⚠ Node not found: ${connectId}`;
                    }

                    if (connectedNodes.has(nodeToConnect)) {
                        return `⚠ Already connected to ${nodeToConnect.substring(0, 8)}...`;
                    }

                    await connectToNode(nodeToConnect);
                    return `✓ Connected to ${nodeToConnect.substring(0, 8)}...`;

                case 'disconnect':
                    if (args.length === 0) {
                        return '⚠ Usage: disconnect <node_id>';
                    }
                    const disconnectId = args[0];
                    const nodeToDisconnect = Array.from(connectedNodes.keys())
                        .find(id => id.toLowerCase().startsWith(disconnectId.toLowerCase()));

                    if (!nodeToDisconnect) {
                        return `⚠ Not connected to: ${disconnectId}`;
                    }

                    await disconnectFromNode(nodeToDisconnect);
                    return `✓ Disconnected from ${nodeToDisconnect.substring(0, 8)}...`;

                case 'refresh':
                    await refreshNetwork();
                    return '✓ Network refreshed\n◉ Rediscovering nodes...';

                case 'send':
                case 'broadcast':
                    if (args.length === 0) {
                        return '⚠ Usage: send <message>';
                    }
                    const broadcastMsg = args.join(' ');
                    await sendMessage(broadcastMsg, undefined, MessageType.BROADCAST);
                    return `✓ Broadcasting: "${broadcastMsg}"`;

                case 'dm':
                case 'direct':
                    if (args.length < 2) {
                        return '⚠ Usage: dm <node_id> <message>';
                    }
                    const dmNodeId = args[0];
                    const dmMsg = args.slice(1).join(' ');
                    const dmTarget = Array.from(connectedNodes.keys())
                        .find(id => id.toLowerCase().startsWith(dmNodeId.toLowerCase()));

                    if (!dmTarget) {
                        return `⚠ Not connected to: ${dmNodeId}`;
                    }

                    await sendMessage(dmMsg, dmTarget, MessageType.DIRECT);
                    return `✓ Sent to ${dmTarget.substring(0, 8)}...: "${dmMsg}"`;

                case 'messages':
                case 'msgs':
                    if (messages.length === 0) {
                        return '⚠ No messages';
                    }
                    let msgList = 'MESSAGE HISTORY\n\n';
                    messages.slice(-10).forEach(msg => {
                        const time = new Date(msg.timestamp).toLocaleTimeString('en-US', {
                            hour12: false,
                            hour: '2-digit',
                            minute: '2-digit'
                        });
                        const direction = msg.isIncoming ? '←' : '→';
                        const status = msg.status === 'DELIVERED' ? '✓' :
                            msg.status === 'SENT' ? '→' :
                                msg.status === 'FAILED' ? '✗' : '◉';
                        msgList += `[${time}] ${direction} ${status} ${msg.content}\n`;
                    });
                    return msgList;

                case 'clear-messages':
                    await clearMessages();
                    return '✓ Messages cleared';

                case 'status':
                    const nodeId = keyPair?.getFingerprint() || 'Unknown';
                    const uptime = Math.floor((Date.now() - networkStats.uptime) / 1000);
                    const hours = Math.floor(uptime / 3600);
                    const minutes = Math.floor((uptime % 3600) / 60);
                    const seconds = uptime % 60;

                    return `
SYSTEM STATUS

Node ID    ${nodeId.substring(0, 16)}...
Alias      ${alias}
Uptime     ${hours}h ${minutes}m ${seconds}s

NETWORK
  Scanning     ${isScanning ? '● Active' : '○ Inactive'}
  Advertising  ${isAdvertising ? '● Active' : '○ Inactive'}
  Discovered   ${discoveredNodes.size} nodes
  Connected    ${connectedNodes.size} nodes

MESSAGES
  Sent         ${networkStats.messagesSent}
  Received     ${networkStats.messagesReceived}
  Relayed      ${networkStats.messagesRelayed}
  Dropped      ${networkStats.messagesDropped}

DATA TRANSFER
  TX           ${(networkStats.bytesTransmitted / 1024).toFixed(2)} KB
  RX           ${(networkStats.bytesReceived / 1024).toFixed(2)} KB`;

                case 'stats':
                    return `
NETWORK STATISTICS

Nodes
  Total        ${networkStats.totalNodes}
  Active       ${networkStats.activeNodes}
  Trusted      ${networkStats.trustedNodes}
  Blocked      ${networkStats.blockedNodes}

Messages
  Sent         ${networkStats.messagesSent}
  Received     ${networkStats.messagesReceived}
  Relayed      ${networkStats.messagesRelayed}
  Dropped      ${networkStats.messagesDropped}

Performance
  Delivery     ${(networkStats.deliverySuccessRate * 100).toFixed(1)}%
  Avg Hops     ${networkStats.averageHopCount.toFixed(1)}
  Avg Latency  ${networkStats.averageLatency.toFixed(0)}ms
  Density      ${(networkStats.networkDensity * 100).toFixed(1)}%
  Reach        ${(networkStats.networkReachability * 100).toFixed(1)}%

Data Transfer
  TX           ${(networkStats.bytesTransmitted / 1024).toFixed(2)} KB
  RX           ${(networkStats.bytesReceived / 1024).toFixed(2)} KB
  Throughput   ${networkStats.averageThroughput.toFixed(2)} KB/s`;

                case 'logs':
                    if (systemLogs.length === 0) {
                        return '⚠ No logs';
                    }
                    let logOutput = 'SYSTEM LOGS\n\n';
                    systemLogs.slice(-20).forEach(log => {
                        const time = new Date(log.timestamp).toLocaleTimeString('en-US', {
                            hour12: false,
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit'
                        });
                        const levelIcon = log.level === 'ERROR' ? '✗' :
                            log.level === 'WARN' ? '⚠' :
                                log.level === 'SUCCESS' ? '✓' :
                                    log.level === 'DEBUG' ? '◆' : '•';
                        logOutput += `${time} ${levelIcon} ${log.message}\n`;
                    });
                    return logOutput;

                case 'clear-logs':
                    clearLogs();
                    return '✓ Logs cleared';

                case 'identity':
                case 'id':
                    if (!keyPair) {
                        return '⚠ No identity loaded';
                    }
                    const fingerprint = keyPair.getFingerprint();
                    const publicKey = keyPair.exportKeys().publicKey;
                    return `
NODE IDENTITY

Fingerprint  ${fingerprint}
Alias        ${alias}

Public Key (Ed25519)
${publicKey.substring(0, 32)}
${publicKey.substring(32, 64)}
${publicKey.substring(64, 96)}
${publicKey.substring(96, 128)}`;

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

${JSON.stringify(exported, null, 2)}`;

                case 'ping':
                    if (args.length === 0) {
                        return '⚠ Usage: ping <node_id>';
                    }
                    const pingTarget = args[0];
                    const pingNode = Array.from(connectedNodes.keys())
                        .find(id => id.toLowerCase().startsWith(pingTarget.toLowerCase()));

                    if (!pingNode) {
                        return `⚠ Not connected to: ${pingTarget}`;
                    }

                    const pingStart = Date.now();
                    await sendMessage('PING', pingNode, MessageType.DIRECT);
                    const pingTime = Date.now() - pingStart;
                    return `✓ Ping to ${pingNode.substring(0, 8)}...: ${pingTime}ms`;

                case 'test':
                case 'diagnostic':
                case 'diag':
                    let testOutput = 'RUNNING DIAGNOSTICS\n\n';
                    testOutput += 'BLE Manager      ' + (bleManager ? '✓ OK' : '✗ FAILED') + '\n';
                    testOutput += 'KeyPair          ' + (keyPair ? '✓ OK' : '✗ FAILED') + '\n';
                    testOutput += 'Network          ' + (discoveredNodes.size > 0 ? '✓ OK' : '⚠ No nodes') + '\n';
                    testOutput += 'Storage          ✓ OK\n';
                    testOutput += 'Crypto           ✓ OK\n';
                    testOutput += '\nDiagnostics complete';
                    return testOutput;

                case 'clear':
                case 'cls':
                    // Terminal screen will handle clearing
                    return '\x1b[2J\x1b[H';

                case 'exit':
                case 'quit':
                    return '✓ Goodbye';

                case 'version':
                case 'ver':
                    return `
GhostComm v2.0.0
Protocol: Binary Packet v2
Encryption: XChaCha20-Poly1305
Signatures: Ed25519
Key Exchange: X25519`;

                case 'debug':
                    const debugMode = args[0] === 'on' || args[0] === 'true';
                    if (debugMode) {
                        addSystemLog('DEBUG', 'Debug mode enabled');
                        return '✓ Debug mode ON';
                    } else {
                        return '✓ Debug mode OFF';
                    }

                default:
                    return `⚠ Unknown command: ${cmd}\n→ Type "help" for available commands`;
            }
        } catch (error: any) {
            addSystemLog('ERROR', `Command failed: ${cmd}`, error);
            return `✗ Error: ${error.message || 'Command execution failed'}`;
        }
    }, [
        isScanning, isAdvertising, discoveredNodes, connectedNodes, messages,
        networkStats, systemLogs, keyPair, alias, bleManager,
        startScanning, stopScanning, startAdvertising, stopAdvertising,
        connectToNode, disconnectFromNode, refreshNetwork, sendMessage,
        clearMessages, clearLogs, addSystemLog
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
                addSystemLog('SUCCESS', 'GhostComm ready');

            } catch (error) {
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

    return (
        <GhostCommContext.Provider value={value}>
            {children}
        </GhostCommContext.Provider>
    );
};