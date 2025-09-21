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
    IGhostKeyPair,
    MessageType,
    MessagePriority,
    NetworkStats,
    VerificationStatus,
    VerificationMethod,
    VerificationResult,
    NodeCapability,
    DeviceType,
    SECURITY_CONFIG,
    ConnectionState,
    BLESession,
    BLEMessage
} from '../../core';
import { debug } from '../utils/debug';
import { BLE_SECURITY_CONFIG } from '../../core/src/ble/types';

// Enhanced system log with Protocol v2.1 events
export interface SystemLog {
    id: string;
    timestamp: number;
    level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'DEBUG' | 'SECURITY';
    category?: 'NETWORK' | 'MESSAGE' | 'SECURITY' | 'SYSTEM' | 'PROTOCOL';
    message: string;
    data?: any;
}

// Enhanced stored message with Protocol v2.1 fields
export interface StoredMessage {
    id: string;
    content: string;
    type: MessageType;
    status: 'QUEUED' | 'SIGNING' | 'TRANSMITTING' | 'SENT' | 'DELIVERED' | 'FAILED' | 'TIMEOUT' | 'VERIFIED';
    timestamp: number;
    isIncoming: boolean;
    senderFingerprint?: string;
    recipientFingerprint?: string;
    
    // Protocol v2.1 fields
    messageHash?: string;
    previousMessageHash?: string;
    sequenceNumber?: number;
    verified?: boolean;
    verificationError?: string;
    
    // Delivery tracking
    attempts?: number;
    lastAttempt?: number;
    hopCount?: number;
    relayPath?: string[];
}

// Node trust management
export interface TrustedNode {
    nodeId: string;
    fingerprint: string;
    alias?: string;
    verificationMethod: VerificationMethod;
    verifiedAt: number;
    trustLevel: 'VERIFIED' | 'TRUSTED' | 'KNOWN';
    publicKey?: string;
    lastSeen: number;
}

// Enhanced context type with Protocol v2.1 features
interface GhostCommContextType {
    // Core objects
    bleManager: ReactNativeBLEManager | null;
    keyPair: IGhostKeyPair | null;
    
    // State
    messages: StoredMessage[];
    discoveredNodes: Map<string, BLENode>;
    connectedNodes: Map<string, BLENode>;
    trustedNodes: Map<string, TrustedNode>;
    activeSessions: Map<string, BLESession>;
    networkStats: NetworkStats;
    systemLogs: SystemLog[];
    
    // Status flags
    isScanning: boolean;
    isAdvertising: boolean;
    isInitialized: boolean;
    protocolVersion: string;
    
    // Enhanced actions
    sendMessage: (content: string, recipientId?: string, type?: MessageType, priority?: MessagePriority) => Promise<void>;
    verifyNode: (nodeId: string, method: VerificationMethod, verificationData?: string) => Promise<VerificationResult>;
    trustNode: (nodeId: string, alias?: string) => Promise<void>;
    untrustNode: (nodeId: string) => Promise<void>;
    exportTrustedNodes: () => Promise<string>;
    importTrustedNodes: (data: string) => Promise<void>;
    
    // Network management
    startScanning: () => Promise<void>;
    stopScanning: () => Promise<void>;
    startAdvertising: () => Promise<void>;
    stopAdvertising: () => Promise<void>;
    connectToNode: (nodeId: string) => Promise<void>;
    disconnectFromNode: (nodeId: string) => Promise<void>;
    refreshNetwork: () => Promise<void>;
    
    // Data management
    clearMessages: () => Promise<void>;
    clearLogs: () => void;
    exportMessages: () => Promise<string>;
    
    // Command interface
    executeCommand: (command: string) => Promise<string>;
    
    // Logging
    addSystemLog: (level: SystemLog['level'], message: string, category?: SystemLog['category'], data?: any) => void;
    
    // Security
    getNodeSecurityInfo: (nodeId: string) => {
        verified: boolean;
        trusted: boolean;
        publicKey?: string;
        verificationMethod?: VerificationMethod;
        sessionActive: boolean;
        messageChainIntact: boolean;
    } | null;
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
    TRUSTED_NODES: '@ghostcomm_trusted_nodes',
    MESSAGE_CHAINS: '@ghostcomm_message_chains',
};

export const GhostCommProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [bleManager, setBleManager] = useState<ReactNativeBLEManager | null>(null);
    const [keyPair, setKeyPair] = useState<IGhostKeyPair | null>(null);
    const [messages, setMessages] = useState<StoredMessage[]>([]);
    const [discoveredNodes, setDiscoveredNodes] = useState<Map<string, BLENode>>(new Map());
    const [connectedNodes, setConnectedNodes] = useState<Map<string, BLENode>>(new Map());
    const [trustedNodes, setTrustedNodes] = useState<Map<string, TrustedNode>>(new Map());
    const [activeSessions, setActiveSessions] = useState<Map<string, BLESession>>(new Map());
    const [systemLogs, setSystemLogs] = useState<SystemLog[]>([]);
    const [isInitialized, setIsInitialized] = useState(false);
    const [isScanning, setIsScanning] = useState(false);
    const [isAdvertising, setIsAdvertising] = useState(false);
    const [alias, setAlias] = useState('anonymous');
    const protocolVersion = `${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}.1`;

    // Message chain tracking for Protocol v2.1
    const messageChains = useRef<Map<string, {
        lastSentHash: string;
        lastReceivedHash: string;
        sentSequence: number;
        receivedSequence: number;
        chainBreaks: number;
    }>>(new Map());

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

    // Enhanced logging with categories
    const addSystemLog = useCallback((
        level: SystemLog['level'],
        message: string,
        category: SystemLog['category'] = 'SYSTEM',
        data?: any
    ) => {
        const log: SystemLog = {
            id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: Date.now(),
            level,
            category,
            message,
            data,
        };

        setSystemLogs(prev => {
            const updated = [...prev, log];
            // Keep only last 200 logs for Protocol v2.1 debugging
            if (updated.length > 200) {
                return updated.slice(-200);
            }
            return updated;
        });

        debug.info(`[${level}/${category}] ${message}`, data);
    }, []);

    // Enhanced node discovery with Protocol v2.1 verification
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

        // Check if node supports Protocol v2.1
        if (node.protocolVersion >= 2.1) {
            addSystemLog('INFO', `Discovered v${node.protocolVersion} node: ${node.name || node.id.substring(0, 8)}`, 'NETWORK');
        } else {
            addSystemLog('WARN', `Legacy node discovered: ${node.name || node.id.substring(0, 8)} (v${node.protocolVersion})`, 'NETWORK');
        }

        // Check if this is a trusted node
        const trusted = trustedNodes.get(node.id);
        if (trusted) {
            addSystemLog('SUCCESS', `Trusted node online: ${trusted.alias || node.id.substring(0, 8)}`, 'SECURITY');
        }
    }, [trustedNodes, addSystemLog]);

    // Enhanced connection handling with session tracking
    const handleNodeConnected = useCallback((nodeId: string, session?: BLESession) => {
        const node = discoveredNodes.get(nodeId);
        if (node) {
            setConnectedNodes(prev => {
                const updated = new Map(prev);
                updated.set(nodeId, node);
                return updated;
            });

            if (session) {
                setActiveSessions(prev => {
                    const updated = new Map(prev);
                    updated.set(nodeId, session);
                    return updated;
                });
                addSystemLog('SUCCESS', `Secure session established with ${node.name || nodeId.substring(0, 8)}`, 'SECURITY');
            }

            setNetworkStats(prev => ({
                ...prev,
                activeNodes: (prev.activeNodes || 0) + 1,
                totalConnections: (prev.totalConnections || 0) + 1,
                lastUpdated: Date.now()
            }));

            addSystemLog('SUCCESS', `Connected: ${node.name || nodeId.substring(0, 8)}`, 'NETWORK');
        }
    }, [discoveredNodes, addSystemLog]);

    // Enhanced message handling with Protocol v2.1 verification
    const handleMessageReceived = useCallback((
        message: BLEMessage,
        fromNodeId?: string,
        verificationResult?: { verified: boolean; error?: string }
    ) => {
        const newMessage: StoredMessage = {
            id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            content: typeof message === 'object' && message.encryptedPayload 
                ? '[Encrypted Message]' 
                : message.toString(),
            type: MessageType.DIRECT,
            timestamp: Date.now(),
            status: verificationResult?.verified ? 'VERIFIED' : 'DELIVERED',
            isIncoming: true,
            senderFingerprint: fromNodeId,
            recipientFingerprint: keyPair?.getFingerprint(),
            
            // Protocol v2.1 fields
            messageHash: message.messageHash,
            previousMessageHash: message.previousMessageHash,
            sequenceNumber: message.sequenceNumber,
            verified: verificationResult?.verified,
            verificationError: verificationResult?.error,
            hopCount: message.hopCount,
            relayPath: message.routePath
        };

        setMessages(prev => [...prev, newMessage]);

        // Update message chain tracking
        if (fromNodeId) {
            const chain = messageChains.current.get(fromNodeId) || {
                lastSentHash: '',
                lastReceivedHash: '',
                sentSequence: 0,
                receivedSequence: 0,
                chainBreaks: 0
            };
            
            // Check chain integrity
            if (chain.lastReceivedHash && message.previousMessageHash !== chain.lastReceivedHash) {
                chain.chainBreaks++;
                addSystemLog('WARN', `Message chain break from ${fromNodeId.substring(0, 8)} (${chain.chainBreaks} breaks)`, 'SECURITY');
            }
            
            chain.lastReceivedHash = message.messageHash;
            chain.receivedSequence = message.sequenceNumber;
            messageChains.current.set(fromNodeId, chain);
        }

        setNetworkStats(prev => ({
            ...prev,
            messagesReceived: prev.messagesReceived + 1,
            bytesReceived: prev.bytesReceived + (newMessage.content?.length || 0),
            averageHopCount: ((prev.averageHopCount * prev.messagesReceived) + (message.hopCount || 0)) / (prev.messagesReceived + 1),
            lastUpdated: Date.now()
        }));

        // Log with verification status
        if (verificationResult?.verified) {
            addSystemLog('SUCCESS', `Verified message from ${fromNodeId?.substring(0, 8) || 'unknown'}`, 'MESSAGE');
        } else if (verificationResult?.error) {
            addSystemLog('SECURITY', `Unverified message from ${fromNodeId?.substring(0, 8)}: ${verificationResult.error}`, 'SECURITY');
        } else {
            addSystemLog('INFO', `Message from ${fromNodeId?.substring(0, 8) || 'unknown'}`, 'MESSAGE');
        }
    }, [keyPair, addSystemLog]);

    // Enhanced BLE event handler with Protocol v2.1 events
    const handleBLEEvent = useCallback((event: BLEConnectionEvent | BLEMessageEvent | BLEDiscoveryEvent) => {
        switch (event.type) {
            case 'node_discovered':
            case 'node_updated':
                const discEvent = event as BLEDiscoveryEvent;
                if (discEvent.node) {
                    handleNodeDiscovered(discEvent.node);
                }
                break;

            case 'node_verified':
                const verifyEvent = event as BLEDiscoveryEvent;
                if (verifyEvent.node && verifyEvent.verificationResult) {
                    addSystemLog('SUCCESS', `Node verified: ${verifyEvent.node.id.substring(0, 8)}`, 'SECURITY');
                }
                break;

            case 'node_lost':
                const lostEvent = event as BLEDiscoveryEvent;
                if (lostEvent.node) {
                    setDiscoveredNodes(prev => {
                        const updated = new Map(prev);
                        updated.delete(lostEvent.node.id);
                        return updated;
                    });
                    addSystemLog('INFO', `Lost: ${lostEvent.node.id.substring(0, 8)}`, 'NETWORK');
                }
                break;

            case 'connected':
                const connEvent = event as BLEConnectionEvent;
                handleNodeConnected(connEvent.nodeId);
                break;

            case 'authenticated':
            case 'session_established':
                const authEvent = event as BLEConnectionEvent;
                if (authEvent.session) {
                    handleNodeConnected(authEvent.nodeId, authEvent.session);
                }
                break;

            case 'disconnected':
                const disconnEvent = event as BLEConnectionEvent;
                handleNodeDisconnected(disconnEvent.nodeId);
                break;

            case 'message_received':
                const msgEvent = event as BLEMessageEvent;
                handleMessageReceived(
                    msgEvent.message,
                    msgEvent.fromNodeId,
                    msgEvent.verificationResult
                );
                break;

            case 'message_acknowledged':
                const ackEvent = event as BLEMessageEvent;
                if (ackEvent.acknowledgment) {
                    handleMessageAcknowledged(
                        ackEvent.acknowledgment.messageId,
                        ackEvent.fromNodeId || ''
                    );
                }
                break;

            case 'signature_verification_failed':
                const sigFailEvent = event as BLEMessageEvent;
                addSystemLog('SECURITY', 
                    `Signature verification failed from ${sigFailEvent.fromNodeId?.substring(0, 8)}: ${sigFailEvent.verificationResult?.error}`,
                    'SECURITY'
                );
                break;

            case 'error':
                const errorEvent = event as BLEConnectionEvent;
                if (errorEvent.error) {
                    addSystemLog('ERROR', errorEvent.error.message, 'SYSTEM');
                }
                break;
        }
    }, [handleNodeDiscovered, handleNodeConnected, handleMessageReceived, addSystemLog]);

    const handleNodeDisconnected = useCallback((nodeId: string) => {
        setConnectedNodes(prev => {
            const updated = new Map(prev);
            updated.delete(nodeId);
            return updated;
        });

        setActiveSessions(prev => {
            const updated = new Map(prev);
            updated.delete(nodeId);
            return updated;
        });

        setNetworkStats(prev => ({
            ...prev,
            activeNodes: Math.max(0, prev.activeNodes - 1),
            lastUpdated: Date.now()
        }));

        addSystemLog('WARN', `Disconnected: ${nodeId.substring(0, 8)}`, 'NETWORK');
    }, [addSystemLog]);

    const handleMessageAcknowledged = useCallback((
    messageId: string,
    fromNodeId: string
    ): void => {
        console.log(`✅ Message ${messageId} acknowledged by ${fromNodeId}`);
    
    // Update message status to DELIVERED
    setMessages(prev => 
        prev.map(msg => {
            if (msg.id === messageId || msg.messageHash === messageId) {
                return {
                    ...msg,
                    status: 'DELIVERED' as const,
                    deliveredAt: Date.now()
                };
            }
            return msg;
        })
    );
    
    // Update network statistics
    setNetworkStats(prev => ({
        ...prev,
        deliverySuccessRate: Math.min(
            1,
            (prev.deliverySuccessRate * prev.messagesSent + 1) / (prev.messagesSent + 1)
        ),
        lastUpdated: Date.now()
    }));
    
    // Find the node for better logging
    const node = discoveredNodes.get(fromNodeId);
    const nodeName = node?.name || fromNodeId.substring(0, 8);
    
    addSystemLog(
        'SUCCESS',
        `Message delivered to ${nodeName}`,
        'MESSAGE',
        { messageId, fromNodeId }
    );
}, [discoveredNodes, addSystemLog]);
    

    // Node verification with Protocol v2.1
    const verifyNode = useCallback(async (
        nodeId: string,
        method: VerificationMethod,
        verificationData?: string
    ): Promise<VerificationResult> => {
        if (!bleManager) {
            throw new Error('BLE Manager not initialized');
        }

        const result = await bleManager.verifyNode(nodeId, method, verificationData);
        
        if (result.verified) {
            addSystemLog('SUCCESS', `Node verified via ${method}: ${nodeId.substring(0, 8)}`, 'SECURITY');
        } else {
            addSystemLog('WARN', `Verification failed for ${nodeId.substring(0, 8)}`, 'SECURITY');
        }

        return result;
    }, [bleManager, addSystemLog]);

    // Trust management
    const trustNode = useCallback(async (nodeId: string, alias?: string) => {
        const node = discoveredNodes.get(nodeId);
        if (!node) {
            throw new Error('Node not found');
        }

        const trustedNode: TrustedNode = {
            nodeId,
            fingerprint: node.id,
            alias,
            verificationMethod: node.verificationMethod || VerificationMethod.FINGERPRINT,
            verifiedAt: Date.now(),
            trustLevel: node.verificationStatus === VerificationStatus.VERIFIED ? 'VERIFIED' : 'KNOWN',
            publicKey: node.identityKey ? Buffer.from(node.identityKey).toString('hex') : undefined,
            lastSeen: Date.now()
        };

        setTrustedNodes(prev => {
            const updated = new Map(prev);
            updated.set(nodeId, trustedNode);
            return updated;
        });

        // Persist trusted nodes
        const trustedArray = Array.from(trustedNodes.values());
        trustedArray.push(trustedNode);
        await AsyncStorage.setItem(STORAGE_KEYS.TRUSTED_NODES, JSON.stringify(trustedArray));

        addSystemLog('SUCCESS', `Node trusted: ${alias || nodeId.substring(0, 8)}`, 'SECURITY');
    }, [discoveredNodes, trustedNodes, addSystemLog]);

    const untrustNode = useCallback(async (nodeId: string) => {
        setTrustedNodes(prev => {
            const updated = new Map(prev);
            updated.delete(nodeId);
            return updated;
        });

        const trustedArray = Array.from(trustedNodes.values()).filter(n => n.nodeId !== nodeId);
        await AsyncStorage.setItem(STORAGE_KEYS.TRUSTED_NODES, JSON.stringify(trustedArray));

        addSystemLog('INFO', `Node untrusted: ${nodeId.substring(0, 8)}`, 'SECURITY');
    }, [trustedNodes, addSystemLog]);

    // Enhanced message sending with Protocol v2.1
    const sendMessage = useCallback(async (
        content: string,
        recipientId?: string,
        type: MessageType = MessageType.DIRECT,
        priority: MessagePriority = MessagePriority.NORMAL
    ) => {
        if (!bleManager || !keyPair) {
            throw new Error('BLE Manager not initialized');
        }

        const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Get or create message chain
        const chain = recipientId ? (messageChains.current.get(recipientId) || {
            lastSentHash: '',
            lastReceivedHash: '',
            sentSequence: 0,
            receivedSequence: 0,
            chainBreaks: 0
        }) : null;

        const newMessage: StoredMessage = {
            id: messageId,
            content,
            type,
            timestamp: Date.now(),
            status: 'QUEUED',
            isIncoming: false,
            senderFingerprint: keyPair.getFingerprint(),
            recipientFingerprint: recipientId,
            sequenceNumber: chain ? chain.sentSequence : 0,
            previousMessageHash: chain ? chain.lastSentHash : '',
            attempts: 0,
            lastAttempt: Date.now(),
        };

        setMessages(prev => [...prev, newMessage]);

        try {
            // Update status to signing (Protocol v2.1)
            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'SIGNING' } : msg
                )
            );

            // Send message (Protocol v2.1 signing handled by BLE manager)
            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'TRANSMITTING' } : msg
                )
            );

            let bleMessageId: string;
            if (type === MessageType.BROADCAST) {
                bleMessageId = await bleManager.broadcastMessage(content, priority);
            } else if (recipientId) {
                bleMessageId = await bleManager.sendMessage(recipientId, content, priority);
            } else {
                throw new Error('Recipient required for direct message');
            }

            // Update message chain if direct message
            if (chain && recipientId) {
                // The BLE manager will have calculated the hash
                chain.sentSequence++;
                messageChains.current.set(recipientId, chain);
            }

            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'SENT', messageHash: bleMessageId } : msg
                )
            );

            setNetworkStats(prev => ({
                ...prev,
                messagesSent: prev.messagesSent + 1,
                bytesTransmitted: prev.bytesTransmitted + content.length,
                lastUpdated: Date.now()
            }));

            addSystemLog('SUCCESS', `Message sent (${type})`, 'MESSAGE');

        } catch (error: any) {
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

            addSystemLog('ERROR', `Failed to send message: ${error.message}`, 'MESSAGE');
            throw error;
        }
    }, [bleManager, keyPair, addSystemLog]);

    // Get security info for a node
    const getNodeSecurityInfo = useCallback((nodeId: string) => {
        const node = discoveredNodes.get(nodeId);
        if (!node) return null;

        const trusted = trustedNodes.has(nodeId);
        const session = activeSessions.get(nodeId);
        const chain = messageChains.current.get(nodeId);

        return {
            verified: node.verificationStatus === VerificationStatus.VERIFIED,
            trusted,
            publicKey: node.identityKey ? Buffer.from(node.identityKey).toString('hex') : undefined,
            verificationMethod: node.verificationMethod,
            sessionActive: !!session,
            messageChainIntact: chain ? chain.chainBreaks === 0 : true
        };
    }, [discoveredNodes, trustedNodes, activeSessions]);

    // Export/Import functions
    const exportTrustedNodes = useCallback(async (): Promise<string> => {
        const nodes = Array.from(trustedNodes.values());
        return JSON.stringify(nodes, null, 2);
    }, [trustedNodes]);

    const importTrustedNodes = useCallback(async (data: string) => {
        try {
            const nodes = JSON.parse(data) as TrustedNode[];
            const nodeMap = new Map(nodes.map(n => [n.nodeId, n]));
            setTrustedNodes(nodeMap);
            await AsyncStorage.setItem(STORAGE_KEYS.TRUSTED_NODES, JSON.stringify(nodes));
            addSystemLog('SUCCESS', `Imported ${nodes.length} trusted nodes`, 'SECURITY');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to import trusted nodes', 'SECURITY', error);
            throw error;
        }
    }, [addSystemLog]);

    const exportMessages = useCallback(async (): Promise<string> => {
        return JSON.stringify(messages, null, 2);
    }, [messages]);

    // Network management functions
    const clearMessages = useCallback(async () => {
        setMessages([]);
        await AsyncStorage.removeItem(STORAGE_KEYS.MESSAGES);
        addSystemLog('INFO', 'Messages cleared', 'SYSTEM');
    }, [addSystemLog]);

    const clearLogs = useCallback(() => {
        setSystemLogs([]);
        AsyncStorage.removeItem(STORAGE_KEYS.SYSTEM_LOGS).catch(console.error);
    }, []);

    const startScanning = useCallback(async () => {
        if (!bleManager || isScanning) return;
        try {
            await bleManager.start();
            setIsScanning(true);
            setIsAdvertising(true);
            addSystemLog('SUCCESS', `Mesh network started (Protocol v${protocolVersion})`, 'NETWORK');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to start scanning', 'NETWORK', error);
            throw error;
        }
    }, [bleManager, isScanning, protocolVersion, addSystemLog]);

    const stopScanning = useCallback(async () => {
        if (!bleManager || !isScanning) return;
        try {
            await bleManager.stop();
            setIsScanning(false);
            setIsAdvertising(false);
            addSystemLog('INFO', 'Mesh network stopped', 'NETWORK');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to stop scanning', 'NETWORK', error);
            throw error;
        }
    }, [bleManager, isScanning, addSystemLog]);

    const startAdvertising = startScanning; // Combined in Protocol v2.1
    const stopAdvertising = stopScanning;

    const connectToNode = useCallback(async (nodeId: string) => {
        if (!bleManager) throw new Error('BLE not initialized');
        await bleManager.connectToNode(nodeId);
    }, [bleManager]);

    const disconnectFromNode = useCallback(async (nodeId: string) => {
        if (!bleManager) throw new Error('BLE not initialized');
        await bleManager.disconnectFromNode(nodeId);
    }, [bleManager]);

    const refreshNetwork = useCallback(async () => {
        addSystemLog('INFO', 'Refreshing network...', 'NETWORK');
        setDiscoveredNodes(new Map());
        setConnectedNodes(new Map());
        setActiveSessions(new Map());

        if (bleManager && isScanning) {
            await stopScanning();
            await startScanning();
        }
    }, [bleManager, isScanning, stopScanning, startScanning, addSystemLog]);

    // Enhanced command execution with Protocol v2.1 commands
    const executeCommand = useCallback(async (command: string): Promise<string> => {
        const parts = command.trim().split(/\s+/);
        const cmd = parts[0].toLowerCase();
        const args = parts.slice(1);

        try {
            switch (cmd) {
                case 'help':
                case '?':
                    return `GHOSTCOMM PROTOCOL v${protocolVersion} COMMANDS

NETWORK
  scan          Start mesh network
  stop          Stop network activity  
  nodes         List discovered nodes
  connect <id>  Connect to node
  disconnect    Disconnect from node
  refresh       Refresh network

SECURITY (v2.1)
  verify <id> <method>  Verify node identity
  trust <id> [alias]    Mark node as trusted
  untrust <id>          Remove trust
  trusted               List trusted nodes
  security <id>         Show node security info

MESSAGING
  send <msg>            Broadcast message
  dm <id> <msg>         Direct message
  messages              Show messages
  clear                 Clear messages

SYSTEM
  status                System status
  stats                 Network statistics
  logs [category]       Show logs
  identity              Your node identity
  alias [name]          Set/show alias
  export <type>         Export data

Type 'help <command>' for details`;

                case 'verify':
                    if (args.length < 2) {
                        return 'Usage: verify <node_id> <method>\nMethods: fingerprint, qr_code, numeric';
                    }
                    
                    const verifyTarget = args[0];
                    const verifyMethod = args[1] as VerificationMethod;
                    const verifyData = args[2];
                    
                    const nodeToVerify = Array.from(discoveredNodes.values()).find(
                        n => n.id.includes(verifyTarget) || n.name?.includes(verifyTarget)
                    );
                    
                    if (!nodeToVerify) {
                        return `Node not found: ${verifyTarget}`;
                    }
                    
                    const verifyResult = await verifyNode(nodeToVerify.id, verifyMethod, verifyData);
                    return verifyResult.verified 
                        ? `✓ Node verified: ${nodeToVerify.name || nodeToVerify.id.substring(0, 8)}`
                        : `✗ Verification failed`;

                case 'trust':
                    if (args.length === 0) {
                        return 'Usage: trust <node_id> [alias]';
                    }
                    
                    const trustTarget = args[0];
                    const trustAlias = args.slice(1).join(' ');
                    
                    const nodeToTrust = Array.from(discoveredNodes.values()).find(
                        n => n.id.includes(trustTarget) || n.name?.includes(trustTarget)
                    );
                    
                    if (!nodeToTrust) {
                        return `Node not found: ${trustTarget}`;
                    }
                    
                    await trustNode(nodeToTrust.id, trustAlias);
                    return `✓ Node trusted: ${trustAlias || nodeToTrust.name || nodeToTrust.id.substring(0, 8)}`;

                case 'untrust':
                    if (args.length === 0) {
                        return 'Usage: untrust <node_id>';
                    }
                    
                    await untrustNode(args[0]);
                    return `✓ Node untrusted`;

                case 'trusted':
                    if (trustedNodes.size === 0) {
                        return 'No trusted nodes';
                    }
                    
                    let trustedList = `TRUSTED NODES (${trustedNodes.size})\n\n`;
                    trustedNodes.forEach((node) => {
                        const online = discoveredNodes.has(node.nodeId);
                        const status = online ? '🟢' : '⚫';
                        trustedList += `${status} ${node.alias || node.fingerprint.substring(0, 8)}\n`;
                        trustedList += `   Trust: ${node.trustLevel} | Method: ${node.verificationMethod}\n`;
                        trustedList += `   Last seen: ${new Date(node.lastSeen).toLocaleDateString()}\n\n`;
                    });
                    return trustedList;

                case 'security':
                    if (args.length === 0) {
                        return 'Usage: security <node_id>';
                    }
                    
                    const securityTarget = args[0];
                    const securityNode = Array.from(discoveredNodes.values()).find(
                        n => n.id.includes(securityTarget) || n.name?.includes(securityTarget)
                    );
                    
                    if (!securityNode) {
                        return `Node not found: ${securityTarget}`;
                    }
                    
                    const secInfo = getNodeSecurityInfo(securityNode.id);
                    if (!secInfo) {
                        return 'No security info available';
                    }
                    
                    return `SECURITY INFO: ${securityNode.name || securityNode.id.substring(0, 8)}

Protocol:     v${securityNode.protocolVersion}
Verified:     ${secInfo.verified ? '✓' : '✗'}
Trusted:      ${secInfo.trusted ? '✓' : '✗'}
Session:      ${secInfo.sessionActive ? 'Active' : 'None'}
Chain intact: ${secInfo.messageChainIntact ? 'Yes' : 'BROKEN'}
Public key:   ${secInfo.publicKey ? secInfo.publicKey.substring(0, 16) + '...' : 'Unknown'}`;

                case 'nodes':
                case 'peers':
                    if (discoveredNodes.size === 0) {
                        return 'No nodes discovered';
                    }
                    
                    let nodeList = `DISCOVERED NODES (${discoveredNodes.size})\n\n`;
                    discoveredNodes.forEach((node) => {
                        const connected = connectedNodes.has(node.id);
                        const trusted = trustedNodes.has(node.id);
                        const session = activeSessions.has(node.id);
                        
                        const icons = [];
                        if (connected) icons.push('🔗');
                        if (trusted) icons.push('✓');
                        if (session) icons.push('🔒');
                        if (node.protocolVersion >= 2.1) icons.push('v2.1');
                        
                        const status = icons.join(' ');
                        nodeList += `${status} ${node.name || node.id.substring(0, 8)} | ${node.rssi || -100}dBm\n`;
                    });
                    
                    nodeList += `\n🔗=Connected ✓=Trusted 🔒=Secure v2.1=Protocol`;
                    return nodeList;

                case 'status':
                    const sessionCount = activeSessions.size;
                    const trustedCount = trustedNodes.size;
                    
                    return `SYSTEM STATUS

Protocol:     v${protocolVersion}
Network:      ${isScanning ? 'Active' : 'Inactive'}
Discovered:   ${discoveredNodes.size} nodes
Connected:    ${connectedNodes.size} nodes
Sessions:     ${sessionCount} active
Trusted:      ${trustedCount} nodes
Messages:     ${messages.length} total
Identity:     ${keyPair?.getFingerprint().substring(0, 16) || 'Unknown'}
Alias:        ${alias}`;

                case 'stats':
                    return `NETWORK STATISTICS

Nodes:        ${networkStats.totalNodes} discovered
Active:       ${networkStats.activeNodes} connected
Trusted:      ${trustedNodes.size} verified

MESSAGES
Sent:         ${networkStats.messagesSent}
Received:     ${networkStats.messagesReceived}
Relayed:      ${networkStats.messagesRelayed}
Dropped:      ${networkStats.messagesDropped}
Success rate: ${(networkStats.deliverySuccessRate * 100).toFixed(1)}%
Avg hops:     ${networkStats.averageHopCount.toFixed(1)}

DATA
Transmitted:  ${(networkStats.bytesTransmitted / 1024).toFixed(1)}KB
Received:     ${(networkStats.bytesReceived / 1024).toFixed(1)}KB
Throughput:   ${(networkStats.averageThroughput / 1024).toFixed(1)}KB/s`;

                case 'logs':
                    const category = args[0]?.toUpperCase() as SystemLog['category'];
                    const logsToShow = category 
                        ? systemLogs.filter(l => l.category === category)
                        : systemLogs;
                    
                    return logsToShow.slice(-15).map(log => {
                        const time = new Date(log.timestamp).toLocaleTimeString();
                        const icon = log.level === 'ERROR' ? '❌' : 
                                   log.level === 'WARN' ? '⚠️' :
                                   log.level === 'SUCCESS' ? '✅' :
                                   log.level === 'SECURITY' ? '🔒' : '•';
                        return `[${time}] ${icon} ${log.message}`;
                    }).join('\n');

                case 'export':
                    if (args.length === 0) {
                        return 'Usage: export <messages|trusted|logs>';
                    }
                    
                    switch (args[0]) {
                        case 'messages':
                            const msgExport = await exportMessages();
                            // In real app, copy to clipboard
                            return `✓ Exported ${messages.length} messages`;
                        case 'trusted':
                            const trustedExport = await exportTrustedNodes();
                            return `✓ Exported ${trustedNodes.size} trusted nodes`;
                        case 'logs':
                            const logsExport = JSON.stringify(systemLogs, null, 2);
                            return `✓ Exported ${systemLogs.length} logs`;
                        default:
                            return 'Unknown export type';
                    }

                // Include all original commands...
                case 'scan':
                    if (isScanning) return 'Already scanning';
                    await startScanning();
                    return '✓ Mesh network started';

                case 'stop':
                    if (!isScanning) return 'Network already stopped';
                    await stopScanning();
                    return '✓ Network stopped';

                case 'send':
                case 'broadcast':
                    if (args.length === 0) {
                        return 'Usage: send <message>';
                    }
                    const broadcastMsg = args.join(' ');
                    await sendMessage(broadcastMsg, undefined, MessageType.BROADCAST);
                    return `✓ Broadcast sent: "${broadcastMsg}"`;

                case 'dm':
                case 'direct':
                    if (args.length < 2) {
                        return 'Usage: dm <node_id> <message>';
                    }
                    
                    const dmTarget = args[0];
                    const dmMessage = args.slice(1).join(' ');
                    
                    const dmNode = Array.from(discoveredNodes.values()).find(
                        n => n.id.includes(dmTarget) || n.name?.includes(dmTarget)
                    );
                    
                    if (!dmNode) {
                        return `Node not found: ${dmTarget}`;
                    }
                    
                    await sendMessage(dmMessage, dmNode.id, MessageType.DIRECT);
                    return `✓ Sent to ${dmNode.name || dmNode.id.substring(0, 8)}: "${dmMessage}"`;

                case 'messages':
                    if (messages.length === 0) {
                        return 'No messages';
                    }
                    
                    return messages.slice(-10).map(msg => {
                        const time = new Date(msg.timestamp).toLocaleTimeString();
                        const direction = msg.isIncoming ? '←' : '→';
                        const verified = msg.verified ? '✓' : '';
                        return `[${time}] ${direction} ${verified} ${msg.content}`;
                    }).join('\n');

                case 'clear':
                    await clearMessages();
                    return '✓ Messages cleared';

                case 'identity':
                case 'id':
                    if (!keyPair) {
                        return 'No identity loaded';
                    }
                    return `NODE IDENTITY
Protocol:    v${protocolVersion}
Fingerprint: ${keyPair.getFingerprint()}
Short ID:    ${keyPair.getShortFingerprint()}
Alias:       ${alias}`;

                case 'alias':
                    if (args.length === 0) {
                        return `Current alias: ${alias}`;
                    }
                    const newAlias = args.join(' ');
                    setAlias(newAlias);
                    await AsyncStorage.setItem(STORAGE_KEYS.ALIAS, newAlias);
                    return `✓ Alias set to: ${newAlias}`;

                case 'refresh':
                    await refreshNetwork();
                    return '✓ Network refreshed';

                case 'connect':
                    if (args.length === 0) {
                        return 'Usage: connect <node_id>';
                    }
                    
                    const connectTarget = args[0];
                    const nodeToConnect = Array.from(discoveredNodes.values()).find(
                        n => n.id.includes(connectTarget) || n.name?.includes(connectTarget)
                    );
                    
                    if (!nodeToConnect) {
                        return `Node not found: ${connectTarget}`;
                    }
                    
                    await connectToNode(nodeToConnect.id);
                    return `✓ Connected to ${nodeToConnect.name || nodeToConnect.id.substring(0, 8)}`;

                case 'disconnect':
                    if (args.length === 0 || connectedNodes.size === 0) {
                        return 'No connected nodes';
                    }
                    
                    const disconnectTarget = args[0];
                    const nodeToDisconnect = Array.from(connectedNodes.values()).find(
                        n => n.id.includes(disconnectTarget) || n.name?.includes(disconnectTarget)
                    );
                    
                    if (nodeToDisconnect) {
                        await disconnectFromNode(nodeToDisconnect.id);
                        return `✓ Disconnected from ${nodeToDisconnect.name || nodeToDisconnect.id.substring(0, 8)}`;
                    }
                    
                    return 'Node not found';

                default:
                    return `Unknown command: ${cmd}\nType 'help' for available commands`;
            }
        } catch (error: any) {
            addSystemLog('ERROR', `Command failed: ${cmd}`, 'SYSTEM', error);
            return `Error: ${error.message || 'Command execution failed'}`;
        }
    }, [
        isScanning, discoveredNodes, connectedNodes, trustedNodes, activeSessions, 
        messages, systemLogs, networkStats, keyPair, alias, bleManager, protocolVersion,
        startScanning, stopScanning, connectToNode, disconnectFromNode, 
        sendMessage, clearMessages, refreshNetwork, verifyNode, trustNode, untrustNode,
        exportMessages, exportTrustedNodes, getNodeSecurityInfo, addSystemLog, setAlias
    ]);

    // Load stored data
    const loadStoredData = useCallback(async () => {
        try {
            const [storedMessages, storedStats, storedLogs, storedAlias, storedTrusted] = await Promise.all([
                AsyncStorage.getItem(STORAGE_KEYS.MESSAGES),
                AsyncStorage.getItem(STORAGE_KEYS.NETWORK_STATS),
                AsyncStorage.getItem(STORAGE_KEYS.SYSTEM_LOGS),
                AsyncStorage.getItem(STORAGE_KEYS.ALIAS),
                AsyncStorage.getItem(STORAGE_KEYS.TRUSTED_NODES),
            ]);

            if (storedMessages) {
                setMessages(JSON.parse(storedMessages));
            }

            if (storedStats) {
                setNetworkStats(JSON.parse(storedStats));
            }

            if (storedLogs) {
                setSystemLogs(JSON.parse(storedLogs).slice(-100));
            }

            if (storedAlias) {
                setAlias(storedAlias);
            }

            if (storedTrusted) {
                const nodes = JSON.parse(storedTrusted) as TrustedNode[];
                setTrustedNodes(new Map(nodes.map(n => [n.nodeId, n])));
            }
        } catch (error) {
            addSystemLog('WARN', 'Failed to load stored data', 'SYSTEM', error);
        }
    }, [addSystemLog]);

    // Initialize BLE and load stored data
    useEffect(() => {
        const initializeGhostComm = async () => {
            try {
                addSystemLog('INFO', 'Initializing GhostComm...', 'SYSTEM');

                // Load or generate keypair
                let keys: IGhostKeyPair;
                const storedKeys = await AsyncStorage.getItem(STORAGE_KEYS.KEYPAIR);

                if (storedKeys) {
                    addSystemLog('INFO', 'Loading existing keypair', 'SYSTEM');
                    const parsed = JSON.parse(storedKeys);
                    keys = GhostKeyPair.fromExported(parsed);
                } else {
                    addSystemLog('INFO', 'Generating new keypair', 'SYSTEM');
                    keys = new GhostKeyPair();
                    const exported = keys.exportKeys();
                    await AsyncStorage.setItem(STORAGE_KEYS.KEYPAIR, JSON.stringify(exported));
                }

                setKeyPair(keys);
                addSystemLog('SUCCESS', `Node ID: ${keys.getFingerprint().substring(0, 16)}...`, 'SYSTEM');

                // Create and initialize BLE manager with Protocol v2.1
                const manager = new ReactNativeBLEManager(keys);
                setBleManager(manager);

                // Set up event listeners
                manager.onEvent(handleBLEEvent);

                manager.onDiscovery((node: BLENode) => {
                    handleNodeDiscovered(node);
                });

                manager.onMessage(async (message: BLEMessage, node: BLENode, session: BLESession, verificationResult: any) => {
                    handleMessageReceived(message, node.id, verificationResult);
                });

                // React Native specific events
                manager.onRNEvent('initialized', () => {
                    addSystemLog('SUCCESS', `BLE Manager ready (Protocol v${protocolVersion})`, 'SYSTEM');
                });

                manager.onRNEvent('error', (data: any) => {
                    addSystemLog('ERROR', `BLE Error: ${data.error}`, 'SYSTEM');
                });

                manager.onRNEvent('bleStateChanged', (data: any) => {
                    addSystemLog('INFO', `BLE state: ${data.currentState}`, 'SYSTEM');
                });

                // Initialize manager
                await manager.initialize();

                // Load stored data
                await loadStoredData();

                setIsInitialized(true);
                addSystemLog('SUCCESS', `GhostComm ready (Protocol v${protocolVersion})`, 'SYSTEM');

            } catch (error) {
                addSystemLog('ERROR', 'Failed to initialize', 'SYSTEM', error);
            }
        };

        initializeGhostComm();
    }, []); // Only run once on mount

    // Save data periodically
    useEffect(() => {
        if (messages.length > 0) {
            AsyncStorage.setItem(STORAGE_KEYS.MESSAGES, JSON.stringify(messages.slice(-200))).catch(console.error);
        }
    }, [messages]);

    useEffect(() => {
        AsyncStorage.setItem(STORAGE_KEYS.NETWORK_STATS, JSON.stringify(networkStats)).catch(console.error);
    }, [networkStats]);

    useEffect(() => {
        if (systemLogs.length > 0) {
            AsyncStorage.setItem(STORAGE_KEYS.SYSTEM_LOGS, JSON.stringify(systemLogs.slice(-100))).catch(console.error);
        }
    }, [systemLogs]);

    const value: GhostCommContextType = {
        bleManager,
        keyPair,
        messages,
        discoveredNodes,
        connectedNodes,
        trustedNodes,
        activeSessions,
        networkStats,
        systemLogs,
        isScanning,
        isAdvertising,
        isInitialized,
        protocolVersion,
        sendMessage,
        verifyNode,
        trustNode,
        untrustNode,
        exportTrustedNodes,
        importTrustedNodes,
        clearMessages,
        clearLogs,
        exportMessages,
        startScanning,
        stopScanning,
        startAdvertising,
        stopAdvertising,
        connectToNode,
        disconnectFromNode,
        refreshNetwork,
        addSystemLog,
        executeCommand,
        getNodeSecurityInfo
    };

    return (
        <GhostCommContext.Provider value={value}>
            {children}
        </GhostCommContext.Provider>
    );
};