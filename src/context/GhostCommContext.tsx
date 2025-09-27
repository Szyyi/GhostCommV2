/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * GHOSTCOMM PROTOCOL v2.1 REACT CONTEXT PROVIDER AND STATE MANAGEMENT ENGINE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Comprehensive React Context implementation providing centralized state management
 * for GhostComm Protocol v2.1 mesh networking with enterprise-grade React Native
 * integration. Orchestrates BLE mesh operations, cryptographic identity management,
 * message handling, and security verification for production deployments.
 * 
 * Author: LCpl 'Si' Procak
 * Protocol: GhostComm v2.1 with Ed25519/X25519 cryptographic security
 * Platform: React Native cross-platform mobile mesh networking
 * 
 * COMPREHENSIVE CONTEXT ARCHITECTURE:
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Enterprise State Management:
 * • Centralized React Context with comprehensive mesh network state orchestration
 * • Real-time BLE node discovery and connection management with live state updates
 * • Message delivery tracking with Protocol v2.1 cryptographic verification chains
 * • Trust relationship management with enterprise-grade security verification
 * 
 * Protocol v2.1 Integration Features:
 * • Ed25519/X25519 cryptographic key pair management with secure identity handling
 * • Message chain integrity verification with hash-based sequence validation
 * • Node verification and trust establishment with multiple authentication methods
 * • Secure session management with encrypted communication and state preservation
 * 
 * React Native Mobile Optimization:
 * • AsyncStorage integration with persistent state management and data recovery
 * • Background operation support with app lifecycle integration and state preservation
 * • Real-time event handling with efficient React state updates and rendering optimization
 * • Performance monitoring with comprehensive metrics collection and analysis
 * 
 * PRODUCTION DEPLOYMENT FEATURES:
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Enterprise Reliability:
 * • Robust error handling with graceful degradation and recovery mechanisms
 * • Data persistence with comprehensive backup and restoration capabilities
 * • Network resilience with connection retry and failover strategies
 * • Security audit integration with detailed logging and verification tracking
 * 
 * Development and Debugging:
 * • Comprehensive system logging with categorized event tracking and analysis
 * • Command-line interface integration with full network management capabilities
 * • Performance analytics with real-time metrics and optimization insights
 * • Security monitoring with verification status and trust relationship tracking
 */

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

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * PROTOCOL v2.1 ENHANCED SYSTEM LOGGING AND EVENT TRACKING INTERFACES
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Comprehensive system logging interface with Protocol v2.1 event categorization
 * and security audit integration. Provides detailed event tracking with
 * structured data correlation and production monitoring capabilities.
 * 
 * Author: LCpl 'Si' Procak
 */

// Enhanced system log with Protocol v2.1 events
export interface SystemLog {
    /** Unique log entry identifier for correlation and tracking */
    id: string;
    /** Unix timestamp for chronological ordering and time-based analysis */
    timestamp: number;
    /** Log severity level for filtering and alerting systems */
    level: 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'DEBUG' | 'SECURITY';
    /** Event category for systematic organization and audit trail management */
    category?: 'NETWORK' | 'MESSAGE' | 'SECURITY' | 'SYSTEM' | 'PROTOCOL';
    /** Human-readable log message with contextual information */
    message: string;
    /** Optional structured data for detailed analysis and debugging correlation */
    data?: any;
}

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * PROTOCOL v2.1 ENHANCED MESSAGE STORAGE AND VERIFICATION INTERFACE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Comprehensive message storage interface with Protocol v2.1 cryptographic
 * verification, delivery tracking, and chain integrity management for
 * enterprise-grade message handling and audit capabilities.
 * 
 * Author: LCpl 'Si' Procak
 */

// Enhanced stored message with Protocol v2.1 fields
export interface StoredMessage {
    /** Unique message identifier for tracking and correlation across the system */
    id: string;
    /** Message content (encrypted or plaintext depending on context) */
    content: string;
    /** Protocol v2.1 message type classification for routing and handling */
    type: MessageType;
    /** Comprehensive message lifecycle status with Protocol v2.1 verification states */
    status: 'QUEUED' | 'SIGNING' | 'TRANSMITTING' | 'SENT' | 'DELIVERED' | 'FAILED' | 'TIMEOUT' | 'VERIFIED';
    /** Unix timestamp for chronological ordering and delivery analysis */
    timestamp: number;
    /** Direction flag for message flow analysis and UI presentation */
    isIncoming: boolean;
    /** Ed25519 sender fingerprint for cryptographic identity verification */
    senderFingerprint?: string;
    /** Ed25519 recipient fingerprint for targeted delivery and encryption */
    recipientFingerprint?: string;
    
    // Protocol v2.1 cryptographic verification fields
    /** SHA-256 message hash for integrity verification and chain linking */
    messageHash?: string;
    /** Previous message hash for chain integrity and replay protection */
    previousMessageHash?: string;
    /** Monotonic sequence number for ordering and duplicate detection */
    sequenceNumber?: number;
    /** Cryptographic signature verification status for authenticity confirmation */
    verified?: boolean;
    /** Detailed verification failure reason for security audit and debugging */
    verificationError?: string;
    
    // Enhanced delivery tracking and mesh routing analytics
    /** Delivery attempt counter for retry logic and success rate analysis */
    attempts?: number;
    /** Last attempt timestamp for retry scheduling and timeout management */
    lastAttempt?: number;
    /** Mesh network hop count for routing efficiency analysis */
    hopCount?: number;
    /** Complete relay path for network topology analysis and optimization */
    relayPath?: string[];
}

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * PROTOCOL v2.1 NODE TRUST AND VERIFICATION MANAGEMENT INTERFACE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Comprehensive trust relationship management with multiple verification
 * methods, trust levels, and persistent relationship tracking for
 * enterprise-grade security and identity management.
 * 
 * Author: LCpl 'Si' Procak
 */

// Node trust management
export interface TrustedNode {
    /** Unique node identifier for consistent tracking across sessions */
    nodeId: string;
    /** Ed25519 public key fingerprint for cryptographic identity verification */
    fingerprint: string;
    /** User-assigned human-readable alias for simplified node identification */
    alias?: string;
    /** Verification method used for trust establishment and security auditing */
    verificationMethod: VerificationMethod;
    /** Unix timestamp of trust establishment for relationship lifecycle tracking */
    verifiedAt: number;
    /** Hierarchical trust level for graduated security and access control */
    trustLevel: 'VERIFIED' | 'TRUSTED' | 'KNOWN';
    /** Raw Ed25519 public key for advanced cryptographic operations and verification */
    publicKey?: string;
    /** Last activity timestamp for relationship freshness and cleanup management */
    lastSeen: number;
}

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * COMPREHENSIVE GHOSTCOMM CONTEXT INTERFACE WITH PROTOCOL v2.1 INTEGRATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Complete React Context interface providing centralized access to all
 * GhostComm Protocol v2.1 functionality including mesh networking, security,
 * message handling, and enterprise management capabilities.
 * 
 * Author: LCpl 'Si' Procak
 */

// Enhanced context type with Protocol v2.1 features
interface GhostCommContextType {
    // Core Protocol v2.1 Management Objects
    /** React Native BLE mesh network manager with Protocol v2.1 integration */
    bleManager: ReactNativeBLEManager | null;
    /** Ed25519/X25519 cryptographic key pair for identity and encryption */
    keyPair: IGhostKeyPair | null;
    
    // Comprehensive Network and Message State Management
    /** Complete message history with Protocol v2.1 verification and delivery tracking */
    messages: StoredMessage[];
    /** Real-time discovered nodes map with Protocol v2.1 capability detection */
    discoveredNodes: Map<string, BLENode>;
    /** Active connection pool with connection state and health monitoring */
    connectedNodes: Map<string, BLENode>;
    /** Verified trust relationships with hierarchical security levels */
    trustedNodes: Map<string, TrustedNode>;
    /** Active encrypted sessions with Protocol v2.1 security contexts */
    activeSessions: Map<string, BLESession>;
    /** Comprehensive network performance metrics and analytics */
    networkStats: NetworkStats;
    /** Categorized system logs with security audit and debugging information */
    systemLogs: SystemLog[];
    
    // Real-time System Status and Configuration
    /** BLE scanning active status for UI state management and optimization */
    isScanning: boolean;
    /** BLE advertising active status for network participation indication */
    isAdvertising: boolean;
    /** System initialization completion status for feature availability gating */
    isInitialized: boolean;
    /** Current Protocol version for compatibility and feature detection */
    protocolVersion: string;
    
    // Protocol v2.1 Enhanced Messaging and Security Actions
    /** Send encrypted message with Protocol v2.1 signing and delivery tracking */
    sendMessage: (content: string, recipientId?: string, type?: MessageType, priority?: MessagePriority) => Promise<void>;
    /** Verify node identity using multiple cryptographic methods and security protocols */
    verifyNode: (nodeId: string, method: VerificationMethod, verificationData?: string) => Promise<VerificationResult>;
    /** Establish trusted relationship with hierarchical security levels and alias management */
    trustNode: (nodeId: string, alias?: string) => Promise<void>;
    /** Remove trust relationship with secure cleanup and relationship termination */
    untrustNode: (nodeId: string) => Promise<void>;
    /** Export trusted nodes for backup and cross-device synchronization */
    exportTrustedNodes: () => Promise<string>;
    /** Import trusted nodes with validation and conflict resolution */
    importTrustedNodes: (data: string) => Promise<void>;
    
    // Comprehensive Network and Connection Management
    /** Start BLE mesh network scanning with Protocol v2.1 discovery optimization */
    startScanning: () => Promise<void>;
    /** Stop network scanning with graceful connection preservation */
    stopScanning: () => Promise<void>;
    /** Start BLE advertising with Protocol v2.1 capability announcement */
    startAdvertising: () => Promise<void>;
    /** Stop advertising with network participation cleanup */
    stopAdvertising: () => Promise<void>;
    /** Establish secure connection with Protocol v2.1 authentication and session setup */
    connectToNode: (nodeId: string) => Promise<void>;
    /** Gracefully disconnect with session cleanup and state preservation */
    disconnectFromNode: (nodeId: string) => Promise<void>;
    /** Refresh network state with complete rediscovery and connection validation */
    refreshNetwork: () => Promise<void>;
    
    // Enterprise Data Management and Persistence
    /** Clear all stored messages with secure deletion and storage cleanup */
    clearMessages: () => Promise<void>;
    /** Clear system logs with immediate memory cleanup and storage optimization */
    clearLogs: () => void;
    /** Export complete message history for backup and analysis purposes */
    exportMessages: () => Promise<string>;
    
    // Advanced Command-Line Interface Integration
    /** Execute administrative commands with comprehensive network and security management */
    executeCommand: (command: string) => Promise<string>;
    
    // Comprehensive System Logging and Audit Trail
    /** Add categorized system log entry with structured data and security correlation */
    addSystemLog: (level: SystemLog['level'], message: string, category?: SystemLog['category'], data?: any) => void;
    
    // Protocol v2.1 Security and Trust Assessment
    /** Get comprehensive node security information including verification status and session details */
    getNodeSecurityInfo: (nodeId: string) => {
        /** Cryptographic identity verification status using Protocol v2.1 methods */
        verified: boolean;
        /** User-established trust relationship status for access control */
        trusted: boolean;
        /** Ed25519 public key for advanced cryptographic operations */
        publicKey?: string;
        /** Verification method used for trust establishment and audit trail */
        verificationMethod?: VerificationMethod;
        /** Active encrypted session status for real-time security assessment */
        sessionActive: boolean;
        /** Message chain integrity status for replay protection verification */
        messageChainIntact: boolean;
    } | null;
}

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * REACT CONTEXT CREATION AND CUSTOM HOOK IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * React Context creation with TypeScript safety and custom hook for
 * convenient access with automatic provider validation and error handling.
 * 
 * Author: LCpl 'Si' Procak
 */

const GhostCommContext = createContext<GhostCommContextType | undefined>(undefined);

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * CUSTOM HOOK FOR GHOSTCOMM CONTEXT ACCESS WITH VALIDATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Provides safe access to GhostComm context with automatic provider validation
 * and descriptive error messaging for development debugging and production
 * reliability. Ensures context is only used within proper provider scope.
 * 
 * @throws Error if used outside GhostCommProvider
 * @returns Complete GhostCommContextType with all Protocol v2.1 functionality
 */
export const useGhostComm = () => {
    const context = useContext(GhostCommContext);
    if (!context) {
        throw new Error('useGhostComm must be used within GhostCommProvider');
    }
    return context;
};

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * REACT NATIVE ASYNCSTORAGE KEY DEFINITIONS FOR DATA PERSISTENCE
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Centralized storage key definitions for consistent data persistence across
 * app lifecycle events, ensuring reliable state restoration and data integrity
 * with proper key namespacing for GhostComm Protocol v2.1 implementation.
 * 
 * Author: LCpl 'Si' Procak
 */

const STORAGE_KEYS = {
    /** Complete message history with Protocol v2.1 verification data */
    MESSAGES: '@ghostcomm_messages',
    /** Network performance statistics and analytics data */
    NETWORK_STATS: '@ghostcomm_network_stats',
    /** System logs with categorized events and security audit trail */
    SYSTEM_LOGS: '@ghostcomm_system_logs',
    /** Ed25519/X25519 cryptographic key pair for identity management */
    KEYPAIR: '@ghostcomm_keypair',
    /** User-assigned node alias for human-readable identification */
    ALIAS: '@ghostcomm_alias',
    /** Verified trust relationships with security metadata */
    TRUSTED_NODES: '@ghostcomm_trusted_nodes',
    /** Message chain tracking for Protocol v2.1 integrity verification */
    MESSAGE_CHAINS: '@ghostcomm_message_chains',
};

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * GHOSTCOMM PROTOCOL v2.1 CONTEXT PROVIDER IMPLEMENTATION
 * ═══════════════════════════════════════════════════════════════════════════════
 * 
 * Comprehensive React Context Provider implementing centralized state management
 * for GhostComm Protocol v2.1 mesh networking with enterprise-grade security,
 * persistent data management, and real-time network orchestration.
 * 
 * Manages complete application lifecycle including BLE network initialization,
 * cryptographic identity management, message handling with verification,
 * trust relationships, and comprehensive system monitoring.
 * 
 * Author: LCpl 'Si' Procak
 */

export const GhostCommProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    // Core Protocol v2.1 System Components
    const [bleManager, setBleManager] = useState<ReactNativeBLEManager | null>(null);
    const [keyPair, setKeyPair] = useState<IGhostKeyPair | null>(null);
    
    // Comprehensive Message and Network State Management
    const [messages, setMessages] = useState<StoredMessage[]>([]);
    const [discoveredNodes, setDiscoveredNodes] = useState<Map<string, BLENode>>(new Map());
    const [connectedNodes, setConnectedNodes] = useState<Map<string, BLENode>>(new Map());
    const [trustedNodes, setTrustedNodes] = useState<Map<string, TrustedNode>>(new Map());
    const [activeSessions, setActiveSessions] = useState<Map<string, BLESession>>(new Map());
    const [systemLogs, setSystemLogs] = useState<SystemLog[]>([]);
    
    // System Status and Configuration Management
    const [isInitialized, setIsInitialized] = useState(false);
    const [isScanning, setIsScanning] = useState(false);
    const [isAdvertising, setIsAdvertising] = useState(false);
    const [alias, setAlias] = useState('anonymous');
    const protocolVersion = `${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}.1`;

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * PROTOCOL v2.1 MESSAGE CHAIN INTEGRITY TRACKING SYSTEM
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Advanced message chain tracking with cryptographic hash linking for
     * replay protection, sequence validation, and integrity verification.
     * Maintains per-node chain state for comprehensive security monitoring.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Message chain tracking for Protocol v2.1
    const messageChains = useRef<Map<string, {
        /** Last sent message hash for chain continuity verification */
        lastSentHash: string;
        /** Last received message hash for integrity confirmation */
        lastReceivedHash: string;
        /** Monotonic sent sequence counter for ordering validation */
        sentSequence: number;
        /** Monotonic received sequence counter for duplicate detection */
        receivedSequence: number;
        /** Chain break counter for security monitoring and trust assessment */
        chainBreaks: number;
    }>>(new Map());

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * COMPREHENSIVE NETWORK PERFORMANCE METRICS AND ANALYTICS SYSTEM
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Real-time network performance monitoring with comprehensive statistics
     * for mesh efficiency analysis, optimization insights, and production
     * deployment monitoring with enterprise-grade analytics capabilities.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    const [networkStats, setNetworkStats] = useState<NetworkStats>({
        totalNodes: 0,              // Total nodes discovered in network lifetime
        activeNodes: 0,             // Currently connected and responsive nodes
        trustedNodes: 0,            // Verified trusted relationships count
        blockedNodes: 0,            // Security-blocked or blacklisted nodes
        totalConnections: 0,        // Cumulative connection attempts made
        messagesSent: 0,            // Total messages transmitted by this node
        messagesReceived: 0,        // Total messages received and processed
        messagesRelayed: 0,         // Messages forwarded through mesh routing
        messagesDropped: 0,         // Failed or undeliverable messages count
        averageHopCount: 0,         // Mean mesh routing distance for efficiency
        averageLatency: 0,          // Mean message delivery time in milliseconds
        deliverySuccessRate: 1,     // Success rate percentage for reliability
        networkDensity: 0,          // Node connectivity ratio for topology
        networkReachability: 0,     // Network coverage percentage assessment
        bytesTransmitted: 0,        // Total data transmitted for bandwidth
        bytesReceived: 0,           // Total data received for analysis
        averageThroughput: 0,       // Mean data rate in bytes per second
        uptime: Date.now(),         // System initialization timestamp
        lastUpdated: Date.now()     // Last statistics update timestamp
    });

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * ENHANCED SYSTEM LOGGING WITH CATEGORIZATION AND AUDIT INTEGRATION
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive logging system with structured categorization, automatic
     * rotation, and integration with security audit trails for production
     * monitoring and debugging capabilities with Protocol v2.1 event tracking.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Enhanced logging with categories
    const addSystemLog = useCallback((
        level: SystemLog['level'],
        message: string,
        category: SystemLog['category'] = 'SYSTEM',
        data?: any
    ) => {
        // Create structured log entry with unique identification and metadata
        const log: SystemLog = {
            id: `log_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            timestamp: Date.now(),
            level,
            category,
            message,
            data,
        };

        // Update log state with automatic rotation for memory management
        setSystemLogs(prev => {
            const updated = [...prev, log];
            // Keep only last 200 logs for Protocol v2.1 debugging and memory optimization
            if (updated.length > 200) {
                return updated.slice(-200);
            }
            return updated;
        });

        // Forward to debug system for development console integration
        debug.info(`[${level}/${category}] ${message}`, data);
    }, []);

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * PROTOCOL v2.1 NODE DISCOVERY AND VERIFICATION HANDLER
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive node discovery processing with Protocol v2.1 capability
     * detection, trust relationship validation, and network statistics
     * integration for enhanced mesh network management and security.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Enhanced node discovery with Protocol v2.1 verification
    const handleNodeDiscovered = useCallback((node: BLENode) => {
        // Update discovered nodes map with real-time node information
        setDiscoveredNodes(prev => {
            const updated = new Map(prev);
            updated.set(node.id, node);
            return updated;
        });

        // Update network statistics with discovery metrics for analytics
        setNetworkStats(prev => ({
            ...prev,
            totalNodes: prev.totalNodes + 1,
            lastUpdated: Date.now()
        }));

        // Protocol v2.1 capability detection and compatibility logging
        if (node.protocolVersion >= 2.1) {
            addSystemLog('INFO', `Discovered v${node.protocolVersion} node: ${node.name || node.id.substring(0, 8)}`, 'NETWORK');
        } else {
            addSystemLog('WARN', `Legacy node discovered: ${node.name || node.id.substring(0, 8)} (v${node.protocolVersion})`, 'NETWORK');
        }

        // Trust relationship validation and security status logging
        const trusted = trustedNodes.get(node.id);
        if (trusted) {
            addSystemLog('SUCCESS', `Trusted node online: ${trusted.alias || node.id.substring(0, 8)}`, 'SECURITY');
        }
    }, [trustedNodes, addSystemLog]);

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * PROTOCOL v2.1 CONNECTION ESTABLISHMENT AND SESSION MANAGEMENT HANDLER
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive connection handling with Protocol v2.1 secure session
     * establishment, connection pool management, and network statistics
     * integration for enterprise-grade mesh networking reliability.
     * 
     * Author: LCpl 'Si' Procak
     */
    
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

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * PROTOCOL v2.1 MESSAGE RECEPTION AND VERIFICATION PROCESSING ENGINE
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive message handling with Protocol v2.1 cryptographic verification,
     * chain integrity validation, message storage, and network analytics
     * integration for secure and reliable mesh communication processing.
     * 
     * Processes incoming messages with complete verification chain including
     * signature validation, sequence verification, and chain integrity checking
     * for enterprise-grade security and audit compliance.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Enhanced message handling with Protocol v2.1 verification
    const handleMessageReceived = useCallback((
        message: BLEMessage,
        fromNodeId?: string,
        verificationResult?: { verified: boolean; error?: string }
    ) => {
        // Create comprehensive message record with Protocol v2.1 metadata
        const newMessage: StoredMessage = {
            /** Generate unique message identifier for tracking and correlation */
            id: `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            /** Handle encrypted content display for UI presentation safety */
            content: typeof message === 'object' && message.encryptedPayload 
                ? '[Encrypted Message]' 
                : message.toString(),
            /** Default to direct message type for incoming messages */
            type: MessageType.DIRECT,
            /** Record reception timestamp for chronological ordering */
            timestamp: Date.now(),
            /** Set verification-based status for security audit compliance */
            status: verificationResult?.verified ? 'VERIFIED' : 'DELIVERED',
            /** Mark as incoming for message flow analysis and UI presentation */
            isIncoming: true,
            /** Record sender Ed25519 fingerprint for identity verification */
            senderFingerprint: fromNodeId,
            /** Record recipient fingerprint for message correlation and routing */
            recipientFingerprint: keyPair?.getFingerprint(),
            
            // Protocol v2.1 cryptographic and routing metadata
            /** SHA-256 message hash for integrity verification and chain linking */
            messageHash: message.messageHash,
            /** Previous message hash for chain integrity and replay protection */
            previousMessageHash: message.previousMessageHash,
            /** Monotonic sequence number for ordering and duplicate detection */
            sequenceNumber: message.sequenceNumber,
            /** Digital signature verification status for authenticity confirmation */
            verified: verificationResult?.verified,
            /** Detailed verification failure information for security analysis */
            verificationError: verificationResult?.error,
            /** Mesh routing hop count for network efficiency analysis */
            hopCount: message.hopCount,
            /** Complete relay path for topology analysis and optimization */
            relayPath: message.routePath
        };

        // Add message to state for UI display and storage persistence
        setMessages(prev => [...prev, newMessage]);

        // Protocol v2.1 message chain integrity tracking and validation
        if (fromNodeId) {
            // Retrieve or initialize message chain state for sender node
            const chain = messageChains.current.get(fromNodeId) || {
                lastSentHash: '',           // Last hash we sent to this node
                lastReceivedHash: '',       // Last hash we received from this node
                sentSequence: 0,            // Our outbound sequence counter
                receivedSequence: 0,        // Inbound sequence counter from this node
                chainBreaks: 0              // Security breach counter for monitoring
            };
            
            // Validate message chain continuity for replay protection
            if (chain.lastReceivedHash && message.previousMessageHash !== chain.lastReceivedHash) {
                // Detected chain break - potential replay attack or message loss
                chain.chainBreaks++;
                addSystemLog('WARN', `Message chain break from ${fromNodeId.substring(0, 8)} (${chain.chainBreaks} breaks)`, 'SECURITY');
            }
            
            // Update chain state with new message hash for future validation
            chain.lastReceivedHash = message.messageHash;
            // Update sequence tracking for ordering validation
            chain.receivedSequence = message.sequenceNumber;
            // Persist updated chain state for future message validation
            messageChains.current.set(fromNodeId, chain);
        }

        // Update comprehensive network statistics for performance monitoring
        setNetworkStats(prev => ({
            ...prev,
            /** Increment total received message counter */
            messagesReceived: prev.messagesReceived + 1,
            /** Track total bytes received for bandwidth analysis */
            bytesReceived: prev.bytesReceived + (newMessage.content?.length || 0),
            /** Calculate running average hop count for routing efficiency */
            averageHopCount: ((prev.averageHopCount * prev.messagesReceived) + (message.hopCount || 0)) / (prev.messagesReceived + 1),
            /** Update statistics timestamp for freshness tracking */
            lastUpdated: Date.now()
        }));

        // Comprehensive verification status logging for security audit
        if (verificationResult?.verified) {
            // Successfully verified message with valid Ed25519 signature
            addSystemLog('SUCCESS', `Verified message from ${fromNodeId?.substring(0, 8) || 'unknown'}`, 'MESSAGE');
        } else if (verificationResult?.error) {
            // Failed verification - potential security threat or corrupted message
            addSystemLog('SECURITY', `Unverified message from ${fromNodeId?.substring(0, 8)}: ${verificationResult.error}`, 'SECURITY');
        } else {
            // Informational message reception without verification context
            addSystemLog('INFO', `Message from ${fromNodeId?.substring(0, 8) || 'unknown'}`, 'MESSAGE');
        }
    }, [keyPair, addSystemLog]);

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * COMPREHENSIVE BLE EVENT HANDLER WITH PROTOCOL v2.1 EVENT PROCESSING
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Advanced event processing system handling all BLE mesh network events
     * including node discovery, connection management, message reception,
     * security verification, and error handling with Protocol v2.1 integration
     * for complete mesh network state management and coordination.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Enhanced BLE event handler with Protocol v2.1 events
    const handleBLEEvent = useCallback((event: BLEConnectionEvent | BLEMessageEvent | BLEDiscoveryEvent) => {
        // Comprehensive event type routing with Protocol v2.1 support
        switch (event.type) {
            // Node discovery and capability announcement events
            case 'node_discovered':
            case 'node_updated':
                const discEvent = event as BLEDiscoveryEvent;
                if (discEvent.node) {
                    // Process new or updated node with Protocol v2.1 capability detection
                    handleNodeDiscovered(discEvent.node);
                }
                break;

            // Protocol v2.1 cryptographic node verification completion
            case 'node_verified':
                const verifyEvent = event as BLEDiscoveryEvent;
                if (verifyEvent.node && verifyEvent.verificationResult) {
                    // Log successful cryptographic identity verification
                    addSystemLog('SUCCESS', `Node verified: ${verifyEvent.node.id.substring(0, 8)}`, 'SECURITY');
                }
                break;

            // Node disconnection and network topology updates
            case 'node_lost':
                const lostEvent = event as BLEDiscoveryEvent;
                if (lostEvent.node) {
                    // Remove from discovered nodes and update network state
                    setDiscoveredNodes(prev => {
                        const updated = new Map(prev);
                        updated.delete(lostEvent.node.id);
                        return updated;
                    });
                    addSystemLog('INFO', `Lost: ${lostEvent.node.id.substring(0, 8)}`, 'NETWORK');
                }
                break;

            // BLE connection establishment events
            case 'connected':
                const connEvent = event as BLEConnectionEvent;
                // Process new connection without session context
                handleNodeConnected(connEvent.nodeId);
                break;

            // Protocol v2.1 authentication and secure session establishment
            case 'authenticated':
            case 'session_established':
                const authEvent = event as BLEConnectionEvent;
                if (authEvent.session) {
                    // Process connection with established secure session context
                    handleNodeConnected(authEvent.nodeId, authEvent.session);
                }
                break;

            // Connection termination and cleanup events
            case 'disconnected':
                const disconnEvent = event as BLEConnectionEvent;
                // Process graceful disconnection with state cleanup
                handleNodeDisconnected(disconnEvent.nodeId);
                break;

            // Protocol v2.1 message reception with verification
            case 'message_received':
                const msgEvent = event as BLEMessageEvent;
                // Process incoming message with cryptographic verification result
                handleMessageReceived(
                    msgEvent.message,
                    msgEvent.fromNodeId,
                    msgEvent.verificationResult
                );
                break;

            // Message delivery confirmation events
            case 'message_acknowledged':
                const ackEvent = event as BLEMessageEvent;
                if (ackEvent.acknowledgment) {
                    // Process delivery acknowledgment for message status updates
                    handleMessageAcknowledged(
                        ackEvent.acknowledgment.messageId,
                        ackEvent.fromNodeId || ''
                    );
                }
                break;

            // Protocol v2.1 security breach detection
            case 'signature_verification_failed':
                const sigFailEvent = event as BLEMessageEvent;
                // Log critical security event with detailed error information
                addSystemLog('SECURITY', 
                    `Signature verification failed from ${sigFailEvent.fromNodeId?.substring(0, 8)}: ${sigFailEvent.verificationResult?.error}`,
                    'SECURITY'
                );
                break;

            // General error handling for system reliability
            case 'error':
                const errorEvent = event as BLEConnectionEvent;
                if (errorEvent.error) {
                    // Log system errors for debugging and monitoring
                    addSystemLog('ERROR', errorEvent.error.message, 'SYSTEM');
                }
                break;
        }
    }, [handleNodeDiscovered, handleNodeConnected, handleMessageReceived, addSystemLog]);

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * NODE DISCONNECTION AND SESSION CLEANUP HANDLER
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive disconnection processing with state cleanup, session
     * termination, and network statistics updates for reliable connection
     * management and resource cleanup in Protocol v2.1 mesh networking.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    const handleNodeDisconnected = useCallback((nodeId: string) => {
        // Remove from active connections map with immutable state update
        setConnectedNodes(prev => {
            const updated = new Map(prev);
            updated.delete(nodeId);
            return updated;
        });

        // Terminate any active Protocol v2.1 secure sessions
        setActiveSessions(prev => {
            const updated = new Map(prev);
            updated.delete(nodeId);
            return updated;
        });

        // Update network statistics with connection count adjustment
        setNetworkStats(prev => ({
            ...prev,
            /** Decrement active nodes with zero floor protection */
            activeNodes: Math.max(0, prev.activeNodes - 1),
            /** Update timestamp for statistics freshness tracking */
            lastUpdated: Date.now()
        }));

        // Log disconnection event for network monitoring and debugging
        addSystemLog('WARN', `Disconnected: ${nodeId.substring(0, 8)}`, 'NETWORK');
    }, [addSystemLog]);

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * MESSAGE DELIVERY ACKNOWLEDGMENT AND STATUS UPDATE HANDLER
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive message acknowledgment processing with delivery status
     * updates, network statistics correlation, and success rate calculation
     * for reliable message delivery tracking in Protocol v2.1 mesh networking.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    const handleMessageAcknowledged = useCallback((
    messageId: string,
    fromNodeId: string
    ): void => {
        // Log successful message acknowledgment for debugging and monitoring
        console.log(`✅ Message ${messageId} acknowledged by ${fromNodeId}`);
    
        // Update message status to DELIVERED with delivery timestamp
        setMessages(prev => 
            prev.map(msg => {
                // Match by internal ID or Protocol v2.1 message hash
                if (msg.id === messageId || msg.messageHash === messageId) {
                    return {
                        ...msg,
                        /** Mark as successfully delivered */
                        status: 'DELIVERED' as const,
                        /** Record delivery timestamp for analytics */
                        deliveredAt: Date.now()
                    };
                }
                return msg;
            })
        );
        
        // Update delivery success rate statistics for network performance monitoring
        setNetworkStats(prev => ({
            ...prev,
            /** Calculate running delivery success rate with bounded maximum */
            deliverySuccessRate: Math.min(
                1,
                (prev.deliverySuccessRate * prev.messagesSent + 1) / (prev.messagesSent + 1)
            ),
            /** Update statistics timestamp for freshness tracking */
            lastUpdated: Date.now()
        }));
        
        // Resolve node information for enhanced logging context
        const node = discoveredNodes.get(fromNodeId);
        const nodeName = node?.name || fromNodeId.substring(0, 8);
        
        // Log successful delivery with structured data for audit and monitoring
        addSystemLog(
            'SUCCESS',
            `Message delivered to ${nodeName}`,
            'MESSAGE',
            { messageId, fromNodeId }
        );
    }, [discoveredNodes, addSystemLog]);

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * PROTOCOL v2.1 NODE IDENTITY VERIFICATION AND CRYPTOGRAPHIC VALIDATION
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive node verification system supporting multiple cryptographic
     * methods including fingerprint validation, QR code verification, and
     * numeric challenges for secure identity establishment and trust building.
     * 
     * Author: LCpl 'Si' Procak
     */

    // Node verification with Protocol v2.1
    const verifyNode = useCallback(async (
        nodeId: string,
        method: VerificationMethod,
        verificationData?: string
    ): Promise<VerificationResult> => {
        // Validate BLE manager initialization for cryptographic operations
        if (!bleManager) {
            throw new Error('BLE Manager not initialized');
        }

        // Execute Protocol v2.1 cryptographic verification through BLE manager
        const result = await bleManager.verifyNode(nodeId, method, verificationData);
        
        // Log verification results for security audit and trust establishment
        if (result.verified) {
            // Successful verification - node identity confirmed
            addSystemLog('SUCCESS', `Node verified via ${method}: ${nodeId.substring(0, 8)}`, 'SECURITY');
        } else {
            // Verification failure - potential security risk or invalid method
            addSystemLog('WARN', `Verification failed for ${nodeId.substring(0, 8)}`, 'SECURITY');
        }

        return result;
    }, [bleManager, addSystemLog]);

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * TRUST RELATIONSHIP ESTABLISHMENT AND PERSISTENT STORAGE MANAGEMENT
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive trust management system with hierarchical trust levels,
     * persistent storage, and alias management for long-term relationship
     * tracking and secure mesh network operations with Protocol v2.1 integration.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Trust management
    const trustNode = useCallback(async (nodeId: string, alias?: string) => {
        // Validate node existence in discovered nodes map
        const node = discoveredNodes.get(nodeId);
        if (!node) {
            throw new Error('Node not found');
        }

        // Create comprehensive trusted node record with Protocol v2.1 metadata
        const trustedNode: TrustedNode = {
            /** Store node identifier for consistent tracking */
            nodeId,
            /** Record Ed25519 fingerprint for cryptographic identity */
            fingerprint: node.id,
            /** User-assigned alias for human-readable identification */
            alias,
            /** Verification method used for trust establishment */
            verificationMethod: node.verificationMethod || VerificationMethod.FINGERPRINT,
            /** Timestamp of trust establishment for relationship lifecycle */
            verifiedAt: Date.now(),
            /** Hierarchical trust level based on verification status */
            trustLevel: node.verificationStatus === VerificationStatus.VERIFIED ? 'VERIFIED' : 'KNOWN',
            /** Raw Ed25519 public key for advanced cryptographic operations */
            publicKey: node.identityKey ? Buffer.from(node.identityKey).toString('hex') : undefined,
            /** Activity timestamp for relationship freshness tracking */
            lastSeen: Date.now()
        };

        // Update trusted nodes state with immutable map update
        setTrustedNodes(prev => {
            const updated = new Map(prev);
            updated.set(nodeId, trustedNode);
            return updated;
        });

        // Persist trusted relationships to AsyncStorage for cross-session continuity
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

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * PROTOCOL v2.1 MESSAGE TRANSMISSION WITH CRYPTOGRAPHIC SIGNING ENGINE
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive message sending with Protocol v2.1 Ed25519 digital signatures,
     * message chain management, delivery tracking, and network statistics
     * integration for secure and reliable mesh communication transmission.
     * 
     * Handles complete message lifecycle from creation through cryptographic
     * signing, chain linking, transmission, and delivery confirmation with
     * enterprise-grade reliability and security audit compliance.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Enhanced message sending with Protocol v2.1
    const sendMessage = useCallback(async (
        content: string,
        recipientId?: string,
        type: MessageType = MessageType.DIRECT,
        priority: MessagePriority = MessagePriority.NORMAL
    ) => {
        // Validate system initialization before message processing
        if (!bleManager || !keyPair) {
            throw new Error('BLE Manager not initialized');
        }

        // Generate unique message identifier for tracking and correlation
        const messageId = `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        // Retrieve or initialize Protocol v2.1 message chain for recipient
        const chain = recipientId ? (messageChains.current.get(recipientId) || {
            lastSentHash: '',           // Previous message hash for chain linking
            lastReceivedHash: '',       // Last received message for validation
            sentSequence: 0,            // Outbound sequence counter
            receivedSequence: 0,        // Inbound sequence counter
            chainBreaks: 0              // Security breach detection counter
        }) : null;

        // Create comprehensive message record with Protocol v2.1 metadata
        const newMessage: StoredMessage = {
            /** Unique message identifier for tracking */
            id: messageId,
            /** Message content for transmission */
            content,
            /** Message type classification for routing */
            type,
            /** Creation timestamp for chronological ordering */
            timestamp: Date.now(),
            /** Initial queued status for lifecycle tracking */
            status: 'QUEUED',
            /** Outbound message flag for flow analysis */
            isIncoming: false,
            /** Our Ed25519 fingerprint as sender identity */
            senderFingerprint: keyPair.getFingerprint(),
            /** Target recipient fingerprint for routing */
            recipientFingerprint: recipientId,
            /** Protocol v2.1 sequence number for ordering */
            sequenceNumber: chain ? chain.sentSequence : 0,
            /** Previous message hash for chain integrity */
            previousMessageHash: chain ? chain.lastSentHash : '',
            /** Delivery attempt counter for retry logic */
            attempts: 0,
            /** Last attempt timestamp for retry scheduling */
            lastAttempt: Date.now(),
        };

        // Add message to state for immediate UI feedback
        setMessages(prev => [...prev, newMessage]);

        try {
            // Protocol v2.1 message lifecycle: QUEUED → SIGNING → TRANSMITTING → SENT
            
            // Update status to signing for Ed25519 cryptographic signature generation
            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'SIGNING' } : msg
                )
            );

            // Update status to transmitting for BLE mesh network delivery
            setMessages(prev =>
                prev.map(msg =>
                    msg.id === messageId ? { ...msg, status: 'TRANSMITTING' } : msg
                )
            );

            // Route message through appropriate Protocol v2.1 delivery mechanism
            let bleMessageId: string;
            if (type === MessageType.BROADCAST) {
                // Broadcast to all discovered nodes in mesh network
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

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * COMPREHENSIVE COMMAND-LINE INTERFACE WITH PROTOCOL v2.1 ADMINISTRATION
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Advanced command execution engine providing complete administrative
     * control over GhostComm Protocol v2.1 mesh network operations including
     * security management, network administration, message handling, and
     * system monitoring with enterprise-grade command processing.
     * 
     * Supports comprehensive command set including network management,
     * security operations, message handling, trust administration, and
     * system analytics with detailed help and error handling integration.
     * 
     * Author: LCpl 'Si' Procak
     */
    
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

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * COMPREHENSIVE DATA PERSISTENCE AND RESTORATION SYSTEM
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Advanced data loading system with comprehensive state restoration
     * from React Native AsyncStorage including messages, network statistics,
     * system logs, user preferences, and trusted node relationships
     * with error handling and graceful degradation for reliability.
     * 
     * Author: LCpl 'Si' Procak
     */
    
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

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * COMPREHENSIVE GHOSTCOMM INITIALIZATION AND SYSTEM BOOTSTRAP ENGINE
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Complete system initialization orchestrating cryptographic key management,
     * BLE manager setup, event handler registration, data restoration, and
     * Protocol v2.1 compliance validation for production-ready deployment.
     * 
     * Handles entire application bootstrap including identity management,
     * network initialization, event system setup, and state restoration
     * with comprehensive error handling and recovery mechanisms.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Initialize BLE and load stored data
    useEffect(() => {
        const initializeGhostComm = async () => {
            try {
                addSystemLog('INFO', 'Initializing GhostComm...', 'SYSTEM');

                // Cryptographic identity management with Ed25519/X25519 key generation
                let keys: IGhostKeyPair;
                const storedKeys = await AsyncStorage.getItem(STORAGE_KEYS.KEYPAIR);

                if (storedKeys) {
                    // Restore existing cryptographic identity from secure storage
                    addSystemLog('INFO', 'Loading existing keypair', 'SYSTEM');
                    const parsed = JSON.parse(storedKeys);
                    keys = GhostKeyPair.fromExported(parsed);
                } else {
                    // Generate new Ed25519/X25519 key pair for Protocol v2.1 identity
                    addSystemLog('INFO', 'Generating new keypair', 'SYSTEM');
                    keys = new GhostKeyPair();
                    const exported = keys.exportKeys();
                    await AsyncStorage.setItem(STORAGE_KEYS.KEYPAIR, JSON.stringify(exported));
                }

                // Set cryptographic identity and log node fingerprint for identification
                setKeyPair(keys);
                addSystemLog('SUCCESS', `Node ID: ${keys.getFingerprint().substring(0, 16)}...`, 'SYSTEM');

                // Create React Native BLE Manager with Protocol v2.1 integration
                const manager = new ReactNativeBLEManager(keys);
                setBleManager(manager);

                // Comprehensive event listener registration for mesh network operations
                manager.onEvent(handleBLEEvent);

                // Node discovery event handler for real-time network topology updates
                manager.onDiscovery((node: BLENode) => {
                    handleNodeDiscovered(node);
                });

                // Message reception handler with Protocol v2.1 verification integration
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

    /**
     * ═══════════════════════════════════════════════════════════════════════════
     * AUTOMATED DATA PERSISTENCE WITH OPTIMIZED STORAGE MANAGEMENT
     * ═══════════════════════════════════════════════════════════════════════════
     * 
     * Comprehensive automatic data persistence system with optimized storage
     * management, data rotation, and error handling for reliable state
     * preservation across application lifecycle events and system restarts.
     * 
     * Author: LCpl 'Si' Procak
     */
    
    // Save messages with rotation to prevent storage overflow
    useEffect(() => {
        if (messages.length > 0) {
            // Keep last 200 messages for storage optimization and performance
            AsyncStorage.setItem(STORAGE_KEYS.MESSAGES, JSON.stringify(messages.slice(-200))).catch(console.error);
        }
    }, [messages]);

    // Persist network statistics for analytics and monitoring continuity
    useEffect(() => {
        AsyncStorage.setItem(STORAGE_KEYS.NETWORK_STATS, JSON.stringify(networkStats)).catch(console.error);
    }, [networkStats]);

    // Save system logs with rotation for debugging and audit trail preservation
    useEffect(() => {
        if (systemLogs.length > 0) {
            // Keep last 100 logs for storage efficiency and performance optimization
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