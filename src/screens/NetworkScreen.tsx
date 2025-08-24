import React, { useState, useEffect, useRef, useMemo } from 'react';
import {
    View,
    Text,
    ScrollView,
    StyleSheet,
    TouchableOpacity,
    RefreshControl,
    Platform,
    Dimensions,
    Animated,
    Easing,
} from 'react-native';
import { useGhostComm } from '../context/GhostCommContext';
import { useTheme } from '../context/ThemeContext';

const { width: SCREEN_WIDTH, height: SCREEN_HEIGHT } = Dimensions.get('window');

// Enhanced node type with mesh routing info
interface MeshNode {
    id: string;
    rssi: number;
    lastSeen: number;
    alias?: string;
    routingTable?: Map<string, string>; // destination -> nextHop
    messageCount?: number;
    bytesTransferred?: number;
    hopCount?: number; // hops from our node
    discoveredBy?: string; // which node told us about this one
    canSee?: string[]; // nodes this node can directly see
}

const NetworkScreen: React.FC = () => {
    const { currentTheme } = useTheme();

    const {
        keyPair,
        connectedNodes,
        discoveredNodes,
        networkStats,
        systemLogs,
        isScanning,
        isAdvertising,
        refreshNetwork,
        startScanning,
        stopScanning,
        connectToNode,
        disconnectFromNode,
        startAdvertising,
        stopAdvertising,
        getNodeRoutingTable,
        getMessageFlow,
    } = useGhostComm();

    const [refreshing, setRefreshing] = useState(false);
    const [selectedNode, setSelectedNode] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<'mesh' | 'nodes' | 'stats' | 'logs'>('mesh');
    const [autoScroll, setAutoScroll] = useState(true);
    const scrollViewRef = useRef<ScrollView>(null);

    // Animation values
    const fadeAnim = useRef(new Animated.Value(0)).current;
    const slideAnim = useRef(new Animated.Value(30)).current;
    const pulseAnim = useRef(new Animated.Value(1)).current;
    const scanPulse = useRef(new Animated.Value(1)).current;
    const nodeAnimations = useRef<Map<string, Animated.Value>>(new Map()).current;
    const connectionAnimations = useRef<Map<string, Animated.Value>>(new Map()).current;

    // Calculate mesh topology
    const meshTopology = useMemo(() => {
        const topology = new Map<string, Set<string>>();
        const routingPaths = new Map<string, Map<string, string[]>>();

        discoveredNodes.forEach((node) => {
            if (node.canSee) {
                topology.set(node.id, new Set(node.canSee));
            }
        });

        const calculatePath = (from: string, to: string): string[] => {
            if (from === to) return [from];

            const visited = new Set<string>();
            const queue: { node: string, path: string[] }[] = [{ node: from, path: [from] }];

            while (queue.length > 0) {
                const { node, path } = queue.shift()!;

                if (visited.has(node)) continue;
                visited.add(node);

                const neighbors = topology.get(node) || new Set();
                for (const neighbor of neighbors) {
                    const newPath = [...path, neighbor];
                    if (neighbor === to) {
                        return newPath;
                    }
                    queue.push({ node: neighbor, path: newPath });
                }
            }

            return [];
        };

        const ourId = keyPair?.getFingerprint() || 'self';
        const paths = new Map<string, string[]>();

        discoveredNodes.forEach((node) => {
            const path = calculatePath(ourId, node.id);
            if (path.length > 0) {
                paths.set(node.id, path);
            }
        });

        return { topology, paths };
    }, [discoveredNodes, keyPair]);

    const [messageFlows, setMessageFlows] = useState<Map<string, Map<string, number>>>(new Map());

    useEffect(() => {
        const interval = setInterval(() => {
            if (getMessageFlow) {
                const flows = getMessageFlow();
                setMessageFlows(flows);
            }
        }, 1000);

        return () => clearInterval(interval);
    }, [getMessageFlow]);

    // Initial animations
    useEffect(() => {
        Animated.parallel([
            Animated.timing(fadeAnim, {
                toValue: 1,
                duration: 500,
                useNativeDriver: true,
            }),
            Animated.timing(slideAnim, {
                toValue: 0,
                duration: 500,
                easing: Easing.out(Easing.cubic),
                useNativeDriver: true,
            }),
        ]).start();
    }, []);

    // Scanning pulse
    useEffect(() => {
        if (isScanning) {
            const pulse = Animated.loop(
                Animated.sequence([
                    Animated.timing(scanPulse, {
                        toValue: 1.3,
                        duration: 1000,
                        easing: Easing.inOut(Easing.ease),
                        useNativeDriver: true,
                    }),
                    Animated.timing(scanPulse, {
                        toValue: 1,
                        duration: 1000,
                        easing: Easing.inOut(Easing.ease),
                        useNativeDriver: true,
                    }),
                ])
            );
            pulse.start();
            return () => pulse.stop();
        }
    }, [isScanning]);

    const handleRefresh = async () => {
        setRefreshing(true);
        await refreshNetwork();
        setTimeout(() => setRefreshing(false), 1000);
    };

    const formatFingerprint = (fp: string) => {
        return fp.substring(0, 8).toUpperCase();
    };

    const getSignalStrength = (rssi: number) => {
        // Use theme-aware colors for signal strength
        const excellentColor = currentTheme.primary;
        const goodColor = currentTheme.primary + 'DD';
        const fairColor = currentTheme.primary + 'AA';
        const weakColor = currentTheme.primary + '88';
        const poorColor = currentTheme.primary + '66';
        const lostColor = currentTheme.primary + '44';

        if (rssi >= -50) return { bars: 5, level: 'EXCELLENT', color: excellentColor };
        if (rssi >= -60) return { bars: 4, level: 'GOOD', color: goodColor };
        if (rssi >= -70) return { bars: 3, level: 'FAIR', color: fairColor };
        if (rssi >= -80) return { bars: 2, level: 'WEAK', color: weakColor };
        if (rssi >= -90) return { bars: 1, level: 'POOR', color: poorColor };
        return { bars: 0, level: 'LOST', color: lostColor };
    };

    const getSignalBars = (strength: number) => {
        const filled = '█';
        const empty = '░';
        return filled.repeat(strength) + empty.repeat(5 - strength);
    };

    const toggleBeacon = () => {
        if (isAdvertising) {
            stopAdvertising?.();
        } else {
            startAdvertising?.();
        }
    };

    const renderMeshView = () => {
        const nodes = Array.from(discoveredNodes.values());
        const ourId = keyPair?.getFingerprint() || 'self';

        return (
            <Animated.View
                style={[
                    styles.meshContainer,
                    {
                        opacity: fadeAnim,
                        transform: [{ translateY: slideAnim }]
                    }
                ]}
            >
                <View style={[styles.meshVisualization, {
                    backgroundColor: currentTheme.surface,
                    borderColor: currentTheme.primary
                }]}>
                    <Text style={[styles.meshTitle, { color: currentTheme.primary }]}>
                        MESH TOPOLOGY
                    </Text>

                    <View style={styles.meshCenter}>
                        <Animated.View
                            style={[
                                styles.centralNode,
                                { transform: [{ scale: pulseAnim }] }
                            ]}
                        >
                            <View style={[styles.centralNodeInner, {
                                backgroundColor: currentTheme.surface,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.centralNodeIcon, { color: currentTheme.primary }]}>◈</Text>
                                <Text style={[styles.centralNodeLabel, { color: currentTheme.primary }]}>YOU</Text>
                            </View>
                        </Animated.View>

                        <View style={styles.meshGrid}>
                            {nodes.slice(0, 8).map((node, index) => {
                                const isConnected = connectedNodes.has(node.id);
                                const nodeAnim = nodeAnimations.get(node.id) || new Animated.Value(1);
                                const signal = getSignalStrength(node.rssi ?? -100);
                                const angle = (index * 45) * Math.PI / 180;
                                const radius = 100;
                                const x = Math.cos(angle) * radius;
                                const y = Math.sin(angle) * radius;

                                return (
                                    <Animated.View
                                        key={node.id}
                                        style={[
                                            styles.meshNode,
                                            {
                                                transform: [
                                                    { translateX: x },
                                                    { translateY: y },
                                                    { scale: nodeAnim }
                                                ]
                                            }
                                        ]}
                                    >
                                        {isConnected && (
                                            <View
                                                style={[
                                                    styles.connectionLine,
                                                    {
                                                        backgroundColor: currentTheme.primary,
                                                        width: radius,
                                                        transform: [
                                                            { rotate: `${angle}rad` },
                                                            { translateX: -radius / 2 }
                                                        ]
                                                    }
                                                ]}
                                            />
                                        )}

                                        <TouchableOpacity
                                            style={[
                                                styles.nodeButton,
                                                {
                                                    backgroundColor: currentTheme.background,
                                                    borderColor: currentTheme.primary
                                                },
                                                isConnected && {
                                                    backgroundColor: currentTheme.surface,
                                                    borderWidth: 2
                                                },
                                                selectedNode === node.id && {
                                                    backgroundColor: currentTheme.surface,
                                                    shadowColor: currentTheme.primary
                                                }
                                            ]}
                                            onPress={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                                            activeOpacity={0.7}
                                        >
                                            <Text style={[styles.nodeIcon, { color: signal.color }]}>
                                                {isConnected ? '◉' : '◯'}
                                            </Text>
                                            <Text style={[styles.nodeIdShort, { color: currentTheme.primary }]}>
                                                {formatFingerprint(node.id).substring(0, 4)}
                                            </Text>
                                            <Text style={[styles.nodeSignalBars, { color: signal.color }]}>
                                                {getSignalBars(signal.bars)}
                                            </Text>
                                        </TouchableOpacity>
                                    </Animated.View>
                                );
                            })}
                        </View>

                        {nodes.length > 8 && (
                            <View style={[styles.moreNodesIndicator, {
                                backgroundColor: currentTheme.surface,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.moreNodesText, { color: currentTheme.primary }]}>
                                    +{nodes.length - 8} MORE
                                </Text>
                            </View>
                        )}
                    </View>

                    {nodes.length === 0 && (
                        <View style={styles.emptyMesh}>
                            <Text style={[styles.emptyMeshIcon, { color: currentTheme.primary }]}>◎</Text>
                            <Text style={[styles.emptyMeshText, { color: currentTheme.primary }]}>
                                NO NODES DETECTED
                            </Text>
                            <Text style={[styles.emptyMeshSubtext, { color: currentTheme.textSecondary }]}>
                                {isScanning ? 'SCANNING...' : 'START SCAN TO DISCOVER'}
                            </Text>
                        </View>
                    )}
                </View>

                <View style={[styles.quickStats, {
                    backgroundColor: currentTheme.surface,
                    borderColor: currentTheme.primary
                }]}>
                    <View style={styles.quickStatItem}>
                        <Text style={[styles.quickStatValue, { color: currentTheme.primary }]}>
                            {connectedNodes.size}
                        </Text>
                        <Text style={[styles.quickStatLabel, { color: currentTheme.textSecondary }]}>
                            LINKED
                        </Text>
                    </View>
                    <View style={[styles.quickStatDivider, { backgroundColor: currentTheme.border }]} />
                    <View style={styles.quickStatItem}>
                        <Text style={[styles.quickStatValue, { color: currentTheme.primary }]}>
                            {discoveredNodes.size}
                        </Text>
                        <Text style={[styles.quickStatLabel, { color: currentTheme.textSecondary }]}>
                            VISIBLE
                        </Text>
                    </View>
                    <View style={[styles.quickStatDivider, { backgroundColor: currentTheme.border }]} />
                    <View style={styles.quickStatItem}>
                        <Text style={[styles.quickStatValue, { color: currentTheme.primary }]}>
                            {Math.max(...Array.from(discoveredNodes.values()).map(n => (n as MeshNode).hopCount || 0), 0)}
                        </Text>
                        <Text style={[styles.quickStatLabel, { color: currentTheme.textSecondary }]}>
                            MAX HOPS
                        </Text>
                    </View>
                    <View style={[styles.quickStatDivider, { backgroundColor: currentTheme.border }]} />
                    <View style={styles.quickStatItem}>
                        <Text style={[styles.quickStatValue, { color: currentTheme.primary }]}>
                            {networkStats.messagesRelayed}
                        </Text>
                        <Text style={[styles.quickStatLabel, { color: currentTheme.textSecondary }]}>
                            RELAYED
                        </Text>
                    </View>
                </View>

                {selectedNode && (
                    <Animated.View style={[styles.nodeDetailCard, {
                        backgroundColor: currentTheme.surface,
                        borderColor: currentTheme.primary
                    }]}>
                        <View style={styles.nodeDetailHeader}>
                            <Text style={[styles.nodeDetailTitle, { color: currentTheme.primary }]}>
                                NODE {formatFingerprint(selectedNode)}
                            </Text>
                            <TouchableOpacity
                                onPress={() => setSelectedNode(null)}
                                style={styles.nodeDetailClose}
                            >
                                <Text style={[styles.nodeDetailCloseText, { color: currentTheme.textSecondary }]}>✕</Text>
                            </TouchableOpacity>
                        </View>

                        <View style={styles.nodeDetailContent}>
                            <View style={styles.nodeDetailRow}>
                                <Text style={[styles.nodeDetailLabel, { color: currentTheme.textSecondary }]}>STATUS</Text>
                                <Text style={[styles.nodeDetailValue, { color: currentTheme.text }]}>
                                    {connectedNodes.has(selectedNode) ? 'CONNECTED' : 'AVAILABLE'}
                                </Text>
                            </View>
                            <View style={styles.nodeDetailRow}>
                                <Text style={[styles.nodeDetailLabel, { color: currentTheme.textSecondary }]}>SIGNAL</Text>
                                <Text style={[styles.nodeDetailValue, { color: currentTheme.text }]}>
                                    {discoveredNodes.get(selectedNode)?.rssi} dBm
                                </Text>
                            </View>
                            <View style={styles.nodeDetailRow}>
                                <Text style={[styles.nodeDetailLabel, { color: currentTheme.textSecondary }]}>QUALITY</Text>
                                <Text style={[
                                    styles.nodeDetailValue,
                                    { color: getSignalStrength(discoveredNodes.get(selectedNode)?.rssi ?? -100).color }
                                ]}>
                                    {getSignalBars(getSignalStrength(discoveredNodes.get(selectedNode)?.rssi ?? -100).bars)}
                                </Text>
                            </View>
                        </View>

                        <TouchableOpacity
                            style={[
                                styles.nodeDetailAction,
                                {
                                    backgroundColor: currentTheme.surface,
                                    borderColor: currentTheme.primary
                                },
                                connectedNodes.has(selectedNode) && {
                                    borderColor: currentTheme.error
                                }
                            ]}
                            onPress={() => {
                                if (connectedNodes.has(selectedNode)) {
                                    disconnectFromNode(selectedNode);
                                } else {
                                    connectToNode(selectedNode);
                                }
                                setSelectedNode(null);
                            }}
                            activeOpacity={0.7}
                        >
                            <Text style={[styles.nodeDetailActionText, {
                                color: connectedNodes.has(selectedNode) ? currentTheme.error : currentTheme.primary
                            }]}>
                                {connectedNodes.has(selectedNode) ? 'DISCONNECT' : 'CONNECT'}
                            </Text>
                        </TouchableOpacity>
                    </Animated.View>
                )}
            </Animated.View>
        );
    };

    const renderNodesView = () => {
        const allNodes = Array.from(discoveredNodes.values());

        return (
            <ScrollView style={styles.nodesContainer} showsVerticalScrollIndicator={false}>
                <View style={styles.nodesHeader}>
                    <Text style={[styles.nodesTitle, { color: currentTheme.primary }]}>
                        DISCOVERED NODES
                    </Text>
                    <Text style={[styles.nodesCount, { color: currentTheme.textSecondary }]}>
                        [{allNodes.length}]
                    </Text>
                </View>

                {allNodes.length === 0 ? (
                    <View style={styles.emptyNodes}>
                        <Text style={[styles.emptyNodesIcon, { color: currentTheme.textSecondary }]}>◎ ◎ ◎</Text>
                        <Text style={[styles.emptyNodesText, { color: currentTheme.textSecondary }]}>
                            NO NODES IN RANGE
                        </Text>
                        <TouchableOpacity
                            style={[styles.emptyScanButton, { borderColor: currentTheme.primary }]}
                            onPress={startScanning}
                            activeOpacity={0.7}
                        >
                            <Text style={[styles.emptyScanButtonText, { color: currentTheme.primary }]}>
                                START SCAN
                            </Text>
                        </TouchableOpacity>
                    </View>
                ) : (
                    <View style={styles.nodesList}>
                        {allNodes.map((node) => {
                            const meshNode = node as MeshNode;
                            const isConnected = connectedNodes.has(node.id);
                            const signal = getSignalStrength(node.rssi ?? -100);

                            return (
                                <TouchableOpacity
                                    key={node.id}
                                    style={[
                                        styles.nodeListItem,
                                        {
                                            backgroundColor: currentTheme.surface,
                                            borderColor: currentTheme.primary
                                        },
                                        isConnected && {
                                            backgroundColor: currentTheme.surface,
                                            borderWidth: 2
                                        }
                                    ]}
                                    onPress={() => setSelectedNode(node.id)}
                                    activeOpacity={0.7}
                                >
                                    <View style={styles.nodeListLeft}>
                                        <Text style={[
                                            styles.nodeListIcon,
                                            { color: currentTheme.primary },
                                            isConnected && styles.nodeListIconConnected
                                        ]}>
                                            {isConnected ? '◉' : '◯'}
                                        </Text>
                                        <View style={styles.nodeListInfo}>
                                            <Text style={[styles.nodeListId, { color: currentTheme.text }]}>
                                                {formatFingerprint(node.id)}
                                            </Text>
                                            {meshNode.alias && (
                                                <Text style={[styles.nodeListAlias, { color: currentTheme.textSecondary }]}>
                                                    {meshNode.alias}
                                                </Text>
                                            )}
                                        </View>
                                    </View>

                                    <View style={styles.nodeListRight}>
                                        <Text style={[styles.nodeListSignal, { color: signal.color }]}>
                                            {getSignalBars(signal.bars)}
                                        </Text>
                                        <Text style={[styles.nodeListRssi, { color: currentTheme.textSecondary }]}>
                                            {node.rssi} dBm
                                        </Text>
                                    </View>
                                </TouchableOpacity>
                            );
                        })}
                    </View>
                )}
            </ScrollView>
        );
    };

    const renderStatsView = () => {
        return (
            <ScrollView style={styles.statsContainer} showsVerticalScrollIndicator={false}>
                <Text style={[styles.statsTitle, { color: currentTheme.primary }]}>
                    NETWORK STATISTICS
                </Text>

                <View style={styles.statsGrid}>
                    {[
                        { icon: '◈', value: connectedNodes.size, label: 'ACTIVE LINKS' },
                        { icon: '◎', value: discoveredNodes.size, label: 'DISCOVERED' },
                        { icon: '⟲', value: networkStats.messagesRelayed, label: 'RELAYED' },
                        { icon: '↑', value: `${(networkStats.bytesTransmitted / 1024).toFixed(1)}K`, label: 'SENT' },
                        { icon: '↓', value: `${(networkStats.bytesReceived / 1024).toFixed(1)}K`, label: 'RECEIVED' },
                        { icon: '⇅', value: `${((networkStats.bytesTransmitted + networkStats.bytesReceived) / 1024).toFixed(1)}K`, label: 'TOTAL' },
                    ].map((stat, index) => (
                        <View key={index} style={[styles.statCard, {
                            backgroundColor: currentTheme.surface,
                            borderColor: currentTheme.primary
                        }]}>
                            <Text style={[styles.statCardIcon, { color: currentTheme.primary }]}>
                                {stat.icon}
                            </Text>
                            <Text style={[styles.statCardValue, { color: currentTheme.text }]}>
                                {stat.value}
                            </Text>
                            <Text style={[styles.statCardLabel, { color: currentTheme.textSecondary }]}>
                                {stat.label}
                            </Text>
                        </View>
                    ))}
                </View>

                <View style={[styles.routingSection, {
                    backgroundColor: currentTheme.surface,
                    borderColor: currentTheme.primary
                }]}>
                    <Text style={[styles.routingSectionTitle, { color: currentTheme.primary }]}>
                        ROUTING PATHS
                    </Text>
                    {Array.from(meshTopology.paths?.entries() || []).slice(0, 5).map(([nodeId, path]) => (
                        <View key={nodeId} style={styles.routingPath}>
                            <Text style={[styles.routingPathLabel, { color: currentTheme.textSecondary }]}>
                                TO {formatFingerprint(nodeId).substring(0, 4)}
                            </Text>
                            <Text style={[styles.routingPathValue, { color: currentTheme.text }]}>
                                {path.map(id =>
                                    id === keyPair?.getFingerprint() ? 'YOU' : formatFingerprint(id).substring(0, 4)
                                ).join(' → ')}
                            </Text>
                        </View>
                    ))}
                </View>
            </ScrollView>
        );
    };

    const renderLogsView = () => {
        return (
            <View style={styles.logsContainer}>
                <View style={styles.logsHeader}>
                    <Text style={[styles.logsTitle, { color: currentTheme.primary }]}>
                        SYSTEM LOGS
                    </Text>
                    <TouchableOpacity
                        onPress={() => setAutoScroll(!autoScroll)}
                        style={[
                            styles.logsAutoScroll,
                            { borderColor: currentTheme.primary },
                            autoScroll && { backgroundColor: currentTheme.surface }
                        ]}
                        activeOpacity={0.7}
                    >
                        <Text style={[styles.logsAutoScrollText, { color: currentTheme.primary }]}>
                            AUTO
                        </Text>
                    </TouchableOpacity>
                </View>

                <ScrollView
                    ref={scrollViewRef}
                    style={[styles.logsContent, {
                        backgroundColor: currentTheme.surface,
                        borderColor: currentTheme.primary
                    }]}
                    showsVerticalScrollIndicator={false}
                >
                    {systemLogs.map(log => (
                        <View key={log.id} style={styles.logEntry}>
                            <Text style={[styles.logTime, { color: currentTheme.textSecondary }]}>
                                [{new Date(log.timestamp).toLocaleTimeString('en-US', {
                                    hour12: false,
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: '2-digit'
                                })}]
                            </Text>
                            <Text style={[
                                styles.logMessage,
                                { color: currentTheme.text },
                                log.level === 'ERROR' && { color: currentTheme.error },
                                log.level === 'WARN' && { color: currentTheme.warning },
                                log.level === 'SUCCESS' && { color: currentTheme.primary },
                            ]}>
                                {log.level === 'ERROR' ? '✗' :
                                    log.level === 'WARN' ? '⚠' :
                                        log.level === 'SUCCESS' ? '✓' : '▶'} {log.message}
                            </Text>
                        </View>
                    ))}
                    <View style={[styles.logEnd, { borderTopColor: currentTheme.border }]}>
                        <Text style={[styles.logEndText, { color: currentTheme.textSecondary }]}>
                            ━━━ END OF LOG ━━━
                        </Text>
                    </View>
                </ScrollView>
            </View>
        );
    };

    return (
        <View style={[styles.container, { backgroundColor: currentTheme.background }]}>
            <View style={[styles.statusBar, {
                backgroundColor: currentTheme.surface,
                borderBottomColor: currentTheme.primary
            }]}>
                <View style={styles.statusSection}>
                    <Animated.View
                        style={[
                            styles.statusIndicator,
                            isScanning && { shadowColor: currentTheme.primary },
                            { transform: [{ scale: isScanning ? scanPulse : 1 }] }
                        ]}
                    >
                        <Text style={[styles.statusDot, { color: currentTheme.primary }]}>
                            {isScanning ? '◉' : '○'}
                        </Text>
                    </Animated.View>
                    <Text style={[styles.statusLabel, { color: currentTheme.textSecondary }]}>SCAN</Text>
                </View>

                <View style={styles.statusSection}>
                    <View style={[styles.statusIndicator, isAdvertising && { shadowColor: currentTheme.primary }]}>
                        <Text style={[styles.statusDot, { color: currentTheme.primary }]}>
                            {isAdvertising ? '◉' : '○'}
                        </Text>
                    </View>
                    <Text style={[styles.statusLabel, { color: currentTheme.textSecondary }]}>BEACON</Text>
                </View>

                <View style={styles.statusSection}>
                    <Animated.View
                        style={[
                            styles.statusIndicator,
                            connectedNodes.size > 0 && { shadowColor: currentTheme.primary },
                            { transform: [{ scale: connectedNodes.size > 0 ? pulseAnim : 1 }] }
                        ]}
                    >
                        <Text style={[styles.statusDot, { color: currentTheme.primary }]}>
                            {connectedNodes.size > 0 ? '◉' : '○'}
                        </Text>
                    </Animated.View>
                    <Text style={[styles.statusLabel, { color: currentTheme.textSecondary }]}>MESH</Text>
                </View>

                <View style={styles.statusId}>
                    <Text style={[styles.statusIdText, { color: currentTheme.textSecondary }]}>
                        ID: {keyPair ? formatFingerprint(keyPair.getFingerprint()) : 'UNKNOWN'}
                    </Text>
                </View>
            </View>

            <View style={[styles.tabBar, {
                backgroundColor: currentTheme.background,
                borderBottomColor: currentTheme.primary
            }]}>
                {[
                    { key: 'mesh', icon: '◈', text: 'MESH' },
                    { key: 'nodes', icon: '◎', text: 'NODES' },
                    { key: 'stats', icon: '▦', text: 'STATS' },
                    { key: 'logs', icon: '▶', text: 'LOGS' }
                ].map(tab => (
                    <TouchableOpacity
                        key={tab.key}
                        style={[
                            styles.tab,
                            viewMode === tab.key && {
                                backgroundColor: currentTheme.surface,
                                borderBottomColor: currentTheme.primary
                            }
                        ]}
                        onPress={() => setViewMode(tab.key as any)}
                        activeOpacity={0.7}
                    >
                        <Text style={[styles.tabIcon, { color: currentTheme.primary }]}>
                            {tab.icon}
                        </Text>
                        <Text style={[styles.tabText, { color: currentTheme.primary }]}>
                            {tab.text}
                        </Text>
                    </TouchableOpacity>
                ))}
            </View>

            <View style={styles.content}>
                {viewMode === 'mesh' && (
                    <ScrollView
                        refreshControl={
                            <RefreshControl
                                refreshing={refreshing}
                                onRefresh={handleRefresh}
                                tintColor={currentTheme.primary}
                            />
                        }
                        showsVerticalScrollIndicator={false}
                    >
                        {renderMeshView()}
                    </ScrollView>
                )}
                {viewMode === 'nodes' && renderNodesView()}
                {viewMode === 'stats' && renderStatsView()}
                {viewMode === 'logs' && renderLogsView()}
            </View>

            <View style={[styles.controlBar, {
                backgroundColor: currentTheme.surface,
                borderTopColor: currentTheme.primary
            }]}>
                <TouchableOpacity
                    style={[
                        styles.controlButton,
                        {
                            backgroundColor: currentTheme.background,
                            borderColor: currentTheme.primary
                        },
                        isScanning && {
                            backgroundColor: currentTheme.surface,
                            borderWidth: 2
                        }
                    ]}
                    onPress={isScanning ? stopScanning : startScanning}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.controlButtonIcon, { color: currentTheme.primary }]}>
                        {isScanning ? '◼' : '▶'}
                    </Text>
                    <Text style={[styles.controlButtonText, { color: currentTheme.primary }]}>
                        {isScanning ? 'STOP' : 'SCAN'}
                    </Text>
                </TouchableOpacity>

                <TouchableOpacity
                    style={[styles.controlButton, {
                        backgroundColor: currentTheme.background,
                        borderColor: currentTheme.primary
                    }]}
                    onPress={handleRefresh}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.controlButtonIcon, { color: currentTheme.primary }]}>⟲</Text>
                    <Text style={[styles.controlButtonText, { color: currentTheme.primary }]}>REFRESH</Text>
                </TouchableOpacity>

                <TouchableOpacity
                    style={[
                        styles.controlButton,
                        {
                            backgroundColor: currentTheme.background,
                            borderColor: currentTheme.primary
                        },
                        isAdvertising && {
                            backgroundColor: currentTheme.surface,
                            borderWidth: 2
                        }
                    ]}
                    onPress={toggleBeacon}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.controlButtonIcon, { color: currentTheme.primary }]}>
                        {isAdvertising ? '◉' : '○'}
                    </Text>
                    <Text style={[styles.controlButtonText, { color: currentTheme.primary }]}>BEACON</Text>
                </TouchableOpacity>
            </View>
        </View>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
    },

    // Status Bar
    statusBar: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 15,
        paddingVertical: 12,
        borderBottomWidth: 1,
    },
    statusSection: {
        flexDirection: 'row',
        alignItems: 'center',
        marginRight: 20,
    },
    statusIndicator: {
        marginRight: 6,
        shadowRadius: 6,
        shadowOpacity: 0.8,
    },
    statusDot: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
    },
    statusLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.8,
        letterSpacing: 1,
    },
    statusId: {
        marginLeft: 'auto',
    },
    statusIdText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 1,
    },

    // Tab Bar
    tabBar: {
        flexDirection: 'row',
        borderBottomWidth: 1,
    },
    tab: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 12,
        opacity: 0.5,
    },
    tabActive: {
        opacity: 1,
        borderBottomWidth: 2,
    },
    tabIcon: {
        fontSize: 14,
        marginRight: 6,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    },
    tabText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },

    // Content
    content: {
        flex: 1,
    },

    // Mesh View
    meshContainer: {
        padding: 20,
    },
    meshVisualization: {
        borderWidth: 1,
        padding: 20,
        marginBottom: 20,
    },
    meshTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        letterSpacing: 2,
        textAlign: 'center',
        marginBottom: 20,
        opacity: 0.8,
    },
    meshCenter: {
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: 250,
    },
    centralNode: {
        position: 'absolute',
        zIndex: 10,
    },
    centralNodeInner: {
        width: 80,
        height: 80,
        borderWidth: 2,
        alignItems: 'center',
        justifyContent: 'center',
    },
    centralNodeIcon: {
        fontSize: 24,
        marginBottom: 5,
    },
    centralNodeLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
    },
    meshGrid: {
        position: 'absolute',
        width: '100%',
        height: '100%',
        alignItems: 'center',
        justifyContent: 'center',
    },
    meshNode: {
        position: 'absolute',
        alignItems: 'center',
    },
    connectionLine: {
        position: 'absolute',
        height: 1,
        opacity: 0.3,
    },
    nodeButton: {
        width: 60,
        height: 60,
        borderWidth: 1,
        alignItems: 'center',
        justifyContent: 'center',
        padding: 5,
        shadowRadius: 10,
        shadowOpacity: 0.8,
    },
    nodeIcon: {
        fontSize: 16,
        marginBottom: 2,
    },
    nodeIdShort: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 8,
        opacity: 0.8,
    },
    nodeSignalBars: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 8,
        marginTop: 2,
    },
    moreNodesIndicator: {
        position: 'absolute',
        bottom: -30,
        paddingHorizontal: 10,
        paddingVertical: 3,
        borderWidth: 1,
    },
    moreNodesText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.7,
    },
    emptyMesh: {
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 40,
    },
    emptyMeshIcon: {
        fontSize: 40,
        opacity: 0.2,
        marginBottom: 15,
    },
    emptyMeshText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        opacity: 0.6,
        letterSpacing: 2,
    },
    emptyMeshSubtext: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.4,
        marginTop: 5,
    },

    // Quick Stats
    quickStats: {
        flexDirection: 'row',
        borderWidth: 1,
        padding: 15,
        marginBottom: 20,
    },
    quickStatItem: {
        flex: 1,
        alignItems: 'center',
    },
    quickStatValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 18,
        fontWeight: 'bold',
        marginBottom: 3,
    },
    quickStatLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.6,
        letterSpacing: 1,
    },
    quickStatDivider: {
        width: 1,
        opacity: 0.3,
        marginHorizontal: 10,
    },

    // Node Detail Card
    nodeDetailCard: {
        borderWidth: 1,
        padding: 15,
    },
    nodeDetailHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 15,
    },
    nodeDetailTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    nodeDetailClose: {
        padding: 5,
    },
    nodeDetailCloseText: {
        fontSize: 16,
        opacity: 0.6,
    },
    nodeDetailContent: {
        marginBottom: 15,
    },
    nodeDetailRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 8,
    },
    nodeDetailLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 1,
    },
    nodeDetailValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
    },
    nodeDetailAction: {
        paddingVertical: 10,
        borderWidth: 1,
        alignItems: 'center',
    },
    nodeDetailActionText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 2,
    },

    // Nodes List
    nodesContainer: {
        flex: 1,
        padding: 20,
    },
    nodesHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 20,
    },
    nodesTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 2,
    },
    nodesCount: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        opacity: 0.6,
        marginLeft: 10,
    },
    emptyNodes: {
        alignItems: 'center',
        paddingTop: 50,
    },
    emptyNodesIcon: {
        fontSize: 30,
        opacity: 0.2,
        marginBottom: 20,
    },
    emptyNodesText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        opacity: 0.6,
        letterSpacing: 2,
        marginBottom: 20,
    },
    emptyScanButton: {
        paddingHorizontal: 20,
        paddingVertical: 10,
        borderWidth: 1,
    },
    emptyScanButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    nodesList: {
        flex: 1,
    },
    nodeListItem: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingVertical: 12,
        paddingHorizontal: 15,
        borderWidth: 1,
        marginBottom: 8,
    },
    nodeListLeft: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    nodeListIcon: {
        fontSize: 16,
        marginRight: 12,
        opacity: 0.6,
    },
    nodeListIconConnected: {
        opacity: 1,
    },
    nodeListInfo: {
        justifyContent: 'center',
    },
    nodeListId: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
    },
    nodeListAlias: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        marginTop: 2,
    },
    nodeListRight: {
        alignItems: 'flex-end',
    },
    nodeListSignal: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        marginBottom: 2,
    },
    nodeListRssi: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.6,
    },

    // Stats
    statsContainer: {
        flex: 1,
        padding: 20,
    },
    statsTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 2,
        marginBottom: 20,
        textAlign: 'center',
    },
    statsGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        marginBottom: 30,
    },
    statCard: {
        width: '48%',
        borderWidth: 1,
        padding: 15,
        alignItems: 'center',
        marginBottom: 10,
    },
    statCardIcon: {
        fontSize: 20,
        marginBottom: 8,
        opacity: 0.8,
    },
    statCardValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 20,
        fontWeight: 'bold',
        marginBottom: 5,
    },
    statCardLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.6,
        letterSpacing: 1,
    },
    routingSection: {
        borderWidth: 1,
        padding: 15,
    },
    routingSectionTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        letterSpacing: 1,
        marginBottom: 15,
    },
    routingPath: {
        marginBottom: 10,
    },
    routingPathLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        marginBottom: 3,
    },
    routingPathValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        marginLeft: 10,
    },

    // Logs
    logsContainer: {
        flex: 1,
        padding: 20,
    },
    logsHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 15,
    },
    logsTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 2,
    },
    logsAutoScroll: {
        paddingHorizontal: 12,
        paddingVertical: 5,
        borderWidth: 1,
        opacity: 0.5,
    },
    logsAutoScrollActive: {
        opacity: 1,
    },
    logsAutoScrollText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        letterSpacing: 1,
    },
    logsContent: {
        flex: 1,
        borderWidth: 1,
        padding: 10,
    },
    logEntry: {
        flexDirection: 'row',
        marginBottom: 5,
    },
    logTime: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.5,
        marginRight: 8,
    },
    logMessage: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        flex: 1,
    },
    logEnd: {
        marginTop: 10,
        paddingTop: 10,
        borderTopWidth: 1,
        opacity: 0.3,
    },
    logEndText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        textAlign: 'center',
        opacity: 0.5,
    },

    // Control Bar
    controlBar: {
        flexDirection: 'row',
        padding: 12,
        borderTopWidth: 1,
    },
    controlButton: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 10,
        marginHorizontal: 5,
        borderWidth: 1,
    },
    controlButtonIcon: {
        fontSize: 14,
        marginRight: 6,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    },
    controlButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
});

export default NetworkScreen;