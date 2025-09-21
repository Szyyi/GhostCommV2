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
} from 'react-native';
import { useGhostComm } from '../context/GhostCommContext';
import { useTheme } from '../context/ThemeContext';

const { width: SCREEN_WIDTH, height: SCREEN_HEIGHT } = Dimensions.get('window');

interface MeshNode {
    id: string;
    rssi: number;
    lastSeen: number;
    alias?: string;
    messageCount?: number;
    hopCount?: number;
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
    } = useGhostComm();

    const [refreshing, setRefreshing] = useState(false);
    const [selectedNode, setSelectedNode] = useState<string | null>(null);
    const [viewMode, setViewMode] = useState<'radar' | 'grid' | 'stats'>('radar');

    // Animation values
    const fadeAnim = useRef(new Animated.Value(0)).current;
    const radarSweep = useRef(new Animated.Value(0)).current;
    const pulseAnim = useRef(new Animated.Value(1)).current;
    const nodeAnimations = useRef<Map<string, Animated.Value>>(new Map()).current;

    // Initialize animations
    useEffect(() => {
        Animated.timing(fadeAnim, {
            toValue: 1,
            duration: 600,
            useNativeDriver: true,
        }).start();

        // Radar sweep animation
        if (isScanning) {
            Animated.loop(
                Animated.timing(radarSweep, {
                    toValue: 1,
                    duration: 3000,
                    useNativeDriver: true,
                })
            ).start();
        } else {
            radarSweep.setValue(0);
        }
    }, [isScanning]);

    // Pulse animation for connected nodes
    useEffect(() => {
        if (connectedNodes.size > 0) {
            Animated.loop(
                Animated.sequence([
                    Animated.timing(pulseAnim, {
                        toValue: 1.1,
                        duration: 1500,
                        useNativeDriver: true,
                    }),
                    Animated.timing(pulseAnim, {
                        toValue: 1,
                        duration: 1500,
                        useNativeDriver: true,
                    }),
                ])
            ).start();
        }
    }, [connectedNodes.size]);

    const handleRefresh = async () => {
        setRefreshing(true);
        await refreshNetwork();
        setTimeout(() => setRefreshing(false), 1000);
    };

    const formatFingerprint = (fp: string) => {
        return fp.substring(0, 8).toUpperCase();
    };

    const getSignalQuality = (rssi: number) => {
        if (rssi >= -50) return { level: 5, label: 'EXCELLENT', opacity: 1 };
        if (rssi >= -60) return { level: 4, label: 'STRONG', opacity: 0.85 };
        if (rssi >= -70) return { level: 3, label: 'GOOD', opacity: 0.7 };
        if (rssi >= -80) return { level: 2, label: 'FAIR', opacity: 0.55 };
        if (rssi >= -90) return { level: 1, label: 'WEAK', opacity: 0.4 };
        return { level: 0, label: 'LOST', opacity: 0.25 };
    };

    const renderRadarView = () => {
        const nodes = Array.from(discoveredNodes.values());
        const RADAR_SIZE = SCREEN_WIDTH - 40;
        const CENTER = RADAR_SIZE / 2;

        return (
            <View style={styles.radarContainer}>
                {/* Radar Display */}
                <View style={[
                    styles.radarDisplay,
                    { 
                        width: RADAR_SIZE,
                        height: RADAR_SIZE,
                        backgroundColor: currentTheme.surface
                    }
                ]}>
                    {/* Radar Rings */}
                    {[1, 2, 3, 4].map((ring) => (
                        <View
                            key={ring}
                            style={[
                                styles.radarRing,
                                {
                                    width: (RADAR_SIZE / 4) * ring,
                                    height: (RADAR_SIZE / 4) * ring,
                                    borderColor: currentTheme.border,
                                    opacity: 0.3 - (ring * 0.05)
                                }
                            ]}
                        />
                    ))}

                    {/* Radar Sweep */}
                    {isScanning && (
                        <Animated.View
                            style={[
                                styles.radarSweep,
                                {
                                    backgroundColor: currentTheme.primary,
                                    transform: [
                                        { rotate: radarSweep.interpolate({
                                            inputRange: [0, 1],
                                            outputRange: ['0deg', '360deg']
                                        })}
                                    ]
                                }
                            ]}
                        />
                    )}

                    {/* Center Node (You) */}
                    <Animated.View
                        style={[
                            styles.centerNode,
                            { 
                                backgroundColor: currentTheme.primary,
                                transform: [{ scale: pulseAnim }]
                            }
                        ]}
                    >
                        <View style={[styles.centerNodeInner, { backgroundColor: currentTheme.surface }]}>
                            <Text style={[styles.centerNodeText, { color: currentTheme.primary }]}>YOU</Text>
                        </View>
                    </Animated.View>

                    {/* Discovered Nodes */}
                    {nodes.map((node, index) => {
                        const angle = (index / nodes.length) * 2 * Math.PI;
                        const signal = getSignalQuality(node.rssi || -100);
                        const distance = (5 - signal.level) * 30 + 60;
                        const x = CENTER + Math.cos(angle) * distance - 25;
                        const y = CENTER + Math.sin(angle) * distance - 25;
                        const isConnected = connectedNodes.has(node.id);

                        return (
                            <View key={node.id}>
                                {/* Connection Line */}
                                {isConnected && (
                                    <View
                                        style={[
                                            styles.connectionBeam,
                                            {
                                                backgroundColor: currentTheme.primary,
                                                opacity: signal.opacity * 0.3,
                                                width: distance,
                                                transform: [
                                                    { translateX: CENTER },
                                                    { translateY: CENTER },
                                                    { rotate: `${angle}rad` },
                                                    { translateX: -distance / 2 }
                                                ]
                                            }
                                        ]}
                                    />
                                )}

                                {/* Node */}
                                <TouchableOpacity
                                    style={[
                                        styles.radarNode,
                                        {
                                            left: x,
                                            top: y,
                                            backgroundColor: currentTheme.surface,
                                            borderColor: isConnected ? currentTheme.primary : currentTheme.border,
                                            borderWidth: isConnected ? 2 : 1,
                                            opacity: signal.opacity
                                        }
                                    ]}
                                    onPress={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
                                    activeOpacity={0.8}
                                >
                                    <View style={[
                                        styles.radarNodeDot,
                                        { backgroundColor: isConnected ? currentTheme.primary : currentTheme.textSecondary }
                                    ]} />
                                    <Text style={[styles.radarNodeId, { color: currentTheme.text }]}>
                                        {formatFingerprint(node.id).substring(0, 4)}
                                    </Text>
                                </TouchableOpacity>
                            </View>
                        );
                    })}

                    {/* Distance Labels */}
                    <Text style={[styles.distanceLabel, styles.distanceLabelTop, { color: currentTheme.textTertiary }]}>
                        FAR
                    </Text>
                    <Text style={[styles.distanceLabel, styles.distanceLabelBottom, { color: currentTheme.textTertiary }]}>
                        FAR
                    </Text>
                    <Text style={[styles.distanceLabel, styles.distanceLabelLeft, { color: currentTheme.textTertiary }]}>
                        FAR
                    </Text>
                    <Text style={[styles.distanceLabel, styles.distanceLabelRight, { color: currentTheme.textTertiary }]}>
                        FAR
                    </Text>
                </View>

                {/* Signal Legend */}
                <View style={[styles.signalLegend, { backgroundColor: currentTheme.surface }]}>
                    <Text style={[styles.legendTitle, { color: currentTheme.text }]}>SIGNAL STRENGTH</Text>
                    <View style={styles.legendItems}>
                        {['EXCELLENT', 'STRONG', 'GOOD', 'FAIR', 'WEAK'].map((level, index) => (
                            <View key={level} style={styles.legendItem}>
                                <View style={[
                                    styles.legendDot,
                                    { 
                                        backgroundColor: currentTheme.primary,
                                        opacity: 1 - (index * 0.15)
                                    }
                                ]} />
                                <Text style={[styles.legendText, { color: currentTheme.textSecondary }]}>
                                    {level}
                                </Text>
                            </View>
                        ))}
                    </View>
                </View>
            </View>
        );
    };

    const renderGridView = () => {
        const nodes = Array.from(discoveredNodes.values());

        return (
            <ScrollView style={styles.gridContainer} showsVerticalScrollIndicator={false}>
                <View style={styles.gridHeader}>
                    <Text style={[styles.gridTitle, { color: currentTheme.text }]}>
                        NETWORK NODES
                    </Text>
                    <View style={[styles.gridCount, { backgroundColor: currentTheme.primary }]}>
                        <Text style={[styles.gridCountText, { color: currentTheme.surface }]}>
                            {nodes.length}
                        </Text>
                    </View>
                </View>

                {nodes.length === 0 ? (
                    <View style={styles.emptyGrid}>
                        <View style={[styles.emptyIcon, { backgroundColor: currentTheme.surface }]}>
                            <Text style={[styles.emptyIconText, { color: currentTheme.textTertiary }]}>○</Text>
                        </View>
                        <Text style={[styles.emptyTitle, { color: currentTheme.text }]}>
                            No Nodes Found
                        </Text>
                        <Text style={[styles.emptySubtitle, { color: currentTheme.textSecondary }]}>
                            Start scanning to discover nearby devices
                        </Text>
                    </View>
                ) : (
                    <View style={styles.nodeGrid}>
                        {nodes.map((node) => {
                            const isConnected = connectedNodes.has(node.id);
                            const signal = getSignalQuality(node.rssi || -100);

                            return (
                                <TouchableOpacity
                                    key={node.id}
                                    style={[
                                        styles.gridNode,
                                        { 
                                            backgroundColor: currentTheme.surface,
                                            borderColor: isConnected ? currentTheme.primary : currentTheme.border
                                        }
                                    ]}
                                    onPress={() => setSelectedNode(node.id)}
                                    activeOpacity={0.8}
                                >
                                    <View style={[
                                        styles.gridNodeStatus,
                                        { backgroundColor: isConnected ? currentTheme.primary : currentTheme.textTertiary }
                                    ]} />
                                    
                                    <Text style={[styles.gridNodeId, { color: currentTheme.text }]}>
                                        {formatFingerprint(node.id)}
                                    </Text>
                                    
                                    <View style={styles.gridNodeSignal}>
                                        {[...Array(5)].map((_, i) => (
                                            <View
                                                key={i}
                                                style={[
                                                    styles.signalBar,
                                                    { 
                                                        backgroundColor: i < signal.level 
                                                            ? currentTheme.primary 
                                                            : currentTheme.border,
                                                        height: 4 + (i * 2)
                                                    }
                                                ]}
                                            />
                                        ))}
                                    </View>
                                    
                                    <Text style={[styles.gridNodeLabel, { color: currentTheme.textSecondary }]}>
                                        {signal.label}
                                    </Text>
                                </TouchableOpacity>
                            );
                        })}
                    </View>
                )}
            </ScrollView>
        );
    };

    const renderStatsView = () => {
        const stats = [
            { label: 'CONNECTED', value: connectedNodes.size, icon: '◉' },
            { label: 'DISCOVERED', value: discoveredNodes.size, icon: '◎' },
            { label: 'MESSAGES SENT', value: networkStats.messagesSent, icon: '↑' },
            { label: 'MESSAGES RECEIVED', value: networkStats.messagesReceived, icon: '↓' },
            { label: 'RELAYED', value: networkStats.messagesRelayed, icon: '⟲' },
            { label: 'DATA TRANSFERRED', value: `${((networkStats.bytesTransmitted + networkStats.bytesReceived) / 1024).toFixed(1)}KB`, icon: '⇅' },
        ];

        return (
            <ScrollView style={styles.statsContainer} showsVerticalScrollIndicator={false}>
                <Text style={[styles.statsTitle, { color: currentTheme.text }]}>
                    NETWORK STATISTICS
                </Text>

                <View style={styles.statsGrid}>
                    {stats.map((stat, index) => (
                        <View
                            key={index}
                            style={[
                                styles.statCard,
                                { backgroundColor: currentTheme.surface }
                            ]}
                        >
                            <Text style={[styles.statIcon, { color: currentTheme.primary }]}>
                                {stat.icon}
                            </Text>
                            <Text style={[styles.statValue, { color: currentTheme.text }]}>
                                {stat.value}
                            </Text>
                            <Text style={[styles.statLabel, { color: currentTheme.textSecondary }]}>
                                {stat.label}
                            </Text>
                        </View>
                    ))}
                </View>

                {/* Activity Graph Placeholder */}
                <View style={[styles.activityGraph, { backgroundColor: currentTheme.surface }]}>
                    <Text style={[styles.graphTitle, { color: currentTheme.text }]}>
                        NETWORK ACTIVITY
                    </Text>
                    <View style={styles.graphBars}>
                        {[40, 65, 35, 80, 55, 70, 45].map((height, index) => (
                            <View
                                key={index}
                                style={[
                                    styles.graphBar,
                                    { 
                                        backgroundColor: currentTheme.primary,
                                        height: `${height}%`,
                                        opacity: 0.3 + (height / 100) * 0.7
                                    }
                                ]}
                            />
                        ))}
                    </View>
                </View>
            </ScrollView>
        );
    };

    return (
        <View style={[styles.container, { backgroundColor: currentTheme.background }]}>
            <Animated.View style={[styles.mainContainer, { opacity: fadeAnim }]}>
                {/* Header */}
                <View style={[styles.header, { backgroundColor: currentTheme.surface }]}>
                    <View style={styles.headerTop}>
                        <Text style={[styles.headerTitle, { color: currentTheme.text }]}>
                            NETWORK
                        </Text>
                        <View style={styles.headerStatus}>
                            <View style={[
                                styles.statusDot,
                                { backgroundColor: isScanning ? currentTheme.warning : currentTheme.textTertiary }
                            ]} />
                            <Text style={[styles.statusText, { color: currentTheme.textSecondary }]}>
                                {isScanning ? 'SCANNING' : 'IDLE'}
                            </Text>
                        </View>
                    </View>

                    <View style={styles.idBar}>
                        <Text style={[styles.idLabel, { color: currentTheme.textSecondary }]}>NODE ID:</Text>
                        <Text style={[styles.idValue, { color: currentTheme.text }]}>
                            {keyPair ? formatFingerprint(keyPair.getFingerprint()) : 'UNKNOWN'}
                        </Text>
                    </View>
                </View>

                {/* View Toggle */}
                <View style={[styles.viewToggle, { backgroundColor: currentTheme.surface }]}>
                    {[
                        { key: 'radar', label: 'RADAR', icon: '◎' },
                        { key: 'grid', label: 'GRID', icon: '▦' },
                        { key: 'stats', label: 'STATS', icon: '≡' }
                    ].map((view) => (
                        <TouchableOpacity
                            key={view.key}
                            style={[
                                styles.toggleButton,
                                viewMode === view.key && { backgroundColor: currentTheme.primary }
                            ]}
                            onPress={() => setViewMode(view.key as any)}
                            activeOpacity={0.8}
                        >
                            <Text style={[
                                styles.toggleIcon,
                                { color: viewMode === view.key ? currentTheme.surface : currentTheme.text }
                            ]}>
                                {view.icon}
                            </Text>
                            <Text style={[
                                styles.toggleText,
                                { color: viewMode === view.key ? currentTheme.surface : currentTheme.text }
                            ]}>
                                {view.label}
                            </Text>
                        </TouchableOpacity>
                    ))}
                </View>

                {/* Content Area */}
                <ScrollView
                    style={styles.content}
                    refreshControl={
                        <RefreshControl
                            refreshing={refreshing}
                            onRefresh={handleRefresh}
                            tintColor={currentTheme.primary}
                        />
                    }
                    showsVerticalScrollIndicator={false}
                >
                    {viewMode === 'radar' && renderRadarView()}
                    {viewMode === 'grid' && renderGridView()}
                    {viewMode === 'stats' && renderStatsView()}
                </ScrollView>

                {/* Selected Node Panel */}
                {selectedNode && (
                    <View style={[styles.nodePanel, { backgroundColor: currentTheme.surface }]}>
                        <View style={styles.nodePanelHeader}>
                            <Text style={[styles.nodePanelTitle, { color: currentTheme.text }]}>
                                NODE DETAILS
                            </Text>
                            <TouchableOpacity
                                onPress={() => setSelectedNode(null)}
                                style={styles.nodePanelClose}
                            >
                                <Text style={[styles.nodePanelCloseText, { color: currentTheme.textSecondary }]}>
                                    ✕
                                </Text>
                            </TouchableOpacity>
                        </View>

                        <View style={styles.nodePanelContent}>
                            <View style={styles.nodeDetailRow}>
                                <Text style={[styles.nodeDetailLabel, { color: currentTheme.textSecondary }]}>
                                    FINGERPRINT
                                </Text>
                                <Text style={[styles.nodeDetailValue, { color: currentTheme.text }]}>
                                    {formatFingerprint(selectedNode)}
                                </Text>
                            </View>

                            <View style={styles.nodeDetailRow}>
                                <Text style={[styles.nodeDetailLabel, { color: currentTheme.textSecondary }]}>
                                    SIGNAL
                                </Text>
                                <Text style={[styles.nodeDetailValue, { color: currentTheme.text }]}>
                                    {discoveredNodes.get(selectedNode)?.rssi || 'N/A'} dBm
                                </Text>
                            </View>

                            <View style={styles.nodeDetailRow}>
                                <Text style={[styles.nodeDetailLabel, { color: currentTheme.textSecondary }]}>
                                    STATUS
                                </Text>
                                <Text style={[
                                    styles.nodeDetailValue,
                                    { color: connectedNodes.has(selectedNode) ? currentTheme.success : currentTheme.warning }
                                ]}>
                                    {connectedNodes.has(selectedNode) ? 'CONNECTED' : 'AVAILABLE'}
                                </Text>
                            </View>
                        </View>

                        <TouchableOpacity
                            style={[
                                styles.nodePanelAction,
                                { 
                                    backgroundColor: connectedNodes.has(selectedNode) 
                                        ? currentTheme.error 
                                        : currentTheme.primary 
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
                            activeOpacity={0.8}
                        >
                            <Text style={[styles.nodePanelActionText, { color: currentTheme.surface }]}>
                                {connectedNodes.has(selectedNode) ? 'DISCONNECT' : 'CONNECT'}
                            </Text>
                        </TouchableOpacity>
                    </View>
                )}

                {/* Control Bar */}
                <View style={[styles.controlBar, { backgroundColor: currentTheme.surface }]}>
                    <TouchableOpacity
                        style={[
                            styles.controlButton,
                            { 
                                backgroundColor: isScanning ? currentTheme.primary : 'transparent',
                                borderColor: currentTheme.primary
                            }
                        ]}
                        onPress={isScanning ? stopScanning : startScanning}
                        activeOpacity={0.8}
                    >
                        <Text style={[
                            styles.controlText,
                            { color: isScanning ? currentTheme.surface : currentTheme.primary }
                        ]}>
                            {isScanning ? 'STOP SCAN' : 'START SCAN'}
                        </Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={[
                            styles.controlButton,
                            { 
                                backgroundColor: isAdvertising ? currentTheme.primary : 'transparent',
                                borderColor: currentTheme.primary
                            }
                        ]}
                        onPress={isAdvertising ? stopAdvertising : startAdvertising}
                        activeOpacity={0.8}
                    >
                        <Text style={[
                            styles.controlText,
                            { color: isAdvertising ? currentTheme.surface : currentTheme.primary }
                        ]}>
                            {isAdvertising ? 'BEACON ON' : 'BEACON OFF'}
                        </Text>
                    </TouchableOpacity>
                </View>
            </Animated.View>
        </View>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
    },
    mainContainer: {
        flex: 1,
    },

    // Header
    header: {
        paddingTop: 15,
        paddingHorizontal: 20,
        paddingBottom: 10,
        elevation: 2,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
    },
    headerTop: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 10,
    },
    headerTitle: {
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        letterSpacing: 3,
    },
    headerStatus: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    statusDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        marginRight: 8,
    },
    statusText: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1,
    },
    idBar: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    idLabel: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        marginRight: 8,
        letterSpacing: 1,
    },
    idValue: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
    },

    // View Toggle
    viewToggle: {
        flexDirection: 'row',
        paddingHorizontal: 20,
        paddingVertical: 10,
    },
    toggleButton: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 10,
        marginHorizontal: 5,
    },
    toggleIcon: {
        fontSize: 14,
        marginRight: 6,
    },
    toggleText: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
    },

    // Content
    content: {
        flex: 1,
    },

    // Radar View
    radarContainer: {
        padding: 20,
        alignItems: 'center',
    },
    radarDisplay: {
        position: 'relative',
        alignItems: 'center',
        justifyContent: 'center',
        borderRadius: 1000,
        overflow: 'hidden',
    },
    radarRing: {
        position: 'absolute',
        borderWidth: 1,
        borderRadius: 1000,
    },
    radarSweep: {
        position: 'absolute',
        width: '50%',
        height: 1,
        opacity: 0.3,
        transformOrigin: 'left center',
    },
    centerNode: {
        width: 60,
        height: 60,
        borderRadius: 30,
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 10,
    },
    centerNodeInner: {
        width: 54,
        height: 54,
        borderRadius: 27,
        alignItems: 'center',
        justifyContent: 'center',
    },
    centerNodeText: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1,
    },
    connectionBeam: {
        position: 'absolute',
        height: 1,
        transformOrigin: 'left center',
    },
    radarNode: {
        position: 'absolute',
        width: 50,
        height: 50,
        borderRadius: 25,
        alignItems: 'center',
        justifyContent: 'center',
    },
    radarNodeDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        marginBottom: 3,
    },
    radarNodeId: {
        fontSize: 9,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
    },
    distanceLabel: {
        position: 'absolute',
        fontSize: 9,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        letterSpacing: 1,
    },
    distanceLabelTop: { top: 10, left: '50%', marginLeft: -15 },
    distanceLabelBottom: { bottom: 10, left: '50%', marginLeft: -15 },
    distanceLabelLeft: { left: 10, top: '50%', marginTop: -10 },
    distanceLabelRight: { right: 10, top: '50%', marginTop: -10 },
    signalLegend: {
        marginTop: 20,
        paddingVertical: 15,
        paddingHorizontal: 20,
        width: '100%',
    },
    legendTitle: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 2,
        marginBottom: 10,
        textAlign: 'center',
    },
    legendItems: {
        flexDirection: 'row',
        justifyContent: 'space-around',
    },
    legendItem: {
        alignItems: 'center',
    },
    legendDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        marginBottom: 4,
    },
    legendText: {
        fontSize: 9,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },

    // Grid View
    gridContainer: {
        flex: 1,
        padding: 20,
    },
    gridHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 20,
    },
    gridTitle: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        letterSpacing: 2,
    },
    gridCount: {
        paddingHorizontal: 12,
        paddingVertical: 4,
    },
    gridCountText: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
    },
    nodeGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
    },
    gridNode: {
        width: '48%',
        padding: 15,
        marginBottom: 15,
        borderWidth: 1,
        alignItems: 'center',
    },
    gridNodeStatus: {
        width: 12,
        height: 12,
        borderRadius: 6,
        marginBottom: 10,
    },
    gridNodeId: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
        marginBottom: 10,
    },
    gridNodeSignal: {
        flexDirection: 'row',
        alignItems: 'flex-end',
        height: 20,
        marginBottom: 8,
    },
    signalBar: {
        width: 3,
        marginHorizontal: 1,
    },
    gridNodeLabel: {
        fontSize: 9,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1,
    },
    emptyGrid: {
        alignItems: 'center',
        paddingVertical: 60,
    },
    emptyIcon: {
        width: 80,
        height: 80,
        borderRadius: 40,
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 20,
    },
    emptyIconText: {
        fontSize: 40,
    },
    emptyTitle: {
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        marginBottom: 8,
    },
    emptySubtitle: {
        fontSize: 13,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
    },

    // Stats View
    statsContainer: {
        flex: 1,
        padding: 20,
    },
    statsTitle: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
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
        paddingVertical: 20,
        paddingHorizontal: 15,
        marginBottom: 15,
        alignItems: 'center',
    },
    statIcon: {
        fontSize: 24,
        marginBottom: 10,
    },
    statValue: {
        fontSize: 18,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        marginBottom: 5,
    },
    statLabel: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1,
        textAlign: 'center',
    },
    activityGraph: {
        padding: 20,
        height: 200,
    },
    graphTitle: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
        marginBottom: 20,
    },
    graphBars: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'flex-end',
        justifyContent: 'space-around',
    },
    graphBar: {
        width: 30,
    },

    // Node Panel
    nodePanel: {
        position: 'absolute',
        bottom: 0,
        left: 0,
        right: 0,
        padding: 20,
        elevation: 8,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: -2 },
        shadowOpacity: 0.2,
        shadowRadius: 8,
    },
    nodePanelHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 20,
    },
    nodePanelTitle: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 2,
    },
    nodePanelClose: {
        padding: 5,
    },
    nodePanelCloseText: {
        fontSize: 18,
    },
    nodePanelContent: {
        marginBottom: 20,
    },
    nodeDetailRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 12,
    },
    nodeDetailLabel: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1,
    },
    nodeDetailValue: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
    },
    nodePanelAction: {
        paddingVertical: 14,
        alignItems: 'center',
    },
    nodePanelActionText: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 2,
    },

    // Control Bar
    controlBar: {
        flexDirection: 'row',
        padding: 20,
        elevation: 8,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: -2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
    },
    controlButton: {
        flex: 1,
        paddingVertical: 12,
        marginHorizontal: 10,
        borderWidth: 1,
        alignItems: 'center',
    },
    controlText: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
    },
});

export default NetworkScreen;