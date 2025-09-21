import React, { useState, useRef, useEffect } from 'react';
import {
    View,
    Text,
    TextInput,
    ScrollView,
    StyleSheet,
    KeyboardAvoidingView,
    Platform,
    TouchableOpacity,
    Animated,
    Dimensions,
    FlatList,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useGhostComm } from '../context/GhostCommContext';
import { useTheme } from '../context/ThemeContext';

interface CommandItem {
    id: string;
    command: string;
    response: string;
    timestamp: number;
    status: 'success' | 'error' | 'warning' | 'info';
}

interface QuickCommand {
    label: string;
    command: string;
    icon: string;
    description: string;
}

const { width: SCREEN_WIDTH, height: SCREEN_HEIGHT } = Dimensions.get('window');

const TerminalScreen: React.FC = () => {
    const {
        executeCommand,
        keyPair,
        connectedNodes,
        discoveredNodes,
        networkStats,
        isScanning,
        isAdvertising,
    } = useGhostComm();

    const { currentTheme } = useTheme();

    const [commandHistory, setCommandHistory] = useState<CommandItem[]>([]);
    const [currentInput, setCurrentInput] = useState('');
    const [isProcessing, setIsProcessing] = useState(false);
    const [activeView, setActiveView] = useState<'commands' | 'quickActions'>('commands');
    const [searchQuery, setSearchQuery] = useState('');

    const scrollViewRef = useRef<ScrollView>(null);
    const fadeAnim = useRef(new Animated.Value(0)).current;

    // Quick commands configuration
    const quickCommands: QuickCommand[] = [
        { label: 'SCAN', command: 'scan', icon: '◉', description: 'Discover nearby nodes' },
        { label: 'BEACON', command: 'beacon', icon: '⟟', description: 'Broadcast presence' },
        { label: 'NODES', command: 'nodes', icon: '◈', description: 'List all nodes' },
        { label: 'STATUS', command: 'status', icon: '◎', description: 'Network status' },
        { label: 'SEND', command: 'send', icon: '→', description: 'Send message' },
        { label: 'PEERS', command: 'peers', icon: '◊', description: 'Connected peers' },
        { label: 'ROUTES', command: 'routes', icon: '⟆', description: 'Routing table' },
        { label: 'STATS', command: 'stats', icon: '≣', description: 'Network statistics' },
        { label: 'CLEAR', command: 'clear', icon: '○', description: 'Clear history' },
        { label: 'EXPORT', command: 'export', icon: '↗', description: 'Export keys' },
        { label: 'SETTINGS', command: 'settings', icon: '⚙', description: 'Configuration' },
        { label: 'HELP', command: 'help', icon: '?', description: 'Command reference' },
    ];

    useEffect(() => {
        Animated.timing(fadeAnim, {
            toValue: 1,
            duration: 400,
            useNativeDriver: true,
        }).start();

        loadCommandHistory();
    }, []);

    const loadCommandHistory = async () => {
        try {
            const saved = await AsyncStorage.getItem('@ghostcomm_command_history');
            if (saved) {
                setCommandHistory(JSON.parse(saved));
            }
        } catch (error) {
            console.error('Failed to load command history:', error);
        }
    };

    const saveCommandHistory = async (history: CommandItem[]) => {
        try {
            // Keep only last 50 commands
            const trimmed = history.slice(-50);
            await AsyncStorage.setItem('@ghostcomm_command_history', JSON.stringify(trimmed));
        } catch (error) {
            console.error('Failed to save command history:', error);
        }
    };

    const handleCommand = async (command: string) => {
        if (!command.trim()) return;

        setIsProcessing(true);
        const timestamp = Date.now();

        try {
            const result = await executeCommand(command);
            
            const newItem: CommandItem = {
                id: `${timestamp}`,
                command: command.trim(),
                response: result,
                timestamp,
                status: 'success',
            };

            const updatedHistory = [...commandHistory, newItem];
            setCommandHistory(updatedHistory);
            saveCommandHistory(updatedHistory);
            
            setCurrentInput('');
            
            // Auto-scroll to latest
            setTimeout(() => {
                scrollViewRef.current?.scrollToEnd({ animated: true });
            }, 100);
        } catch (error) {
            const newItem: CommandItem = {
                id: `${timestamp}`,
                command: command.trim(),
                response: error instanceof Error ? error.message : String(error),
                timestamp,
                status: 'error',
            };

            const updatedHistory = [...commandHistory, newItem];
            setCommandHistory(updatedHistory);
            saveCommandHistory(updatedHistory);
        } finally {
            setIsProcessing(false);
        }
    };

    const executeQuickCommand = (cmd: string) => {
        if (cmd === 'clear') {
            setCommandHistory([]);
            AsyncStorage.removeItem('@ghostcomm_command_history');
        } else {
            handleCommand(cmd);
        }
    };

    const getNetworkStatusColor = () => {
        if (connectedNodes.size > 0) return currentTheme.success;
        if (isScanning || isAdvertising) return currentTheme.warning;
        return currentTheme.textTertiary;
    };

    const formatTimestamp = (timestamp: number) => {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('en-US', { 
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const filteredHistory = commandHistory.filter(item => 
        item.command.toLowerCase().includes(searchQuery.toLowerCase()) ||
        item.response.toLowerCase().includes(searchQuery.toLowerCase())
    );

    const renderCommandItem = (item: CommandItem) => (
        <View key={item.id} style={[styles.commandCard, { backgroundColor: currentTheme.surface }]}>
            <View style={styles.commandHeader}>
                <Text style={[styles.commandText, { color: currentTheme.text }]}>
                    {item.command}
                </Text>
                <Text style={[styles.timestamp, { color: currentTheme.textTertiary }]}>
                    {formatTimestamp(item.timestamp)}
                </Text>
            </View>
            
            <View style={[styles.responseDivider, { backgroundColor: currentTheme.divider }]} />
            
            <Text style={[
                styles.responseText, 
                { color: item.status === 'error' ? currentTheme.error : currentTheme.textSecondary }
            ]}>
                {item.response}
            </Text>
        </View>
    );

    const renderQuickCommand = (item: QuickCommand) => (
        <TouchableOpacity
            key={item.command}
            style={[styles.quickCommandCard, { 
                backgroundColor: currentTheme.surface,
                borderColor: currentTheme.border
            }]}
            onPress={() => executeQuickCommand(item.command)}
            activeOpacity={0.8}
        >
            <Text style={[styles.quickIcon, { color: currentTheme.primary }]}>
                {item.icon}
            </Text>
            <View style={styles.quickCommandInfo}>
                <Text style={[styles.quickLabel, { color: currentTheme.text }]}>
                    {item.label}
                </Text>
                <Text style={[styles.quickDescription, { color: currentTheme.textTertiary }]}>
                    {item.description}
                </Text>
            </View>
        </TouchableOpacity>
    );

    return (
        <KeyboardAvoidingView
            style={[styles.container, { backgroundColor: currentTheme.background }]}
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
            keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
        >
            <Animated.View style={[styles.mainContainer, { opacity: fadeAnim }]}>
                {/* Premium Header */}
                <View style={[styles.header, { backgroundColor: currentTheme.surface }]}>
                    <View style={styles.headerTop}>
                        <Text style={[styles.headerTitle, { color: currentTheme.text }]}>
                            COMMAND CENTER
                        </Text>
                        <View style={[styles.statusIndicator, { backgroundColor: getNetworkStatusColor() }]} />
                    </View>
                    
                    {/* Network Stats Bar */}
                    <View style={styles.statsBar}>
                        <View style={styles.statItem}>
                            <Text style={[styles.statLabel, { color: currentTheme.textTertiary }]}>NODES</Text>
                            <Text style={[styles.statValue, { color: currentTheme.text }]}>
                                {connectedNodes.size}/{discoveredNodes.size}
                            </Text>
                        </View>
                        
                        <View style={[styles.statDivider, { backgroundColor: currentTheme.divider }]} />
                        
                        <View style={styles.statItem}>
                            <Text style={[styles.statLabel, { color: currentTheme.textTertiary }]}>MESSAGES</Text>
                            <Text style={[styles.statValue, { color: currentTheme.text }]}>
                                {networkStats.messagesSent + networkStats.messagesReceived}
                            </Text>
                        </View>
                        
                        <View style={[styles.statDivider, { backgroundColor: currentTheme.divider }]} />
                        
                        <View style={styles.statItem}>
                            <Text style={[styles.statLabel, { color: currentTheme.textTertiary }]}>IDENTITY</Text>
                            <Text style={[styles.statValue, { color: currentTheme.text }]}>
                                {keyPair?.getFingerprint().substring(0, 8).toUpperCase() || 'NONE'}
                            </Text>
                        </View>
                    </View>
                </View>

                {/* View Toggle */}
                <View style={[styles.viewToggle, { backgroundColor: currentTheme.surface }]}>
                    <TouchableOpacity
                        style={[
                            styles.toggleButton,
                            activeView === 'commands' && { backgroundColor: currentTheme.primary }
                        ]}
                        onPress={() => setActiveView('commands')}
                        activeOpacity={0.8}
                    >
                        <Text style={[
                            styles.toggleText,
                            { color: activeView === 'commands' ? currentTheme.surface : currentTheme.text }
                        ]}>
                            HISTORY
                        </Text>
                    </TouchableOpacity>
                    
                    <TouchableOpacity
                        style={[
                            styles.toggleButton,
                            activeView === 'quickActions' && { backgroundColor: currentTheme.primary }
                        ]}
                        onPress={() => setActiveView('quickActions')}
                        activeOpacity={0.8}
                    >
                        <Text style={[
                            styles.toggleText,
                            { color: activeView === 'quickActions' ? currentTheme.surface : currentTheme.text }
                        ]}>
                            QUICK ACTIONS
                        </Text>
                    </TouchableOpacity>
                </View>

                {/* Search Bar (for command history) */}
                {activeView === 'commands' && (
                    <View style={[styles.searchBar, { backgroundColor: currentTheme.surface }]}>
                        <TextInput
                            style={[styles.searchInput, { color: currentTheme.text }]}
                            placeholder="Search history..."
                            placeholderTextColor={currentTheme.textTertiary}
                            value={searchQuery}
                            onChangeText={setSearchQuery}
                        />
                    </View>
                )}

                {/* Main Content Area */}
                <ScrollView
                    ref={scrollViewRef}
                    style={styles.contentArea}
                    contentContainerStyle={styles.contentContainer}
                    showsVerticalScrollIndicator={false}
                >
                    {activeView === 'commands' ? (
                        filteredHistory.length > 0 ? (
                            filteredHistory.map(renderCommandItem)
                        ) : (
                            <View style={styles.emptyState}>
                                <Text style={[styles.emptyIcon, { color: currentTheme.textTertiary }]}>○</Text>
                                <Text style={[styles.emptyText, { color: currentTheme.textTertiary }]}>
                                    {searchQuery ? 'No matching commands found' : 'No command history yet'}
                                </Text>
                                <Text style={[styles.emptySubtext, { color: currentTheme.textTertiary }]}>
                                    Type a command below to get started
                                </Text>
                            </View>
                        )
                    ) : (
                        <View style={styles.quickCommandsGrid}>
                            {quickCommands.map(renderQuickCommand)}
                        </View>
                    )}
                </ScrollView>

                {/* Premium Input Area */}
                <View style={[styles.inputArea, { backgroundColor: currentTheme.surface }]}>
                    <View style={[styles.inputContainer, { borderColor: currentTheme.border }]}>
                        <TextInput
                            style={[styles.commandInput, { color: currentTheme.text }]}
                            placeholder="Enter command..."
                            placeholderTextColor={currentTheme.textTertiary}
                            value={currentInput}
                            onChangeText={setCurrentInput}
                            onSubmitEditing={() => handleCommand(currentInput)}
                            autoCapitalize="none"
                            autoCorrect={false}
                            returnKeyType="send"
                            editable={!isProcessing}
                        />
                        
                        <TouchableOpacity
                            style={[
                                styles.sendButton,
                                { backgroundColor: currentInput.trim() ? currentTheme.primary : currentTheme.surface },
                                isProcessing && styles.sendButtonDisabled
                            ]}
                            onPress={() => handleCommand(currentInput)}
                            disabled={!currentInput.trim() || isProcessing}
                            activeOpacity={0.8}
                        >
                            <Text style={[
                                styles.sendButtonText,
                                { color: currentInput.trim() ? currentTheme.surface : currentTheme.textTertiary }
                            ]}>
                                {isProcessing ? '...' : '→'}
                            </Text>
                        </TouchableOpacity>
                    </View>
                    
                    {/* Quick Access Buttons */}
                    <View style={styles.quickAccessRow}>
                        <TouchableOpacity
                            style={[styles.quickButton, { borderColor: currentTheme.border }]}
                            onPress={() => executeQuickCommand(isScanning ? 'stop' : 'scan')}
                        >
                            <Text style={[styles.quickButtonText, { color: currentTheme.text }]}>
                                {isScanning ? 'STOP' : 'SCAN'}
                            </Text>
                        </TouchableOpacity>
                        
                        <TouchableOpacity
                            style={[styles.quickButton, { borderColor: currentTheme.border }]}
                            onPress={() => executeQuickCommand(isAdvertising ? 'stop' : 'beacon')}
                        >
                            <Text style={[styles.quickButtonText, { color: currentTheme.text }]}>
                                {isAdvertising ? 'STOP' : 'BEACON'}
                            </Text>
                        </TouchableOpacity>
                        
                        <TouchableOpacity
                            style={[styles.quickButton, { borderColor: currentTheme.border }]}
                            onPress={() => executeQuickCommand('nodes')}
                        >
                            <Text style={[styles.quickButtonText, { color: currentTheme.text }]}>
                                NODES
                            </Text>
                        </TouchableOpacity>
                        
                        <TouchableOpacity
                            style={[styles.quickButton, { borderColor: currentTheme.border }]}
                            onPress={() => executeQuickCommand('help')}
                        >
                            <Text style={[styles.quickButtonText, { color: currentTheme.text }]}>
                                HELP
                            </Text>
                        </TouchableOpacity>
                    </View>
                </View>
            </Animated.View>
        </KeyboardAvoidingView>
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
        marginBottom: 15,
    },
    headerTitle: {
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        letterSpacing: 3,
    },
    statusIndicator: {
        width: 8,
        height: 8,
        borderRadius: 4,
    },

    // Stats Bar
    statsBar: {
        flexDirection: 'row',
        paddingVertical: 10,
    },
    statItem: {
        flex: 1,
        alignItems: 'center',
    },
    statLabel: {
        fontSize: 9,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
        marginBottom: 4,
    },
    statValue: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '400',
    },
    statDivider: {
        width: 1,
        height: 30,
        marginHorizontal: 20,
    },

    // View Toggle
    viewToggle: {
        flexDirection: 'row',
        paddingHorizontal: 20,
        paddingVertical: 10,
    },
    toggleButton: {
        flex: 1,
        paddingVertical: 10,
        alignItems: 'center',
        marginHorizontal: 5,
    },
    toggleText: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 2,
    },

    // Search Bar
    searchBar: {
        paddingHorizontal: 20,
        paddingVertical: 10,
    },
    searchInput: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        paddingVertical: 10,
        paddingHorizontal: 15,
        borderRadius: 0,
        borderWidth: 1,
        borderColor: 'rgba(0,0,0,0.1)',
    },

    // Content Area
    contentArea: {
        flex: 1,
    },
    contentContainer: {
        padding: 20,
    },

    // Command Cards
    commandCard: {
        marginBottom: 15,
        padding: 15,
        borderRadius: 0,
    },
    commandHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 10,
    },
    commandText: {
        fontSize: 13,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '600',
    },
    timestamp: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },
    responseDivider: {
        height: 1,
        marginVertical: 10,
    },
    responseText: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        lineHeight: 18,
    },

    // Quick Commands Grid
    quickCommandsGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
    },
    quickCommandCard: {
        width: '48%',
        flexDirection: 'row',
        alignItems: 'center',
        padding: 15,
        marginBottom: 15,
        borderWidth: 1,
    },
    quickIcon: {
        fontSize: 20,
        marginRight: 12,
    },
    quickCommandInfo: {
        flex: 1,
    },
    quickLabel: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1,
        marginBottom: 3,
    },
    quickDescription: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
    },

    // Empty State
    emptyState: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 60,
    },
    emptyIcon: {
        fontSize: 48,
        marginBottom: 20,
    },
    emptyText: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        marginBottom: 8,
    },
    emptySubtext: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
    },

    // Input Area
    inputArea: {
        paddingHorizontal: 20,
        paddingVertical: 15,
        elevation: 8,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: -2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
    },
    inputContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        borderWidth: 1,
        marginBottom: 10,
    },
    commandInput: {
        flex: 1,
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        paddingVertical: 12,
        paddingHorizontal: 15,
    },
    sendButton: {
        paddingHorizontal: 20,
        paddingVertical: 12,
    },
    sendButtonDisabled: {
        opacity: 0.3,
    },
    sendButtonText: {
        fontSize: 18,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },

    // Quick Access
    quickAccessRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
    },
    quickButton: {
        flex: 1,
        paddingVertical: 10,
        alignItems: 'center',
        marginHorizontal: 5,
        borderWidth: 1,
    },
    quickButtonText: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
    },
});

export default TerminalScreen