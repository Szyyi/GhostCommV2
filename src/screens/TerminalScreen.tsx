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
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useGhostComm } from '../context/GhostCommContext';

interface TerminalLine {
    id: string;
    text: string;
    type: 'input' | 'output' | 'error' | 'success' | 'system' | 'warning';
    timestamp: number;
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
        systemLogs,
    } = useGhostComm();

    const [commandHistory, setCommandHistory] = useState<string[]>([]);
    const [historyIndex, setHistoryIndex] = useState(-1);
    const [currentInput, setCurrentInput] = useState('');
    const [terminalLines, setTerminalLines] = useState<TerminalLine[]>([]);
    const [showCursor, setShowCursor] = useState(true);
    const [alias, setAlias] = useState('ghost');
    const [isProcessing, setIsProcessing] = useState(false);
    const [showQuickActions, setShowQuickActions] = useState(false);

    const scrollViewRef = useRef<ScrollView>(null);
    const inputRef = useRef<TextInput>(null);

    // Animation values
    const fadeAnim = useRef(new Animated.Value(0)).current;
    const pulseAnim = useRef(new Animated.Value(1)).current;
    const slideAnim = useRef(new Animated.Value(-100)).current;

    // Load command history and alias
    useEffect(() => {
        const loadData = async () => {
            const [savedHistory, savedAlias] = await Promise.all([
                AsyncStorage.getItem('@ghostcomm_terminal_history'),
                AsyncStorage.getItem('@ghostcomm_alias'),
            ]);

            if (savedHistory) {
                setCommandHistory(JSON.parse(savedHistory));
            }
            if (savedAlias) {
                setAlias(savedAlias);
            }
        };

        loadData();

        // Smooth fade-in animation
        Animated.timing(fadeAnim, {
            toValue: 1,
            duration: 1000,
            useNativeDriver: true,
        }).start();

        // Initial welcome message - much simpler
        setTimeout(() => {
            addLine('GhostComm Terminal v2.0', 'system');
            addLine('Type "help" for commands • "?" for quick guide', 'system');
        }, 500);
    }, []);

    // Pulse animation for active states
    useEffect(() => {
        if (isScanning || isAdvertising) {
            Animated.loop(
                Animated.sequence([
                    Animated.timing(pulseAnim, {
                        toValue: 1.2,
                        duration: 1000,
                        useNativeDriver: true,
                    }),
                    Animated.timing(pulseAnim, {
                        toValue: 1,
                        duration: 1000,
                        useNativeDriver: true,
                    }),
                ])
            ).start();
        } else {
            pulseAnim.setValue(1);
        }
    }, [isScanning, isAdvertising]);

    // Cursor blink
    useEffect(() => {
        const interval = setInterval(() => {
            setShowCursor(prev => !prev);
        }, 600);
        return () => clearInterval(interval);
    }, []);

    // Auto-scroll to bottom
    useEffect(() => {
        setTimeout(() => {
            scrollViewRef.current?.scrollToEnd({ animated: true });
        }, 100);
    }, [terminalLines]);

    const addLine = (text: string, type: TerminalLine['type'] = 'output') => {
        const newLine: TerminalLine = {
            id: `${Date.now()}_${Math.random()}`,
            text,
            type,
            timestamp: Date.now(),
        };
        setTerminalLines(prev => {
            // Keep only last 100 lines to prevent memory issues
            const updated = [...prev, newLine];
            if (updated.length > 100) {
                return updated.slice(-100);
            }
            return updated;
        });
    };

    const saveCommandHistory = async (history: string[]) => {
        try {
            const trimmed = history.slice(-30);
            await AsyncStorage.setItem('@ghostcomm_terminal_history', JSON.stringify(trimmed));
        } catch (error) {
            console.error('Failed to save command history:', error);
        }
    };

    const handleCommand = async () => {
        const command = currentInput.trim();
        if (!command) return;

        // Add command to display
        addLine(`$ ${command}`, 'input');

        // Add to history
        const newHistory = [...commandHistory, command];
        setCommandHistory(newHistory);
        saveCommandHistory(newHistory);
        setHistoryIndex(-1);

        // Clear input and process
        setCurrentInput('');
        setIsProcessing(true);

        try {
            const result = await executeCommand(command);

            // Display result cleanly
            const lines = result.split('\n');
            lines.forEach((line: string) => {
                if (line.trim()) {
                    addLine(line, 'output');
                }
            });
        } catch (error) {
            addLine(`Error: ${error}`, 'error');
        } finally {
            setIsProcessing(false);
        }
    };

    const handleHistoryNavigation = (direction: 'up' | 'down') => {
        if (commandHistory.length === 0) return;

        let newIndex = historyIndex;

        if (direction === 'up') {
            newIndex = historyIndex === -1
                ? commandHistory.length - 1
                : Math.max(0, historyIndex - 1);
        } else {
            newIndex = historyIndex === commandHistory.length - 1
                ? -1
                : Math.min(commandHistory.length - 1, historyIndex + 1);
        }

        setHistoryIndex(newIndex);
        setCurrentInput(newIndex === -1 ? '' : commandHistory[newIndex]);
    };

    const executeQuickCommand = (cmd: string) => {
        setCurrentInput(cmd);
        setTimeout(handleCommand, 100);
    };

    const renderLine = (line: TerminalLine) => {
        let style = styles.terminalText;

        switch (line.type) {
            case 'input':
                style = styles.inputText;
                break;
            case 'error':
                style = styles.errorText;
                break;
            case 'success':
                style = styles.successText;
                break;
            case 'warning':
                style = styles.warningText;
                break;
            case 'system':
                style = styles.systemText;
                break;
        }

        return (
            <Text key={line.id} style={style}>
                {line.text}
            </Text>
        );
    };

    const getStatusColor = () => {
        if (connectedNodes.size > 0) return '#00FF00';
        if (isScanning || isAdvertising) return '#FFAA00';
        return '#666666';
    };

    return (
        <KeyboardAvoidingView
            style={styles.container}
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
            keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
        >
            <Animated.View style={[styles.mainContainer, { opacity: fadeAnim }]}>
                {/* Minimalist Header */}
                <View style={styles.header}>
                    <View style={styles.headerLeft}>
                        <Text style={styles.headerTitle}>GHOSTCOMM</Text>
                        <Animated.View
                            style={[
                                styles.statusDot,
                                {
                                    backgroundColor: getStatusColor(),
                                    transform: [{ scale: pulseAnim }]
                                }
                            ]}
                        />
                    </View>

                    <TouchableOpacity
                        onPress={() => setShowQuickActions(!showQuickActions)}
                        style={styles.menuButton}
                    >
                        <Text style={styles.menuIcon}>{showQuickActions ? '×' : '≡'}</Text>
                    </TouchableOpacity>
                </View>

                {/* Quick Actions Panel (Hidden by default) */}
                {showQuickActions && (
                    <Animated.View style={styles.quickActionsPanel}>
                        <View style={styles.quickActionsRow}>
                            <TouchableOpacity
                                style={[styles.quickActionBtn, isScanning && styles.activeBtn]}
                                onPress={() => executeQuickCommand(isScanning ? 'stop' : 'scan')}
                            >
                                <Text style={styles.quickActionText}>
                                    {isScanning ? 'SCANNING' : 'SCAN'}
                                </Text>
                            </TouchableOpacity>

                            <TouchableOpacity
                                style={[styles.quickActionBtn, isAdvertising && styles.activeBtn]}
                                onPress={() => executeQuickCommand(isAdvertising ? 'stop' : 'beacon')}
                            >
                                <Text style={styles.quickActionText}>
                                    {isAdvertising ? 'BEACON ON' : 'BEACON'}
                                </Text>
                            </TouchableOpacity>

                            <TouchableOpacity
                                style={styles.quickActionBtn}
                                onPress={() => executeQuickCommand('nodes')}
                            >
                                <Text style={styles.quickActionText}>NODES</Text>
                            </TouchableOpacity>

                            <TouchableOpacity
                                style={styles.quickActionBtn}
                                onPress={() => executeQuickCommand('status')}
                            >
                                <Text style={styles.quickActionText}>STATUS</Text>
                            </TouchableOpacity>
                        </View>
                    </Animated.View>
                )}

                {/* Clean Status Bar */}
                <View style={styles.statusBar}>
                    <View style={styles.statusItem}>
                        <Text style={styles.statusLabel}>NODES</Text>
                        <Text style={styles.statusValue}>
                            {connectedNodes.size}/{discoveredNodes.size}
                        </Text>
                    </View>

                    <View style={styles.statusDivider} />

                    <View style={styles.statusItem}>
                        <Text style={styles.statusLabel}>MSG</Text>
                        <Text style={styles.statusValue}>
                            {networkStats.messagesSent + networkStats.messagesReceived}
                        </Text>
                    </View>

                    <View style={styles.statusDivider} />

                    <View style={styles.statusItem}>
                        <Text style={styles.statusLabel}>ID</Text>
                        <Text style={styles.statusValue}>
                            {keyPair?.getFingerprint().substring(0, 6).toUpperCase() || 'NONE'}
                        </Text>
                    </View>
                </View>

                {/* Terminal Output Area */}
                <ScrollView
                    ref={scrollViewRef}
                    style={styles.terminalOutput}
                    contentContainerStyle={styles.terminalContent}
                    showsVerticalScrollIndicator={false}
                >
                    {terminalLines.map(renderLine)}

                    {/* Current Input Line */}
                    <View style={styles.currentLine}>
                        <Text style={styles.prompt}>$ </Text>
                        <Text style={styles.currentInput}>{currentInput}</Text>
                        {!isProcessing && (
                            <Text style={styles.cursor}>
                                {showCursor ? '█' : ' '}
                            </Text>
                        )}
                        {isProcessing && (
                            <Text style={styles.processingIndicator}>...</Text>
                        )}
                    </View>
                </ScrollView>

                {/* Hidden Input */}
                <TextInput
                    ref={inputRef}
                    style={styles.hiddenInput}
                    value={currentInput}
                    onChangeText={setCurrentInput}
                    onSubmitEditing={handleCommand}
                    autoCapitalize="none"
                    autoCorrect={false}
                    autoFocus={true}
                    blurOnSubmit={false}
                />

                {/* Minimal Input Bar */}
                <View style={styles.inputBar}>
                    <TouchableOpacity
                        style={styles.inputButton}
                        onPress={() => handleHistoryNavigation('up')}
                    >
                        <Text style={styles.inputButtonText}>↑</Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={styles.inputButton}
                        onPress={() => handleHistoryNavigation('down')}
                    >
                        <Text style={styles.inputButtonText}>↓</Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={styles.helpButton}
                        onPress={() => executeQuickCommand('help')}
                    >
                        <Text style={styles.helpButtonText}>?</Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={styles.clearButton}
                        onPress={() => setTerminalLines([])}
                    >
                        <Text style={styles.clearButtonText}>CLR</Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={[styles.executeButton, isProcessing && styles.executeButtonDisabled]}
                        onPress={handleCommand}
                        disabled={isProcessing}
                    >
                        <Text style={styles.executeButtonText}>
                            {isProcessing ? '...' : 'RUN'}
                        </Text>
                    </TouchableOpacity>
                </View>
            </Animated.View>
        </KeyboardAvoidingView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000000',
    },
    mainContainer: {
        flex: 1,
    },

    // Header
    header: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingHorizontal: 15,
        paddingVertical: 10,
        backgroundColor: '#0A0A0A',
        borderBottomWidth: 1,
        borderBottomColor: '#1a1a1a',
    },
    headerLeft: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    headerTitle: {
        color: '#00FF00',
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        letterSpacing: 2,
    },
    statusDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        marginLeft: 10,
    },
    menuButton: {
        padding: 5,
    },
    menuIcon: {
        color: '#00FF00',
        fontSize: 20,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    },

    // Quick Actions Panel
    quickActionsPanel: {
        backgroundColor: '#0A0A0A',
        paddingVertical: 10,
        paddingHorizontal: 15,
        borderBottomWidth: 1,
        borderBottomColor: '#1a1a1a',
    },
    quickActionsRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
    },
    quickActionBtn: {
        flex: 1,
        marginHorizontal: 3,
        paddingVertical: 8,
        backgroundColor: '#111111',
        borderWidth: 1,
        borderColor: '#1a1a1a',
        alignItems: 'center',
    },
    activeBtn: {
        backgroundColor: '#001100',
        borderColor: '#00FF00',
    },
    quickActionText: {
        color: '#00FF00',
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        letterSpacing: 1,
    },

    // Status Bar
    statusBar: {
        flexDirection: 'row',
        backgroundColor: '#050505',
        paddingVertical: 8,
        paddingHorizontal: 15,
        borderBottomWidth: 1,
        borderBottomColor: '#1a1a1a',
    },
    statusItem: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
    },
    statusLabel: {
        color: '#666666',
        fontSize: 9,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        marginRight: 5,
        letterSpacing: 1,
    },
    statusValue: {
        color: '#00FF00',
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
    },
    statusDivider: {
        width: 1,
        height: 12,
        backgroundColor: '#1a1a1a',
        marginHorizontal: 10,
    },

    // Terminal Output
    terminalOutput: {
        flex: 1,
        backgroundColor: '#000000',
    },
    terminalContent: {
        padding: 15,
        paddingBottom: 20,
    },
    terminalText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        lineHeight: 16,
        marginBottom: 2,
        opacity: 0.9,
    },
    inputText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        lineHeight: 16,
        marginBottom: 2,
        opacity: 1,
    },
    errorText: {
        color: '#FF3333',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        lineHeight: 16,
        marginBottom: 2,
        opacity: 1,
    },
    successText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        lineHeight: 16,
        marginBottom: 2,
        opacity: 1,
    },
    warningText: {
        color: '#FFAA00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        lineHeight: 16,
        marginBottom: 2,
        opacity: 1,
    },
    systemText: {
        color: '#666666',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        lineHeight: 16,
        marginBottom: 2,
        opacity: 1,
    },

    // Current Line
    currentLine: {
        flexDirection: 'row',
        marginTop: 5,
    },
    prompt: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
    },
    currentInput: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        flex: 1,
    },
    cursor: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        opacity: 0.8,
    },
    processingIndicator: {
        color: '#FFAA00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
    },

    // Hidden Input
    hiddenInput: {
        position: 'absolute',
        left: -1000,
        width: 1,
        height: 1,
    },

    // Input Bar
    inputBar: {
        flexDirection: 'row',
        backgroundColor: '#0A0A0A',
        paddingVertical: 8,
        paddingHorizontal: 10,
        borderTopWidth: 1,
        borderTopColor: '#1a1a1a',
    },
    inputButton: {
        width: 35,
        height: 35,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: '#111111',
        marginRight: 8,
        borderWidth: 1,
        borderColor: '#1a1a1a',
    },
    inputButtonText: {
        color: '#00FF00',
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    },
    helpButton: {
        width: 35,
        height: 35,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: '#111111',
        marginRight: 8,
        borderWidth: 1,
        borderColor: '#1a1a1a',
    },
    helpButtonText: {
        color: '#00FF00',
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
    },
    clearButton: {
        paddingHorizontal: 15,
        height: 35,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: '#111111',
        marginRight: 8,
        borderWidth: 1,
        borderColor: '#1a1a1a',
    },
    clearButtonText: {
        color: '#666666',
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        letterSpacing: 1,
    },
    executeButton: {
        flex: 1,
        height: 35,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: '#001100',
        borderWidth: 1,
        borderColor: '#00FF00',
        marginLeft: 'auto',
    },
    executeButtonDisabled: {
        backgroundColor: '#0A0A0A',
        borderColor: '#1a1a1a',
    },
    executeButtonText: {
        color: '#00FF00',
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        letterSpacing: 2,
    },
});

export default TerminalScreen;