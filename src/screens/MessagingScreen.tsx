import React, { useState, useRef, useEffect } from 'react';
import {
    View,
    Text,
    TextInput,
    FlatList,
    TouchableOpacity,
    StyleSheet,
    KeyboardAvoidingView,
    Platform,
    Alert,
    Dimensions,
    Animated,
    Easing,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useGhostComm, type StoredMessage } from '../context/GhostCommContext';
import { MessageType } from '../ble';

const { width: SCREEN_WIDTH, height: SCREEN_HEIGHT } = Dimensions.get('window');

const MessagingScreen: React.FC = () => {
    const {
        messages,
        connectedNodes,
        discoveredNodes,
        sendMessage,
        clearMessages,
        keyPair,
        isScanning,
        addSystemLog,
    } = useGhostComm();

    const [inputText, setInputText] = useState('');
    const [selectedRecipient, setSelectedRecipient] = useState<string | null>(null);
    const [messageMode, setMessageMode] = useState<'DIRECT' | 'BROADCAST'>('DIRECT');
    const [showCursor, setShowCursor] = useState(true);
    const [alias, setAlias] = useState<string>('anonymous');
    const [isTyping, setIsTyping] = useState(false);
    const [showNodeSelector, setShowNodeSelector] = useState(false);

    const flatListRef = useRef<FlatList>(null);

    // Animation values
    const fadeAnim = useRef(new Animated.Value(0)).current;
    const slideAnim = useRef(new Animated.Value(30)).current;
    const pulseAnim = useRef(new Animated.Value(1)).current;
    const typeIndicatorAnim = useRef(new Animated.Value(0)).current;
    const messageSendAnim = useRef(new Animated.Value(0)).current;
    const scanLineAnim = useRef(new Animated.Value(-2)).current;

    // Load user alias
    useEffect(() => {
        const loadAlias = async () => {
            const savedAlias = await AsyncStorage.getItem('@ghostcomm_alias');
            if (savedAlias) setAlias(savedAlias);
        };
        loadAlias();

        // Initial fade in
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

    // Cursor blink effect
    useEffect(() => {
        const interval = setInterval(() => {
            setShowCursor(prev => !prev);
        }, 500);
        return () => clearInterval(interval);
    }, []);

    // Pulse animation for broadcast mode
    useEffect(() => {
        if (messageMode === 'BROADCAST') {
            const pulse = Animated.loop(
                Animated.sequence([
                    Animated.timing(pulseAnim, {
                        toValue: 1.05,
                        duration: 1000,
                        easing: Easing.inOut(Easing.ease),
                        useNativeDriver: true,
                    }),
                    Animated.timing(pulseAnim, {
                        toValue: 1,
                        duration: 1000,
                        easing: Easing.inOut(Easing.ease),
                        useNativeDriver: true,
                    }),
                ])
            );
            pulse.start();
            return () => pulse.stop();
        } else {
            pulseAnim.setValue(1);
            return undefined;
        }
    }, [messageMode]);

    // Typing indicator animation
    useEffect(() => {
        if (isTyping) {
            Animated.timing(typeIndicatorAnim, {
                toValue: 1,
                duration: 200,
                useNativeDriver: true,
            }).start();
        } else {
            Animated.timing(typeIndicatorAnim, {
                toValue: 0,
                duration: 200,
                useNativeDriver: true,
            }).start();
        }
    }, [isTyping]);

    // Scan line animation
    useEffect(() => {
        const scan = Animated.loop(
            Animated.timing(scanLineAnim, {
                toValue: SCREEN_HEIGHT,
                duration: 5000,
                easing: Easing.linear,
                useNativeDriver: true,
            })
        );
        scan.start();
        return () => scan.stop();
    }, []);

    // Auto-scroll to bottom when new messages arrive
    useEffect(() => {
        if (messages.length > 0) {
            setTimeout(() => {
                flatListRef.current?.scrollToEnd({ animated: true });
            }, 100);
        }
    }, [messages]);

    const formatFingerprint = (fp?: string) => {
        if (!fp) return 'UNKNOWN';
        return fp.substring(0, 8).toUpperCase();
    };

    const formatTime = (timestamp: number) => {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('en-US', {
            hour12: false,
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    };

    const getStatusIcon = (status: StoredMessage['status']) => {
        switch (status) {
            case 'QUEUED': return { icon: '◔', color: '#FFAA00' };
            case 'TRANSMITTING': return { icon: '◉', color: '#00AAFF' };
            case 'SENT': return { icon: '◉', color: '#00FF00' };
            case 'DELIVERED': return { icon: '◉◉', color: '#00FF00' };
            case 'FAILED': return { icon: '◉', color: '#FF3333' };
            case 'TIMEOUT': return { icon: '◉', color: '#FF6600' };
            default: return { icon: '◯', color: '#666666' };
        }
    };

    const handleSend = async () => {
        const message = inputText.trim();
        if (!message) return;

        // Command processing
        if (message.startsWith('/')) {
            const command = message.substring(1).toLowerCase();
            const parts = command.split(' ');

            switch (parts[0]) {
                case 'clear':
                    await clearMessages();
                    setInputText('');
                    return;
                case 'mode':
                    if (parts[1] === 'direct' || parts[1] === 'broadcast') {
                        setMessageMode(parts[1].toUpperCase() as 'DIRECT' | 'BROADCAST');
                        addSystemLog('INFO', `Message mode: ${parts[1].toUpperCase()}`);
                    }
                    setInputText('');
                    return;
                case 'nodes':
                    setShowNodeSelector(!showNodeSelector);
                    setInputText('');
                    return;
                case 'help':
                    addSystemLog('INFO', 'Commands: /clear, /mode [direct|broadcast], /nodes, /status');
                    setInputText('');
                    return;
                case 'status':
                    addSystemLog('INFO', `Nodes: ${connectedNodes.size} connected, ${discoveredNodes.size} discovered`);
                    setInputText('');
                    return;
                default:
                    addSystemLog('WARN', `Unknown command: ${parts[0]}`);
                    setInputText('');
                    return;
            }
        }

        // Send animation
        Animated.sequence([
            Animated.timing(messageSendAnim, {
                toValue: 1,
                duration: 100,
                useNativeDriver: true,
            }),
            Animated.timing(messageSendAnim, {
                toValue: 0,
                duration: 300,
                useNativeDriver: true,
            }),
        ]).start();

        try {
            const type = messageMode === 'BROADCAST' ? MessageType.BROADCAST : MessageType.DIRECT;
            const recipient = messageMode === 'BROADCAST' ? undefined : selectedRecipient || undefined;

            if (messageMode === 'DIRECT' && !recipient && connectedNodes.size === 0) {
                addSystemLog('ERROR', 'No connected nodes for direct message');
                return;
            }

            const finalRecipient = recipient ||
                (messageMode === 'DIRECT' && connectedNodes.size > 0
                    ? Array.from(connectedNodes.keys())[0]
                    : undefined);

            await sendMessage(message, finalRecipient, type);
            setInputText('');
            setIsTyping(false);

            addSystemLog('SUCCESS',
                messageMode === 'BROADCAST'
                    ? 'Broadcast queued'
                    : `Message sent to ${formatFingerprint(finalRecipient)}`
            );
        } catch (error) {
            addSystemLog('ERROR', 'Failed to send message');
        }
    };

    const renderMessage = ({ item, index }: { item: StoredMessage; index: number }) => {
        const isOwn = !item.isIncoming;
        const senderAlias = isOwn ? alias : 'peer';
        const senderId = isOwn
            ? formatFingerprint(keyPair?.getFingerprint())
            : formatFingerprint(item.senderFingerprint);
        const statusInfo = getStatusIcon(item.status);

        return (
            <Animated.View
                style={[
                    styles.messageContainer,
                    isOwn ? styles.ownMessageContainer : styles.otherMessageContainer,
                    {
                        opacity: fadeAnim,
                        transform: [
                            {
                                translateX: isOwn
                                    ? Animated.multiply(messageSendAnim, 10)
                                    : Animated.multiply(messageSendAnim, -10)
                            }
                        ]
                    }
                ]}
            >
                <View style={styles.messageHeader}>
                    <Text style={styles.messageTimestamp}>[{formatTime(item.timestamp)}]</Text>
                    <Text style={styles.messageSender}>
                        {senderAlias}@{senderId}
                    </Text>
                    {item.type === MessageType.BROADCAST && (
                        <View style={styles.broadcastBadge}>
                            <Text style={styles.broadcastBadgeText}>BROADCAST</Text>
                        </View>
                    )}
                </View>

                <View style={[styles.messageBubble, isOwn ? styles.ownBubble : styles.otherBubble]}>
                    <Text style={[styles.messageText, isOwn && styles.ownMessageText]}>
                        {item.content}
                    </Text>
                </View>

                {isOwn && (
                    <View style={styles.messageFooter}>
                        <Text style={[styles.statusIcon, { color: statusInfo.color }]}>
                            {statusInfo.icon}
                        </Text>
                        <Text style={[styles.messageStatus, { color: statusInfo.color }]}>
                            {item.status}
                        </Text>
                    </View>
                )}
            </Animated.View>
        );
    };

    const renderHeader = () => (
        <Animated.View style={[styles.header, { transform: [{ scale: pulseAnim }] }]}>
            <View style={styles.headerTop}>
                <View style={styles.modeIndicator}>
                    <Text style={styles.modeLabel}>MODE</Text>
                    <TouchableOpacity
                        style={[styles.modeButton, messageMode === 'BROADCAST' && styles.modeBroadcast]}
                        onPress={() => setMessageMode(messageMode === 'DIRECT' ? 'BROADCAST' : 'DIRECT')}
                        activeOpacity={0.7}
                    >
                        <Text style={styles.modeButtonText}>
                            {messageMode === 'BROADCAST' ? '⟟ BROADCAST' : '→ DIRECT'}
                        </Text>
                    </TouchableOpacity>
                </View>

                <View style={styles.connectionStatus}>
                    <View style={styles.statusItem}>
                        <Text style={[styles.statusDot, connectedNodes.size > 0 && styles.statusDotActive]}>
                            {connectedNodes.size > 0 ? '◉' : '○'}
                        </Text>
                        <Text style={styles.statusValue}>{connectedNodes.size}</Text>
                        <Text style={styles.statusLabel}>CONNECTED</Text>
                    </View>
                    <View style={styles.statusDivider} />
                    <View style={styles.statusItem}>
                        <Text style={[styles.statusDot, discoveredNodes.size > 0 && styles.statusDotActive]}>
                            {discoveredNodes.size > 0 ? '◉' : '○'}
                        </Text>
                        <Text style={styles.statusValue}>{discoveredNodes.size}</Text>
                        <Text style={styles.statusLabel}>DISCOVERED</Text>
                    </View>
                </View>
            </View>

            {messageMode === 'DIRECT' && (
                <TouchableOpacity
                    style={styles.recipientBar}
                    onPress={() => setShowNodeSelector(!showNodeSelector)}
                    activeOpacity={0.7}
                >
                    <Text style={styles.recipientLabel}>RECIPIENT</Text>
                    <Text style={styles.recipientValue}>
                        {selectedRecipient
                            ? `◈ ${formatFingerprint(selectedRecipient)}`
                            : connectedNodes.size > 0
                                ? `◈ ${formatFingerprint(Array.from(connectedNodes.keys())[0])} [AUTO]`
                                : '○ NO NODES'}
                    </Text>
                    <Text style={styles.recipientArrow}>▼</Text>
                </TouchableOpacity>
            )}

            {showNodeSelector && (
                <View style={styles.nodeSelector}>
                    {Array.from(discoveredNodes.keys()).map((nodeId) => (
                        <TouchableOpacity
                            key={nodeId}
                            style={[
                                styles.nodeOption,
                                selectedRecipient === nodeId && styles.nodeOptionSelected,
                                connectedNodes.has(nodeId) && styles.nodeOptionConnected,
                            ]}
                            onPress={() => {
                                setSelectedRecipient(nodeId);
                                setShowNodeSelector(false);
                            }}
                        >
                            <Text style={styles.nodeOptionText}>
                                {connectedNodes.has(nodeId) ? '◉' : '○'} {formatFingerprint(nodeId)}
                            </Text>
                            {connectedNodes.has(nodeId) && (
                                <Text style={styles.nodeOptionStatus}>ONLINE</Text>
                            )}
                        </TouchableOpacity>
                    ))}
                </View>
            )}
        </Animated.View>
    );

    const renderEmptyState = () => (
        <View style={styles.emptyState}>
            <Animated.View
                style={[
                    styles.emptyGraphic,
                    {
                        opacity: fadeAnim,
                        transform: [{ translateY: slideAnim }]
                    }
                ]}
            >
                <Text style={styles.asciiArt}>{`
     ╭───────────╮
     │  GHOSTCOMM│
     ╰─────┬─────╯
           │
      ╭────┴────╮
      │ NO MSGS │
      ╰─────────╯
           │
    ╭──────┴──────╮
    │ SEND  FIRST │
    ╰──────────────╯`}</Text>
            </Animated.View>

            <Animated.Text
                style={[
                    styles.emptyText,
                    { opacity: Animated.multiply(fadeAnim, 0.8) }
                ]}
            >
                {connectedNodes.size === 0
                    ? 'SCANNING FOR NODES...'
                    : 'READY TO TRANSMIT'}
            </Animated.Text>

            <Animated.View style={styles.emptyHints}>
                <Text style={styles.emptyHint}>• Type message and press [TX]</Text>
                <Text style={styles.emptyHint}>• Use /help for commands</Text>
                <Text style={styles.emptyHint}>• Toggle broadcast with [BRC]</Text>
            </Animated.View>
        </View>
    );

    return (
        <KeyboardAvoidingView
            style={styles.container}
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
            keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
        >
            {renderHeader()}

            <FlatList
                ref={flatListRef}
                data={messages}
                keyExtractor={(item) => item.id}
                renderItem={renderMessage}
                contentContainerStyle={styles.messagesList}
                ListEmptyComponent={renderEmptyState}
                inverted={false}
                showsVerticalScrollIndicator={false}
            />

            {/* Input Section */}
            <View style={styles.inputSection}>
                <Animated.View
                    style={[
                        styles.typingIndicator,
                        {
                            opacity: typeIndicatorAnim,
                            transform: [{ scale: typeIndicatorAnim }]
                        }
                    ]}
                >
                    <Text style={styles.typingText}>COMPOSING...</Text>
                </Animated.View>

                <View style={styles.inputContainer}>
                    <View style={styles.inputWrapper}>
                        <Text style={styles.inputPrefix}>
                            {messageMode === 'BROADCAST' ? '⟟' : '→'}
                        </Text>
                        <TextInput
                            style={styles.textInput}
                            value={inputText}
                            onChangeText={(text) => {
                                setInputText(text);
                                setIsTyping(text.length > 0);
                            }}
                            placeholder="Enter message or /command"
                            placeholderTextColor="#003300"
                            onSubmitEditing={handleSend}
                            returnKeyType="send"
                            autoCapitalize="none"
                            autoCorrect={false}
                            maxLength={256}
                        />
                        <Text style={styles.cursor}>
                            {showCursor && inputText.length === 0 ? '▊' : ''}
                        </Text>
                    </View>

                    <TouchableOpacity
                        style={[
                            styles.sendButton,
                            !inputText.trim() && styles.sendButtonDisabled,
                            inputText.trim() ? styles.sendButtonActive : null
                        ]}
                        onPress={handleSend}
                        disabled={!inputText.trim()}
                        activeOpacity={0.7}
                    >
                        <Text style={styles.sendButtonText}>TX</Text>
                    </TouchableOpacity>
                </View>

                {/* Enhanced Command Bar */}
                <View style={styles.commandBar}>
                    <TouchableOpacity
                        style={[styles.commandButton, messageMode === 'BROADCAST' && styles.commandButtonActive]}
                        onPress={() => setMessageMode(messageMode === 'DIRECT' ? 'BROADCAST' : 'DIRECT')}
                        activeOpacity={0.7}
                    >
                        <Text style={styles.commandButtonText}>BRC</Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={styles.commandButton}
                        onPress={() => setShowNodeSelector(!showNodeSelector)}
                        activeOpacity={0.7}
                    >
                        <Text style={styles.commandButtonText}>NODE</Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={styles.commandButton}
                        onPress={clearMessages}
                        activeOpacity={0.7}
                    >
                        <Text style={styles.commandButtonText}>CLR</Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={styles.commandButton}
                        onPress={() => setInputText('/help')}
                        activeOpacity={0.7}
                    >
                        <Text style={styles.commandButtonText}>?</Text>
                    </TouchableOpacity>

                    <View style={styles.charCounter}>
                        <Text style={[
                            styles.charCountText,
                            inputText.length > 200 && styles.charCountWarning
                        ]}>
                            {inputText.length}/256
                        </Text>
                    </View>
                </View>
            </View>

            {/* Scan line effect */}
            <Animated.View
                pointerEvents="none"
                style={[
                    styles.scanLine,
                    {
                        transform: [{ translateY: scanLineAnim }],
                    },
                ]}
            />
        </KeyboardAvoidingView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000000',
    },

    // Header Styles
    header: {
        backgroundColor: '#0A0A0A',
        borderBottomWidth: 1,
        borderBottomColor: '#00FF00',
    },
    headerTop: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: 12,
    },
    modeIndicator: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    modeLabel: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        marginRight: 10,
        letterSpacing: 1,
    },
    modeButton: {
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderWidth: 1,
        borderColor: '#00FF00',
        backgroundColor: 'transparent',
    },
    modeBroadcast: {
        backgroundColor: '#001100',
        borderColor: '#00FF00',
    },
    modeButtonText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    connectionStatus: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    statusItem: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingHorizontal: 10,
    },
    statusDot: {
        color: '#003300',
        fontSize: 12,
        marginRight: 5,
    },
    statusDotActive: {
        color: '#00FF00',
        textShadowColor: '#00FF00',
        textShadowRadius: 3,
    },
    statusValue: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        marginRight: 5,
    },
    statusLabel: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.6,
        letterSpacing: 1,
    },
    statusDivider: {
        width: 1,
        height: 20,
        backgroundColor: '#00FF00',
        opacity: 0.3,
    },

    // Recipient Bar
    recipientBar: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingVertical: 10,
        paddingHorizontal: 12,
        backgroundColor: '#001100',
        borderTopWidth: 1,
        borderTopColor: '#00FF00',
        opacity: 0.9,
    },
    recipientLabel: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        marginRight: 10,
        letterSpacing: 1,
    },
    recipientValue: {
        flex: 1,
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
    },
    recipientArrow: {
        color: '#00FF00',
        fontSize: 12,
        opacity: 0.6,
    },

    // Node Selector
    nodeSelector: {
        backgroundColor: '#0A0A0A',
        borderTopWidth: 1,
        borderTopColor: '#00FF00',
        maxHeight: 150,
    },
    nodeOption: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingVertical: 10,
        paddingHorizontal: 15,
        borderBottomWidth: 1,
        borderBottomColor: '#001100',
    },
    nodeOptionSelected: {
        backgroundColor: '#001100',
    },
    nodeOptionConnected: {
        borderLeftWidth: 3,
        borderLeftColor: '#00FF00',
    },
    nodeOptionText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
    },
    nodeOptionStatus: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 1,
    },

    // Messages List
    messagesList: {
        padding: 15,
        flexGrow: 1,
    },
    messageContainer: {
        marginBottom: 20,
    },
    ownMessageContainer: {
        alignItems: 'flex-end',
    },
    otherMessageContainer: {
        alignItems: 'flex-start',
    },
    messageHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 5,
        paddingHorizontal: 5,
    },
    messageTimestamp: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.5,
        marginRight: 8,
    },
    messageSender: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 10,
        fontWeight: 'bold',
        opacity: 0.7,
    },
    broadcastBadge: {
        marginLeft: 8,
        paddingHorizontal: 6,
        paddingVertical: 2,
        backgroundColor: '#001100',
        borderWidth: 1,
        borderColor: '#00FF00',
    },
    broadcastBadgeText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 8,
        letterSpacing: 1,
    },
    messageBubble: {
        maxWidth: SCREEN_WIDTH * 0.75,
        paddingVertical: 10,
        paddingHorizontal: 15,
        borderWidth: 1,
    },
    ownBubble: {
        backgroundColor: '#001100',
        borderColor: '#00FF00',
        borderTopRightRadius: 0,
    },
    otherBubble: {
        backgroundColor: '#0A0A0A',
        borderColor: '#00FF00',
        borderTopLeftRadius: 0,
        borderStyle: 'dashed',
    },
    messageText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        lineHeight: 18,
    },
    ownMessageText: {
        color: '#00FF00',
    },
    messageFooter: {
        flexDirection: 'row',
        alignItems: 'center',
        marginTop: 5,
        paddingHorizontal: 5,
    },
    statusIcon: {
        fontSize: 10,
        marginRight: 5,
    },
    messageStatus: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.7,
        letterSpacing: 1,
    },

    // Empty State
    emptyState: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        paddingVertical: 50,
    },
    emptyGraphic: {
        marginBottom: 30,
    },
    asciiArt: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        lineHeight: 14,
        opacity: 0.3,
        textAlign: 'center',
    },
    emptyText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 2,
        marginBottom: 20,
    },
    emptyHints: {
        alignItems: 'flex-start',
    },
    emptyHint: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        opacity: 0.5,
        marginVertical: 3,
    },

    // Input Section
    inputSection: {
        backgroundColor: '#0A0A0A',
        borderTopWidth: 1,
        borderTopColor: '#00FF00',
    },
    typingIndicator: {
        position: 'absolute',
        top: -20,
        left: 15,
        backgroundColor: '#000000',
        paddingHorizontal: 8,
        paddingVertical: 2,
        borderWidth: 1,
        borderColor: '#00FF00',
        zIndex: 1,
    },
    typingText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        letterSpacing: 1,
        opacity: 0.7,
    },
    inputContainer: {
        flexDirection: 'row',
        padding: 12,
        alignItems: 'center',
    },
    inputWrapper: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#000000',
        borderWidth: 1,
        borderColor: '#00FF00',
        paddingHorizontal: 12,
        marginRight: 10,
        height: 40,
    },
    inputPrefix: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        marginRight: 8,
        fontWeight: 'bold',
    },
    textInput: {
        flex: 1,
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        padding: 0,
    },
    cursor: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
    },
    sendButton: {
        width: 50,
        height: 40,
        justifyContent: 'center',
        alignItems: 'center',
        borderWidth: 2,
        borderColor: '#00FF00',
        backgroundColor: 'transparent',
    },
    sendButtonDisabled: {
        opacity: 0.3,
        borderStyle: 'dashed',
    },
    sendButtonActive: {
        backgroundColor: '#00FF00',
    },
    sendButtonText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 1,
    },

    // Command Bar
    commandBar: {
        flexDirection: 'row',
        paddingHorizontal: 12,
        paddingBottom: 8,
        alignItems: 'center',
        borderTopWidth: 1,
        borderTopColor: '#001100',
    },
    commandButton: {
        paddingHorizontal: 12,
        paddingVertical: 6,
        marginRight: 8,
        borderWidth: 1,
        borderColor: '#00FF00',
        backgroundColor: 'transparent',
        opacity: 0.7,
    },
    commandButtonActive: {
        backgroundColor: '#001100',
        opacity: 1,
    },
    commandButtonText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 10,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    charCounter: {
        marginLeft: 'auto',
        paddingHorizontal: 10,
    },
    charCountText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.5,
    },
    charCountWarning: {
        color: '#FFAA00',
        opacity: 0.8,
    },

    // Effects
    scanLine: {
        position: 'absolute',
        left: 0,
        right: 0,
        height: 1,
        backgroundColor: '#00FF00',
        opacity: 0.05,
    },
});

export default MessagingScreen;