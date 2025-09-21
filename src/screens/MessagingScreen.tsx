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
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useGhostComm, type StoredMessage } from '../context/GhostCommContext';
import { useTheme } from '../context/ThemeContext';
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
        addSystemLog,
    } = useGhostComm();

    const { currentTheme } = useTheme();

    const [inputText, setInputText] = useState('');
    const [selectedRecipient, setSelectedRecipient] = useState<string | null>(null);
    const [messageMode, setMessageMode] = useState<'DIRECT' | 'BROADCAST'>('DIRECT');
    const [alias, setAlias] = useState<string>('anonymous');
    const [showNodePanel, setShowNodePanel] = useState(false);

    const flatListRef = useRef<FlatList>(null);
    const fadeAnim = useRef(new Animated.Value(0)).current;

    // Load user alias
    useEffect(() => {
        const loadAlias = async () => {
            const savedAlias = await AsyncStorage.getItem('@ghostcomm_alias');
            if (savedAlias) setAlias(savedAlias);
        };
        loadAlias();

        // Smooth fade in
        Animated.timing(fadeAnim, {
            toValue: 1,
            duration: 400,
            useNativeDriver: true,
        }).start();
    }, []);

    // Auto-scroll to bottom when new messages arrive
    useEffect(() => {
        if (messages.length > 0) {
            setTimeout(() => {
                flatListRef.current?.scrollToEnd({ animated: true });
            }, 100);
        }
    }, [messages]);

    // Auto-select first connected node
    useEffect(() => {
        if (!selectedRecipient && connectedNodes.size > 0) {
            setSelectedRecipient(Array.from(connectedNodes.keys())[0]);
        }
    }, [connectedNodes]);

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
        });
    };

    const getStatusColor = (status: StoredMessage['status']) => {
        switch (status) {
            case 'SENT':
            case 'DELIVERED':
                return currentTheme.success;
            case 'FAILED':
            case 'TIMEOUT':
                return currentTheme.error;
            case 'QUEUED':
            case 'TRANSMITTING':
                return currentTheme.warning;
            default:
                return currentTheme.textTertiary;
        }
    };

    const handleSend = async () => {
        const message = inputText.trim();
        if (!message) return;

        try {
            const type = messageMode === 'BROADCAST' ? MessageType.BROADCAST : MessageType.DIRECT;
            const recipient = messageMode === 'BROADCAST' ? undefined : selectedRecipient || undefined;

            if (messageMode === 'DIRECT' && !recipient && connectedNodes.size === 0) {
                Alert.alert('No Recipients', 'No connected nodes available for direct message.');
                return;
            }

            await sendMessage(message, recipient, type);
            setInputText('');
        } catch (error) {
            Alert.alert('Send Failed', 'Failed to send message. Please try again.');
        }
    };

    const renderMessage = ({ item }: { item: StoredMessage }) => {
        const isOwn = !item.isIncoming;
        const time = formatTime(item.timestamp);

        return (
            <View style={[
                styles.messageWrapper,
                isOwn ? styles.ownMessageWrapper : styles.otherMessageWrapper
            ]}>
                <View style={[
                    styles.messageBubble,
                    { backgroundColor: isOwn ? currentTheme.primary : currentTheme.surface },
                    isOwn ? styles.ownBubble : styles.otherBubble
                ]}>
                    {!isOwn && (
                        <Text style={[styles.senderName, { color: currentTheme.textSecondary }]}>
                            {formatFingerprint(item.senderFingerprint)}
                        </Text>
                    )}
                    
                    <Text style={[
                        styles.messageText,
                        { color: isOwn ? currentTheme.surface : currentTheme.text }
                    ]}>
                        {item.content}
                    </Text>

                    <View style={styles.messageFooter}>
                        <Text style={[
                            styles.messageTime,
                            { color: isOwn ? currentTheme.surface : currentTheme.textTertiary }
                        ]}>
                            {time}
                        </Text>
                        
                        {item.type === MessageType.BROADCAST && (
                            <Text style={[
                                styles.broadcastIndicator,
                                { color: isOwn ? currentTheme.surface : currentTheme.textTertiary }
                            ]}>
                                • BROADCAST
                            </Text>
                        )}
                        
                        {isOwn && (
                            <Text style={[
                                styles.statusIndicator,
                                { color: getStatusColor(item.status) }
                            ]}>
                                • {item.status}
                            </Text>
                        )}
                    </View>
                </View>
            </View>
        );
    };

    const renderEmptyState = () => (
        <View style={styles.emptyState}>
            <View style={[styles.emptyIconContainer, { backgroundColor: currentTheme.surface }]}>
                <Text style={[styles.emptyIcon, { color: currentTheme.textTertiary }]}>○</Text>
            </View>
            <Text style={[styles.emptyTitle, { color: currentTheme.text }]}>
                No Messages Yet
            </Text>
            <Text style={[styles.emptySubtitle, { color: currentTheme.textSecondary }]}>
                {connectedNodes.size === 0
                    ? 'Waiting for nodes to connect...'
                    : 'Send a message to start the conversation'}
            </Text>
        </View>
    );

    const renderNodeOption = (nodeId: string) => {
        const isConnected = connectedNodes.has(nodeId);
        const isSelected = selectedRecipient === nodeId;

        return (
            <TouchableOpacity
                key={nodeId}
                style={[
                    styles.nodeOption,
                    { 
                        backgroundColor: isSelected ? currentTheme.primary : currentTheme.surface,
                        borderColor: currentTheme.border
                    }
                ]}
                onPress={() => {
                    setSelectedRecipient(nodeId);
                    setShowNodePanel(false);
                }}
                activeOpacity={0.8}
            >
                <View style={styles.nodeInfo}>
                    <Text style={[
                        styles.nodeId,
                        { color: isSelected ? currentTheme.surface : currentTheme.text }
                    ]}>
                        {formatFingerprint(nodeId)}
                    </Text>
                    <Text style={[
                        styles.nodeStatus,
                        { color: isSelected ? currentTheme.surface : (isConnected ? currentTheme.success : currentTheme.textTertiary) }
                    ]}>
                        {isConnected ? 'CONNECTED' : 'DISCOVERED'}
                    </Text>
                </View>
                {isConnected && (
                    <View style={[styles.connectedDot, { backgroundColor: currentTheme.success }]} />
                )}
            </TouchableOpacity>
        );
    };

    return (
        <KeyboardAvoidingView
            style={[styles.container, { backgroundColor: currentTheme.background }]}
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
            keyboardVerticalOffset={Platform.OS === 'ios' ? 90 : 0}
        >
            <Animated.View style={[styles.mainContainer, { opacity: fadeAnim }]}>
                {/* Clean Header */}
                <View style={[styles.header, { backgroundColor: currentTheme.surface }]}>
                    <View style={styles.headerTop}>
                        <Text style={[styles.headerTitle, { color: currentTheme.text }]}>
                            MESSAGES
                        </Text>
                        <View style={styles.connectionIndicator}>
                            <View style={[
                                styles.connectionDot,
                                { backgroundColor: connectedNodes.size > 0 ? currentTheme.success : currentTheme.textTertiary }
                            ]} />
                            <Text style={[styles.connectionText, { color: currentTheme.textSecondary }]}>
                                {connectedNodes.size} / {discoveredNodes.size}
                            </Text>
                        </View>
                    </View>

                    {/* Mode and Recipient Bar */}
                    <View style={styles.controlBar}>
                        {/* Mode Toggle */}
                        <TouchableOpacity
                            style={[
                                styles.modeToggle,
                                { 
                                    backgroundColor: messageMode === 'BROADCAST' ? currentTheme.primary : 'transparent',
                                    borderColor: currentTheme.border
                                }
                            ]}
                            onPress={() => setMessageMode(messageMode === 'DIRECT' ? 'BROADCAST' : 'DIRECT')}
                            activeOpacity={0.8}
                        >
                            <Text style={[
                                styles.modeText,
                                { color: messageMode === 'BROADCAST' ? currentTheme.surface : currentTheme.text }
                            ]}>
                                {messageMode}
                            </Text>
                        </TouchableOpacity>

                        {/* Recipient Selector (for Direct mode) */}
                        {messageMode === 'DIRECT' && (
                            <TouchableOpacity
                                style={[styles.recipientSelector, { borderColor: currentTheme.border }]}
                                onPress={() => setShowNodePanel(!showNodePanel)}
                                activeOpacity={0.8}
                            >
                                <Text style={[styles.recipientLabel, { color: currentTheme.textSecondary }]}>
                                    TO:
                                </Text>
                                <Text style={[styles.recipientValue, { color: currentTheme.text }]}>
                                    {selectedRecipient 
                                        ? formatFingerprint(selectedRecipient)
                                        : 'SELECT NODE'}
                                </Text>
                                <Text style={[styles.dropdownArrow, { color: currentTheme.textSecondary }]}>
                                    ▼
                                </Text>
                            </TouchableOpacity>
                        )}

                        {/* Broadcast indicator */}
                        {messageMode === 'BROADCAST' && (
                            <View style={styles.broadcastInfo}>
                                <Text style={[styles.broadcastLabel, { color: currentTheme.textSecondary }]}>
                                    Broadcasting to all {discoveredNodes.size} discovered nodes
                                </Text>
                            </View>
                        )}
                    </View>
                </View>

                {/* Node Selection Panel */}
                {showNodePanel && (
                    <View style={[styles.nodePanel, { backgroundColor: currentTheme.surface }]}>
                        <Text style={[styles.nodePanelTitle, { color: currentTheme.text }]}>
                            SELECT RECIPIENT
                        </Text>
                        <View style={styles.nodeList}>
                            {Array.from(discoveredNodes.keys()).map(renderNodeOption)}
                        </View>
                    </View>
                )}

                {/* Messages List */}
                <FlatList
                    ref={flatListRef}
                    data={messages}
                    keyExtractor={(item) => item.id}
                    renderItem={renderMessage}
                    contentContainerStyle={styles.messagesList}
                    ListEmptyComponent={renderEmptyState}
                    showsVerticalScrollIndicator={false}
                />

                {/* Clean Input Area */}
                <View style={[styles.inputArea, { backgroundColor: currentTheme.surface }]}>
                    <View style={[styles.inputContainer, { borderColor: currentTheme.border }]}>
                        <TextInput
                            style={[styles.textInput, { color: currentTheme.text }]}
                            value={inputText}
                            onChangeText={setInputText}
                            placeholder="Type a message..."
                            placeholderTextColor={currentTheme.textTertiary}
                            onSubmitEditing={handleSend}
                            returnKeyType="send"
                            multiline
                            maxLength={256}
                        />
                        
                        <TouchableOpacity
                            style={[
                                styles.sendButton,
                                { 
                                    backgroundColor: inputText.trim() ? currentTheme.primary : currentTheme.surface,
                                    borderColor: currentTheme.border
                                }
                            ]}
                            onPress={handleSend}
                            disabled={!inputText.trim()}
                            activeOpacity={0.8}
                        >
                            <Text style={[
                                styles.sendButtonText,
                                { color: inputText.trim() ? currentTheme.surface : currentTheme.textTertiary }
                            ]}>
                                →
                            </Text>
                        </TouchableOpacity>
                    </View>

                    {/* Quick Actions */}
                    <View style={styles.quickActions}>
                        <TouchableOpacity
                            style={[styles.quickAction, { borderColor: currentTheme.border }]}
                            onPress={clearMessages}
                        >
                            <Text style={[styles.quickActionText, { color: currentTheme.textSecondary }]}>
                                CLEAR
                            </Text>
                        </TouchableOpacity>
                        
                        <Text style={[styles.charCounter, { color: currentTheme.textTertiary }]}>
                            {inputText.length}/256
                        </Text>
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
    connectionIndicator: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    connectionDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        marginRight: 8,
    },
    connectionText: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },

    // Control Bar
    controlBar: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    modeToggle: {
        paddingVertical: 8,
        paddingHorizontal: 16,
        borderWidth: 1,
        marginRight: 12,
    },
    modeText: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
    },
    recipientSelector: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        paddingVertical: 8,
        paddingHorizontal: 12,
        borderWidth: 1,
    },
    recipientLabel: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        marginRight: 8,
    },
    recipientValue: {
        flex: 1,
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
    },
    dropdownArrow: {
        fontSize: 10,
    },
    broadcastInfo: {
        flex: 1,
    },
    broadcastLabel: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        fontStyle: 'italic',
    },

    // Node Panel
    nodePanel: {
        maxHeight: 200,
        borderBottomWidth: 1,
        borderBottomColor: 'rgba(0,0,0,0.1)',
    },
    nodePanelTitle: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 2,
        padding: 15,
    },
    nodeList: {
        paddingHorizontal: 15,
        paddingBottom: 15,
    },
    nodeOption: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingVertical: 12,
        paddingHorizontal: 15,
        marginBottom: 8,
        borderWidth: 1,
    },
    nodeInfo: {
        flex: 1,
    },
    nodeId: {
        fontSize: 13,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
        marginBottom: 3,
    },
    nodeStatus: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1,
    },
    connectedDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
    },

    // Messages List
    messagesList: {
        padding: 20,
        flexGrow: 1,
    },
    messageWrapper: {
        marginBottom: 12,
    },
    ownMessageWrapper: {
        alignItems: 'flex-end',
    },
    otherMessageWrapper: {
        alignItems: 'flex-start',
    },
    messageBubble: {
        maxWidth: SCREEN_WIDTH * 0.75,
        paddingVertical: 12,
        paddingHorizontal: 16,
    },
    ownBubble: {
        borderTopRightRadius: 4,
        borderTopLeftRadius: 20,
        borderBottomLeftRadius: 20,
        borderBottomRightRadius: 20,
    },
    otherBubble: {
        borderTopLeftRadius: 4,
        borderTopRightRadius: 20,
        borderBottomLeftRadius: 20,
        borderBottomRightRadius: 20,
    },
    senderName: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        marginBottom: 5,
        letterSpacing: 0.5,
    },
    messageText: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        lineHeight: 20,
    },
    messageFooter: {
        flexDirection: 'row',
        alignItems: 'center',
        marginTop: 5,
    },
    messageTime: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },
    broadcastIndicator: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        marginLeft: 6,
    },
    statusIndicator: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        marginLeft: 6,
    },

    // Empty State
    emptyState: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 60,
    },
    emptyIconContainer: {
        width: 80,
        height: 80,
        borderRadius: 40,
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 20,
    },
    emptyIcon: {
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

    // Input Area
    inputArea: {
        paddingHorizontal: 20,
        paddingTop: 15,
        paddingBottom: 15,
        elevation: 8,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: -2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
    },
    inputContainer: {
        flexDirection: 'row',
        alignItems: 'flex-end',
        borderWidth: 1,
        minHeight: 44,
        maxHeight: 100,
    },
    textInput: {
        flex: 1,
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        paddingVertical: 10,
        paddingHorizontal: 15,
        maxHeight: 80,
    },
    sendButton: {
        width: 44,
        height: 44,
        alignItems: 'center',
        justifyContent: 'center',
        borderLeftWidth: 1,
    },
    sendButtonText: {
        fontSize: 20,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },

    // Quick Actions
    quickActions: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginTop: 10,
    },
    quickAction: {
        paddingVertical: 6,
        paddingHorizontal: 12,
        borderWidth: 1,
    },
    quickActionText: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1,
    },
    charCounter: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },
});

export default MessagingScreen;