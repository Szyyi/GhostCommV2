import React, { useState, useEffect, useRef } from 'react';
import {
    View,
    Text,
    ScrollView,
    StyleSheet,
    TouchableOpacity,
    TextInput,
    Platform,
    Alert,
    Clipboard,
    Animated,
    Dimensions,
    Switch,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useGhostComm } from '../context/GhostCommContext';
import { useTheme } from '../context/ThemeContext';

const { width: SCREEN_WIDTH } = Dimensions.get('window');

const SettingsScreen: React.FC = () => {
    const {
        keyPair,
        networkStats,
        clearMessages,
        clearLogs,
        addSystemLog,
    } = useGhostComm();

    const { currentTheme, themeName, setTheme, availableThemes } = useTheme();

    const [alias, setAlias] = useState('anonymous');
    const [editingAlias, setEditingAlias] = useState(false);
    const [newAlias, setNewAlias] = useState('');
    const [copiedFingerprint, setCopiedFingerprint] = useState(false);

    // Settings state
    const [settings, setSettings] = useState({
        autoConnect: true,
        autoScan: true,
        notifications: true,
        vibration: true,
        soundEffects: false,
        debugMode: false,
    });

    // Animation
    const fadeAnim = useRef(new Animated.Value(0)).current;

    useEffect(() => {
        Animated.timing(fadeAnim, {
            toValue: 1,
            duration: 400,
            useNativeDriver: true,
        }).start();

        loadSettings();
    }, []);

    const loadSettings = async () => {
        try {
            const [savedAlias, savedSettings] = await Promise.all([
                AsyncStorage.getItem('@ghostcomm_alias'),
                AsyncStorage.getItem('@ghostcomm_settings'),
            ]);

            if (savedAlias) setAlias(savedAlias);
            if (savedSettings) {
                setSettings(JSON.parse(savedSettings));
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    };

    const saveSettings = async (key: string, value: any) => {
        const newSettings = { ...settings, [key]: value };
        try {
            await AsyncStorage.setItem('@ghostcomm_settings', JSON.stringify(newSettings));
            setSettings(newSettings);
        } catch (error) {
            console.error('Failed to save settings:', error);
        }
    };

    const handleAliasUpdate = async () => {
        const trimmed = newAlias.trim();
        if (trimmed && trimmed.length <= 16) {
            await AsyncStorage.setItem('@ghostcomm_alias', trimmed);
            setAlias(trimmed);
            setEditingAlias(false);
            setNewAlias('');
        }
    };

    const handleCopyFingerprint = () => {
        if (keyPair) {
            Clipboard.setString(keyPair.getFingerprint());
            setCopiedFingerprint(true);
            setTimeout(() => setCopiedFingerprint(false), 2000);
        }
    };

    const handleExportIdentity = () => {
        if (!keyPair) return;

        const exportData = {
            identity: keyPair.exportKeys(),
            alias: alias,
            timestamp: Date.now(),
        };

        const encoded = Buffer.from(JSON.stringify(exportData)).toString('base64');
        Clipboard.setString(encoded);
        
        Alert.alert('Identity Exported', 'Your identity has been copied to clipboard. Keep it safe!');
    };

    const handleClearData = () => {
        Alert.alert(
            'Clear All Data',
            'This will delete all messages and logs. Continue?',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Clear',
                    style: 'destructive',
                    onPress: () => {
                        clearMessages();
                        clearLogs();
                    }
                }
            ]
        );
    };

    const handleFactoryReset = () => {
        Alert.alert(
            'Factory Reset',
            'This will permanently delete:\n• Your identity\n• All messages\n• All settings\n\nThis cannot be undone.',
            [
                { text: 'Cancel', style: 'cancel' },
                {
                    text: 'Reset Everything',
                    style: 'destructive',
                    onPress: async () => {
                        await AsyncStorage.clear();
                        Alert.alert('Reset Complete', 'Please restart the app.');
                    }
                }
            ]
        );
    };

    const formatFingerprint = (fp: string) => {
        return fp.substring(0, 16).toUpperCase().match(/.{1,4}/g)?.join(' ') || '';
    };

    const renderSection = (title: string, icon: string, children: React.ReactNode) => (
        <View style={[styles.section, { backgroundColor: currentTheme.surface }]}>
            <View style={styles.sectionHeader}>
                <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>{icon}</Text>
                <Text style={[styles.sectionTitle, { color: currentTheme.text }]}>{title}</Text>
            </View>
            <View style={styles.sectionContent}>
                {children}
            </View>
        </View>
    );

    const renderSettingRow = (
        label: string,
        description: string,
        key: keyof typeof settings,
        value: boolean
    ) => (
        <View style={styles.settingRow}>
            <View style={styles.settingInfo}>
                <Text style={[styles.settingLabel, { color: currentTheme.text }]}>{label}</Text>
                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                    {description}
                </Text>
            </View>
            <Switch
                value={value}
                onValueChange={(val) => saveSettings(key, val)}
                trackColor={{ 
                    false: currentTheme.border, 
                    true: currentTheme.primary + '66' 
                }}
                thumbColor={value ? currentTheme.primary : currentTheme.textTertiary}
                ios_backgroundColor={currentTheme.border}
            />
        </View>
    );

    return (
        <ScrollView
            style={[styles.container, { backgroundColor: currentTheme.background }]}
            showsVerticalScrollIndicator={false}
        >
            <Animated.View style={{ opacity: fadeAnim }}>
                {/* Header */}
                <View style={styles.header}>
                    <Text style={[styles.headerTitle, { color: currentTheme.text }]}>SETTINGS</Text>
                </View>

                {/* Identity Section */}
                {renderSection('IDENTITY', '◈', (
                    <>
                        {/* Fingerprint Card */}
                        <View style={[styles.card, { backgroundColor: currentTheme.background }]}>
                            <Text style={[styles.cardLabel, { color: currentTheme.textSecondary }]}>
                                NODE FINGERPRINT
                            </Text>
                            <TouchableOpacity 
                                onPress={handleCopyFingerprint}
                                activeOpacity={0.8}
                                style={styles.fingerprintContainer}
                            >
                                <Text style={[styles.fingerprintText, { color: currentTheme.text }]}>
                                    {keyPair ? formatFingerprint(keyPair.getFingerprint()) : 'NOT INITIALIZED'}
                                </Text>
                                <View style={[
                                    styles.copyBadge, 
                                    { backgroundColor: copiedFingerprint ? currentTheme.success : currentTheme.primary }
                                ]}>
                                    <Text style={[styles.copyBadgeText, { color: currentTheme.surface }]}>
                                        {copiedFingerprint ? '✓' : '⧉'}
                                    </Text>
                                </View>
                            </TouchableOpacity>
                            <Text style={[styles.cardHint, { color: currentTheme.textTertiary }]}>
                                Tap to copy
                            </Text>
                        </View>

                        {/* Alias Card */}
                        <View style={[styles.card, { backgroundColor: currentTheme.background }]}>
                            <Text style={[styles.cardLabel, { color: currentTheme.textSecondary }]}>
                                CALLSIGN
                            </Text>
                            {editingAlias ? (
                                <View style={styles.aliasEditContainer}>
                                    <TextInput
                                        style={[styles.aliasInput, { 
                                            color: currentTheme.text,
                                            borderColor: currentTheme.border
                                        }]}
                                        value={newAlias}
                                        onChangeText={setNewAlias}
                                        placeholder="Enter callsign"
                                        placeholderTextColor={currentTheme.textTertiary}
                                        maxLength={16}
                                        autoCapitalize="none"
                                        autoCorrect={false}
                                        returnKeyType="done"
                                        onSubmitEditing={handleAliasUpdate}
                                    />
                                    <View style={styles.aliasActions}>
                                        <TouchableOpacity
                                            style={[styles.aliasButton, { backgroundColor: currentTheme.primary }]}
                                            onPress={handleAliasUpdate}
                                            activeOpacity={0.8}
                                        >
                                            <Text style={[styles.aliasButtonText, { color: currentTheme.surface }]}>
                                                Save
                                            </Text>
                                        </TouchableOpacity>
                                        <TouchableOpacity
                                            style={[styles.aliasButton, styles.cancelButton, { 
                                                borderColor: currentTheme.border 
                                            }]}
                                            onPress={() => {
                                                setEditingAlias(false);
                                                setNewAlias('');
                                            }}
                                            activeOpacity={0.8}
                                        >
                                            <Text style={[styles.aliasButtonText, { color: currentTheme.textSecondary }]}>
                                                Cancel
                                            </Text>
                                        </TouchableOpacity>
                                    </View>
                                </View>
                            ) : (
                                <TouchableOpacity
                                    style={styles.aliasDisplay}
                                    onPress={() => {
                                        setNewAlias(alias);
                                        setEditingAlias(true);
                                    }}
                                    activeOpacity={0.8}
                                >
                                    <Text style={[styles.aliasText, { color: currentTheme.text }]}>
                                        {alias}
                                    </Text>
                                    <Text style={[styles.editIcon, { color: currentTheme.primary }]}>
                                        ✎
                                    </Text>
                                </TouchableOpacity>
                            )}
                        </View>

                        <TouchableOpacity
                            style={[styles.actionButton, { borderColor: currentTheme.primary }]}
                            onPress={handleExportIdentity}
                            activeOpacity={0.8}
                        >
                            <Text style={[styles.actionButtonText, { color: currentTheme.primary }]}>
                                Export Identity
                            </Text>
                        </TouchableOpacity>
                    </>
                ))}

                {/* Appearance Section */}
                {renderSection('APPEARANCE', '◉', (
                    <>
                        <Text style={[styles.themeLabel, { color: currentTheme.textSecondary }]}>
                            THEME
                        </Text>
                        <View style={styles.themeGrid}>
                            {Object.entries(availableThemes).slice(0, 6).map(([key, theme]) => (
                                <TouchableOpacity
                                    key={key}
                                    style={[
                                        styles.themeOption,
                                        { 
                                            backgroundColor: currentTheme.background,
                                            borderColor: themeName === key ? currentTheme.primary : currentTheme.border
                                        }
                                    ]}
                                    onPress={() => setTheme(key)}
                                    activeOpacity={0.8}
                                >
                                    <View style={[styles.themePreview, { backgroundColor: theme.primary }]} />
                                    <Text style={[styles.themeName, { color: currentTheme.text }]}>
                                        {theme.name}
                                    </Text>
                                </TouchableOpacity>
                            ))}
                        </View>
                    </>
                ))}

                {/* Network Section */}
                {renderSection('NETWORK', '⟟', (
                    <>
                        {renderSettingRow(
                            'Auto Connect',
                            'Automatically connect to discovered nodes',
                            'autoConnect',
                            settings.autoConnect
                        )}
                        {renderSettingRow(
                            'Auto Scan',
                            'Continuously scan for new nodes',
                            'autoScan',
                            settings.autoScan
                        )}
                    </>
                ))}

                {/* Notifications Section */}
                {renderSection('NOTIFICATIONS', '◎', (
                    <>
                        {renderSettingRow(
                            'Message Alerts',
                            'Show notifications for new messages',
                            'notifications',
                            settings.notifications
                        )}
                        {renderSettingRow(
                            'Vibration',
                            'Haptic feedback for actions',
                            'vibration',
                            settings.vibration
                        )}
                        {renderSettingRow(
                            'Sound Effects',
                            'Audio feedback for events',
                            'soundEffects',
                            settings.soundEffects
                        )}
                    </>
                ))}

                {/* Advanced Section */}
                {renderSection('ADVANCED', '⚙', (
                    <>
                        {renderSettingRow(
                            'Debug Mode',
                            'Show detailed system logs',
                            'debugMode',
                            settings.debugMode
                        )}
                        
                        <View style={styles.dangerZone}>
                            <TouchableOpacity
                                style={[styles.dangerButton, { borderColor: currentTheme.warning }]}
                                onPress={handleClearData}
                                activeOpacity={0.8}
                            >
                                <Text style={[styles.dangerButtonText, { color: currentTheme.warning }]}>
                                    Clear Data
                                </Text>
                            </TouchableOpacity>

                            <TouchableOpacity
                                style={[styles.dangerButton, { 
                                    borderColor: currentTheme.error,
                                    backgroundColor: currentTheme.error + '11'
                                }]}
                                onPress={handleFactoryReset}
                                activeOpacity={0.8}
                            >
                                <Text style={[styles.dangerButtonText, { color: currentTheme.error }]}>
                                    Factory Reset
                                </Text>
                            </TouchableOpacity>
                        </View>
                    </>
                ))}

                {/* About Section */}
                {renderSection('ABOUT', 'ℹ', (
                    <View style={styles.aboutContainer}>
                        <View style={styles.aboutRow}>
                            <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>
                                Version
                            </Text>
                            <Text style={[styles.aboutValue, { color: currentTheme.text }]}>
                                2.0.0
                            </Text>
                        </View>
                        <View style={styles.aboutRow}>
                            <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>
                                Protocol
                            </Text>
                            <Text style={[styles.aboutValue, { color: currentTheme.text }]}>
                                GhostMesh 1.0
                            </Text>
                        </View>
                        <View style={styles.aboutRow}>
                            <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>
                                Encryption
                            </Text>
                            <Text style={[styles.aboutValue, { color: currentTheme.text }]}>
                                ChaCha20-Poly1305
                            </Text>
                        </View>
                        <View style={styles.aboutRow}>
                            <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>
                                Signature
                            </Text>
                            <Text style={[styles.aboutValue, { color: currentTheme.text }]}>
                                Ed25519
                            </Text>
                        </View>
                    </View>
                ))}

                {/* Footer */}
                <View style={styles.footer}>
                    <Text style={[styles.footerText, { color: currentTheme.textTertiary }]}>
                        GHOSTCOMM • SECURE MESH NETWORK
                    </Text>
                </View>
            </Animated.View>
        </ScrollView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
    },

    // Header
    header: {
        paddingTop: 20,
        paddingBottom: 10,
        paddingHorizontal: 20,
    },
    headerTitle: {
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        letterSpacing: 3,
    },

    // Sections
    section: {
        marginHorizontal: 20,
        marginBottom: 20,
        borderRadius: 0,
        overflow: 'hidden',
    },
    sectionHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingVertical: 12,
        paddingHorizontal: 16,
    },
    sectionIcon: {
        fontSize: 16,
        marginRight: 10,
    },
    sectionTitle: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 2,
    },
    sectionContent: {
        padding: 16,
    },

    // Cards
    card: {
        padding: 15,
        marginBottom: 15,
        borderRadius: 0,
    },
    cardLabel: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
        marginBottom: 10,
    },
    cardHint: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        marginTop: 8,
        textAlign: 'center',
    },

    // Fingerprint
    fingerprintContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
    },
    fingerprintText: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
        letterSpacing: 0.5,
    },
    copyBadge: {
        width: 28,
        height: 28,
        borderRadius: 14,
        alignItems: 'center',
        justifyContent: 'center',
    },
    copyBadgeText: {
        fontSize: 14,
        fontWeight: '600',
    },

    // Alias
    aliasDisplay: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
    },
    aliasText: {
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },
    editIcon: {
        fontSize: 18,
    },
    aliasEditContainer: {
        gap: 12,
    },
    aliasInput: {
        height: 44,
        borderWidth: 1,
        paddingHorizontal: 15,
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
    },
    aliasActions: {
        flexDirection: 'row',
        gap: 10,
    },
    aliasButton: {
        flex: 1,
        paddingVertical: 10,
        alignItems: 'center',
        borderRadius: 0,
    },
    cancelButton: {
        backgroundColor: 'transparent',
        borderWidth: 1,
    },
    aliasButtonText: {
        fontSize: 13,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
    },

    // Action Buttons
    actionButton: {
        paddingVertical: 12,
        alignItems: 'center',
        borderWidth: 1,
    },
    actionButtonText: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
    },

    // Theme Grid
    themeLabel: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
        marginBottom: 15,
    },
    themeGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        marginHorizontal: -5,
    },
    themeOption: {
        width: (SCREEN_WIDTH - 72) / 3,
        margin: 5,
        padding: 10,
        borderWidth: 1,
        alignItems: 'center',
    },
    themePreview: {
        width: 40,
        height: 40,
        marginBottom: 8,
    },
    themeName: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        textAlign: 'center',
    },

    // Settings Rows
    settingRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingVertical: 12,
        borderBottomWidth: StyleSheet.hairlineWidth,
        borderBottomColor: 'rgba(0,0,0,0.1)',
    },
    settingInfo: {
        flex: 1,
        marginRight: 15,
    },
    settingLabel: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        marginBottom: 3,
    },
    settingDescription: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
    },

    // Danger Zone
    dangerZone: {
        marginTop: 20,
        paddingTop: 20,
        borderTopWidth: StyleSheet.hairlineWidth,
        borderTopColor: 'rgba(0,0,0,0.1)',
        gap: 12,
    },
    dangerButton: {
        paddingVertical: 12,
        alignItems: 'center',
        borderWidth: 1,
    },
    dangerButtonText: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '500',
        letterSpacing: 1.5,
    },

    // About
    aboutContainer: {
        gap: 12,
    },
    aboutRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
    },
    aboutLabel: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
    },
    aboutValue: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '500',
    },

    // Footer
    footer: {
        paddingVertical: 30,
        alignItems: 'center',
    },
    footerText: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        letterSpacing: 2,
    },
});

export default SettingsScreen;