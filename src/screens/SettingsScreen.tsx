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
    Easing,
    Modal,
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

    const { currentTheme, themeName, setTheme, setCustomColor, availableThemes } = useTheme();

    const [alias, setAlias] = useState('anonymous');
    const [editingAlias, setEditingAlias] = useState(false);
    const [newAlias, setNewAlias] = useState('');
    const [showExportData, setShowExportData] = useState(false);
    const [importData, setImportData] = useState('');
    const [showImport, setShowImport] = useState(false);
    const [expandedSection, setExpandedSection] = useState<string | null>('identity');
    const [showCursor, setShowCursor] = useState(true);
    const [showThemeModal, setShowThemeModal] = useState(false);
    const [showColorPicker, setShowColorPicker] = useState(false);
    const [customColorInput, setCustomColorInput] = useState('#00FF00');

    // Settings state
    const [settings, setSettings] = useState({
        autoConnect: true,
        autoScan: true,
        messageTTL: 86400, // 24 hours in seconds
        maxHops: 10,
        scanInterval: 5000, // ms
        debugMode: false,
        notifications: true,
        vibration: true,
        soundEffects: false,
        darkTheme: true,
    });

    // Animation values
    const fadeAnim = useRef(new Animated.Value(0)).current;
    const slideAnim = useRef(new Animated.Value(30)).current;
    const pulseAnim = useRef(new Animated.Value(1)).current;
    const sectionAnimations = useRef<Map<string, Animated.Value>>(new Map()).current;
    const toggleAnimations = useRef<Map<string, Animated.Value>>(new Map()).current;

    // Initialize animations
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

        // Pulse animation for active elements
        Animated.loop(
            Animated.sequence([
                Animated.timing(pulseAnim, {
                    toValue: 1.05,
                    duration: 2000,
                    useNativeDriver: true,
                }),
                Animated.timing(pulseAnim, {
                    toValue: 1,
                    duration: 2000,
                    useNativeDriver: true,
                }),
            ])
        ).start();
    }, []);

    // Cursor blink effect
    useEffect(() => {
        const interval = setInterval(() => {
            setShowCursor(prev => !prev);
        }, 500);
        return () => clearInterval(interval);
    }, []);

    // Section expand/collapse animation
    const toggleSection = (section: string) => {
        if (!sectionAnimations.has(section)) {
            sectionAnimations.set(section, new Animated.Value(0));
        }

        const anim = sectionAnimations.get(section)!;
        const isExpanding = expandedSection !== section;

        if (isExpanding) {
            setExpandedSection(section);
            Animated.spring(anim, {
                toValue: 1,
                tension: 50,
                friction: 10,
                useNativeDriver: true,
            }).start();
        } else {
            Animated.timing(anim, {
                toValue: 0,
                duration: 200,
                useNativeDriver: true,
            }).start(() => {
                setExpandedSection(null);
            });
        }
    };

    // Toggle animation for switches
    const animateToggle = (key: string, value: boolean) => {
        if (!toggleAnimations.has(key)) {
            toggleAnimations.set(key, new Animated.Value(value ? 1 : 0));
        }

        const anim = toggleAnimations.get(key)!;
        Animated.timing(anim, {
            toValue: value ? 1 : 0,
            duration: 200,
            useNativeDriver: true,
        }).start();
    };

    useEffect(() => {
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
                const parsed = JSON.parse(savedSettings);
                setSettings(parsed);
                // Initialize toggle animations
                Object.keys(parsed).forEach(key => {
                    if (typeof parsed[key] === 'boolean') {
                        animateToggle(key, parsed[key]);
                    }
                });
            }
        } catch (error) {
            console.error('Failed to load settings:', error);
        }
    };

    const saveSettings = async (newSettings: typeof settings) => {
        try {
            await AsyncStorage.setItem('@ghostcomm_settings', JSON.stringify(newSettings));
            setSettings(newSettings);
            addSystemLog('SUCCESS', 'Settings updated');
        } catch (error) {
            addSystemLog('ERROR', 'Failed to save settings');
        }
    };

    const handleToggleSetting = (key: keyof typeof settings) => {
        const newValue = !settings[key];
        animateToggle(key, newValue);
        saveSettings({ ...settings, [key]: newValue });
    };

    const handleAliasUpdate = async () => {
        const trimmed = newAlias.trim();
        if (trimmed && trimmed.length <= 16) {
            await AsyncStorage.setItem('@ghostcomm_alias', trimmed);
            setAlias(trimmed);
            setEditingAlias(false);
            setNewAlias('');
            addSystemLog('SUCCESS', `Alias updated: ${trimmed}`);
        }
    };

    const handleExportIdentity = () => {
        if (!keyPair) return;

        const exportData = {
            identity: keyPair.export ? keyPair.export('ghostcomm') : keyPair.exportKeys(),
            alias: alias,
            timestamp: Date.now(),
            version: '2.0.0',
        };

        const encoded = Buffer.from(JSON.stringify(exportData)).toString('base64');
        setShowExportData(true);

        // Copy to clipboard
        Clipboard.setString(encoded);
        addSystemLog('SUCCESS', 'Identity exported to clipboard');

        // Hide export confirmation after 3 seconds
        setTimeout(() => setShowExportData(false), 3000);
    };

    const handleImportIdentity = () => {
        try {
            const decoded = Buffer.from(importData, 'base64').toString('utf-8');
            const data = JSON.parse(decoded);

            // Validate and import
            if (data.identity && data.identity.publicKey && data.identity.secretKey) {
                Alert.alert(
                    'IMPORT IDENTITY',
                    'This will replace your current identity. All existing connections will be lost.',
                    [
                        { text: 'CANCEL', style: 'cancel' },
                        {
                            text: 'IMPORT',
                            style: 'destructive',
                            onPress: async () => {
                                await AsyncStorage.setItem('@ghostcomm_keypair', JSON.stringify(data.identity));
                                if (data.alias) {
                                    await AsyncStorage.setItem('@ghostcomm_alias', data.alias);
                                }
                                addSystemLog('SUCCESS', 'Identity imported. Restart required.');
                                Alert.alert('SUCCESS', 'Identity imported. Please restart the app.');
                            }
                        }
                    ]
                );
            } else {
                throw new Error('Invalid import data');
            }
        } catch (error) {
            addSystemLog('ERROR', 'Invalid import data');
            Alert.alert('ERROR', 'Invalid import data format');
        }
    };

    const handleFactoryReset = () => {
        Alert.alert(
            '⚠ FACTORY RESET',
            'This action will:\n• Delete your identity\n• Clear all messages\n• Reset all settings\n• Remove all connections\n\nThis cannot be undone.',
            [
                { text: 'CANCEL', style: 'cancel' },
                {
                    text: 'CONFIRM RESET',
                    style: 'destructive',
                    onPress: async () => {
                        Alert.alert(
                            'FINAL CONFIRMATION',
                            'Are you absolutely sure?',
                            [
                                { text: 'NO', style: 'cancel' },
                                {
                                    text: 'YES, RESET',
                                    style: 'destructive',
                                    onPress: async () => {
                                        await AsyncStorage.clear();
                                        addSystemLog('WARN', 'Factory reset completed');
                                        Alert.alert('RESET COMPLETE', 'Please restart the app.');
                                    }
                                }
                            ]
                        );
                    }
                }
            ]
        );
    };

    const handleCustomColorChange = () => {
        if (/^#[0-9A-F]{6}$/i.test(customColorInput)) {
            setCustomColor(customColorInput);
            setTheme('custom');
            setShowColorPicker(false);
            addSystemLog('SUCCESS', `Custom color set: ${customColorInput}`);
        } else {
            Alert.alert('Invalid Color', 'Please enter a valid hex color (e.g., #00FF00)');
        }
    };

    const formatFingerprint = (fp: string) => {
        const chunks = [];
        for (let i = 0; i < fp.length; i += 4) {
            chunks.push(fp.substring(i, i + 4));
        }
        return chunks.join(' ').toUpperCase();
    };

    const formatUptime = () => {
        const uptimeMs = Date.now() - (networkStats.uptime || Date.now());
        const days = Math.floor(uptimeMs / (1000 * 60 * 60 * 24));
        const hours = Math.floor((uptimeMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
        const minutes = Math.floor((uptimeMs % (1000 * 60 * 60)) / (1000 * 60));

        if (days > 0) return `${days}d ${hours}h ${minutes}m`;
        if (hours > 0) return `${hours}h ${minutes}m`;
        return `${minutes}m`;
    };

    const formatBytes = (bytes: number) => {
        if (bytes < 1024) return `${bytes} B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(2)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    };

    const renderToggle = (key: keyof typeof settings, value: boolean) => {
        const anim = toggleAnimations.get(key) || new Animated.Value(value ? 1 : 0);

        return (
            <TouchableOpacity
                style={styles.toggle}
                onPress={() => handleToggleSetting(key)}
                activeOpacity={0.7}
            >
                <Animated.View
                    style={[
                        styles.toggleTrack,
                        {
                            backgroundColor: anim.interpolate({
                                inputRange: [0, 1],
                                outputRange: [currentTheme.surface, currentTheme.surface],
                            }),
                            borderColor: currentTheme.primary,
                        },
                    ]}
                >
                    <Animated.View
                        style={[
                            styles.toggleThumb,
                            {
                                transform: [{
                                    translateX: anim.interpolate({
                                        inputRange: [0, 1],
                                        outputRange: [2, 18],
                                    }),
                                }],
                                backgroundColor: anim.interpolate({
                                    inputRange: [0, 1],
                                    outputRange: [currentTheme.textSecondary, currentTheme.primary],
                                }),
                                borderColor: currentTheme.primary,
                            },
                        ]}
                    />
                </Animated.View>
            </TouchableOpacity>
        );
    };

    // Theme Modal Component
    const ThemeModal = () => (
        <Modal
            visible={showThemeModal}
            transparent={true}
            animationType="fade"
            onRequestClose={() => setShowThemeModal(false)}
        >
            <TouchableOpacity
                style={[styles.modalOverlay, { backgroundColor: 'rgba(0,0,0,0.9)' }]}
                activeOpacity={1}
                onPress={() => setShowThemeModal(false)}
            >
                <View style={[styles.modalContent, { backgroundColor: currentTheme.surface }]}>
                    <Text style={[styles.modalTitle, { color: currentTheme.primary }]}>SELECT THEME</Text>

                    <ScrollView style={styles.themeList}>
                        {Object.entries(availableThemes).map(([key, theme]) => (
                            <TouchableOpacity
                                key={key}
                                style={[
                                    styles.themeOption,
                                    {
                                        backgroundColor: currentTheme.background,
                                        borderColor: themeName === key ? theme.primary : currentTheme.border,
                                        borderWidth: themeName === key ? 2 : 1,
                                    }
                                ]}
                                onPress={() => {
                                    if (key === 'custom') {
                                        setShowColorPicker(true);
                                        setShowThemeModal(false);
                                    } else {
                                        setTheme(key);
                                        setShowThemeModal(false);
                                        addSystemLog('SUCCESS', `Theme changed: ${theme.name}`);
                                    }
                                }}
                            >
                                <View style={styles.themePreview}>
                                    <View style={[styles.colorSwatch, { backgroundColor: theme.primary }]} />
                                    <View style={styles.themeInfo}>
                                        <Text style={[styles.themeName, { color: theme.primary }]}>
                                            {theme.name}
                                        </Text>
                                        {themeName === key && (
                                            <Text style={[styles.activeIndicator, { color: theme.primary }]}>
                                                ● ACTIVE
                                            </Text>
                                        )}
                                    </View>
                                </View>
                            </TouchableOpacity>
                        ))}
                    </ScrollView>

                    <TouchableOpacity
                        style={[styles.modalCloseButton, { borderColor: currentTheme.primary }]}
                        onPress={() => setShowThemeModal(false)}
                    >
                        <Text style={[styles.modalCloseText, { color: currentTheme.primary }]}>CLOSE</Text>
                    </TouchableOpacity>
                </View>
            </TouchableOpacity>
        </Modal>
    );

    // Color Picker Modal
    const ColorPickerModal = () => (
        <Modal
            visible={showColorPicker}
            transparent={true}
            animationType="fade"
            onRequestClose={() => setShowColorPicker(false)}
        >
            <TouchableOpacity
                style={[styles.modalOverlay, { backgroundColor: 'rgba(0,0,0,0.9)' }]}
                activeOpacity={1}
                onPress={() => setShowColorPicker(false)}
            >
                <View style={[styles.modalContent, { backgroundColor: currentTheme.surface }]}>
                    <Text style={[styles.modalTitle, { color: currentTheme.primary }]}>CUSTOM COLOR</Text>

                    <View style={styles.colorInputContainer}>
                        <TextInput
                            style={[styles.colorInput, {
                                color: currentTheme.primary,
                                borderColor: currentTheme.primary
                            }]}
                            value={customColorInput}
                            onChangeText={setCustomColorInput}
                            placeholder="#00FF00"
                            placeholderTextColor={currentTheme.textSecondary}
                            autoCapitalize="characters"
                            maxLength={7}
                        />
                        <View style={[styles.colorPreview, { backgroundColor: customColorInput }]} />
                    </View>

                    <View style={styles.presetColors}>
                        {['#00FF00', '#00FFFF', '#FF00FF', '#FFFF00', '#FF6B35', '#4A9EFF', '#FFA500', '#FFFFFF'].map(color => (
                            <TouchableOpacity
                                key={color}
                                style={[styles.presetColor, { backgroundColor: color }]}
                                onPress={() => setCustomColorInput(color)}
                            />
                        ))}
                    </View>

                    <View style={styles.modalActions}>
                        <TouchableOpacity
                            style={[styles.modalButton, { borderColor: currentTheme.primary }]}
                            onPress={handleCustomColorChange}
                        >
                            <Text style={[styles.modalButtonText, { color: currentTheme.primary }]}>APPLY</Text>
                        </TouchableOpacity>
                        <TouchableOpacity
                            style={[styles.modalButton, { borderColor: currentTheme.border }]}
                            onPress={() => setShowColorPicker(false)}
                        >
                            <Text style={[styles.modalButtonText, { color: currentTheme.textSecondary }]}>CANCEL</Text>
                        </TouchableOpacity>
                    </View>
                </View>
            </TouchableOpacity>
        </Modal>
    );

    return (
        <ScrollView
            style={[styles.container, { backgroundColor: currentTheme.background }]}
            showsVerticalScrollIndicator={false}
        >
            <Animated.View
                style={{
                    opacity: fadeAnim,
                    transform: [{ translateY: slideAnim }],
                }}
            >
                {/* Header */}
                <View style={[styles.header, {
                    backgroundColor: currentTheme.surface,
                    borderBottomColor: currentTheme.primary
                }]}>
                    <Text style={[styles.headerTitle, { color: currentTheme.primary }]}>
                        SYSTEM CONFIGURATION
                    </Text>
                    <Text style={[styles.headerSubtitle, { color: currentTheme.primary }]}>
                        GHOSTCOMM v2.0.0
                    </Text>
                </View>

                {/* Theme Section */}
                <TouchableOpacity
                    style={[styles.sectionHeader, {
                        backgroundColor: currentTheme.background,
                        borderBottomColor: currentTheme.border
                    }]}
                    onPress={() => toggleSection('theme')}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>◉</Text>
                    <Text style={[styles.sectionTitle, { color: currentTheme.primary }]}>APPEARANCE</Text>
                    <Text style={[styles.sectionArrow, { color: currentTheme.primary }]}>
                        {expandedSection === 'theme' ? '▼' : '▶'}
                    </Text>
                </TouchableOpacity>

                {expandedSection === 'theme' && (
                    <View style={[styles.sectionContent, {
                        backgroundColor: currentTheme.surface,
                        borderBottomColor: currentTheme.primary
                    }]}>
                        <TouchableOpacity
                            style={[styles.themeSelector, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}
                            onPress={() => setShowThemeModal(true)}
                        >
                            <View style={styles.themeSelectorContent}>
                                <Text style={[styles.themeSelectorLabel, { color: currentTheme.textSecondary }]}>
                                    CURRENT THEME
                                </Text>
                                <Text style={[styles.themeSelectorValue, { color: currentTheme.primary }]}>
                                    {currentTheme.name}
                                </Text>
                            </View>
                            <Text style={[styles.themeSelectorArrow, { color: currentTheme.primary }]}>▶</Text>
                        </TouchableOpacity>

                        <View style={[styles.themeNote, { backgroundColor: currentTheme.background }]}>
                            <Text style={[styles.themeNoteText, { color: currentTheme.textSecondary }]}>
                                Tip: Use "Daylight" or "High Contrast" themes for better visibility in bright sunlight
                            </Text>
                        </View>
                    </View>
                )}

                {/* Identity Section */}
                <TouchableOpacity
                    style={[styles.sectionHeader, {
                        backgroundColor: currentTheme.background,
                        borderBottomColor: currentTheme.border
                    }]}
                    onPress={() => toggleSection('identity')}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>◈</Text>
                    <Text style={[styles.sectionTitle, { color: currentTheme.primary }]}>IDENTITY</Text>
                    <Text style={[styles.sectionArrow, { color: currentTheme.primary }]}>
                        {expandedSection === 'identity' ? '▼' : '▶'}
                    </Text>
                </TouchableOpacity>

                {expandedSection === 'identity' && (
                    <Animated.View style={[styles.sectionContent, {
                        backgroundColor: currentTheme.surface,
                        borderBottomColor: currentTheme.primary,
                        transform: [{ scale: pulseAnim }]
                    }]}>
                        <View style={[styles.identityCard, {
                            backgroundColor: currentTheme.background,
                            borderColor: currentTheme.primary
                        }]}>
                            <Text style={[styles.cardLabel, { color: currentTheme.primary }]}>NODE FINGERPRINT</Text>
                            <View style={styles.fingerprintContainer}>
                                <Text style={[styles.fingerprintText, { color: currentTheme.primary }]}>
                                    {keyPair ? formatFingerprint(keyPair.getFingerprint()) : 'NOT INITIALIZED'}
                                </Text>
                                <TouchableOpacity
                                    style={[styles.copyButton, { borderColor: currentTheme.primary }]}
                                    onPress={() => {
                                        if (keyPair) {
                                            Clipboard.setString(keyPair.getFingerprint());
                                            addSystemLog('SUCCESS', 'Fingerprint copied');
                                        }
                                    }}
                                    activeOpacity={0.7}
                                >
                                    <Text style={[styles.copyButtonText, { color: currentTheme.primary }]}>COPY</Text>
                                </TouchableOpacity>
                            </View>
                        </View>

                        <View style={[styles.identityCard, {
                            backgroundColor: currentTheme.background,
                            borderColor: currentTheme.primary
                        }]}>
                            <Text style={[styles.cardLabel, { color: currentTheme.primary }]}>CALLSIGN</Text>
                            {editingAlias ? (
                                <View style={styles.aliasEditContainer}>
                                    <View style={[styles.aliasInputWrapper, {
                                        backgroundColor: currentTheme.surface,
                                        borderColor: currentTheme.primary
                                    }]}>
                                        <Text style={[styles.inputPrefix, { color: currentTheme.primary }]}>$</Text>
                                        <TextInput
                                            style={[styles.aliasInput, { color: currentTheme.primary }]}
                                            value={newAlias}
                                            onChangeText={setNewAlias}
                                            placeholder={alias}
                                            placeholderTextColor={currentTheme.textSecondary}
                                            maxLength={16}
                                            autoCapitalize="none"
                                            autoCorrect={false}
                                            returnKeyType="done"
                                            onSubmitEditing={handleAliasUpdate}
                                        />
                                        <Text style={[styles.inputCursor, { color: currentTheme.primary }]}>
                                            {showCursor && newAlias.length === 0 ? '▊' : ''}
                                        </Text>
                                    </View>
                                    <View style={styles.aliasActions}>
                                        <TouchableOpacity
                                            style={[styles.aliasButton, {
                                                backgroundColor: currentTheme.surface,
                                                borderColor: currentTheme.primary
                                            }]}
                                            onPress={handleAliasUpdate}
                                            activeOpacity={0.7}
                                        >
                                            <Text style={[styles.aliasButtonText, { color: currentTheme.primary }]}>SAVE</Text>
                                        </TouchableOpacity>
                                        <TouchableOpacity
                                            style={[styles.aliasButton, styles.aliasButtonCancel, {
                                                backgroundColor: currentTheme.background,
                                                borderColor: currentTheme.border
                                            }]}
                                            onPress={() => {
                                                setEditingAlias(false);
                                                setNewAlias('');
                                            }}
                                            activeOpacity={0.7}
                                        >
                                            <Text style={[styles.aliasButtonText, { color: currentTheme.primary }]}>CANCEL</Text>
                                        </TouchableOpacity>
                                    </View>
                                </View>
                            ) : (
                                <View style={styles.aliasDisplayContainer}>
                                    <Text style={[styles.aliasText, { color: currentTheme.primary }]}>
                                        {alias}@{keyPair?.getFingerprint().substring(0, 8).toLowerCase() || 'unknown'}
                                    </Text>
                                    <TouchableOpacity
                                        style={[styles.editButton, { borderColor: currentTheme.primary }]}
                                        onPress={() => {
                                            setNewAlias(alias);
                                            setEditingAlias(true);
                                        }}
                                        activeOpacity={0.7}
                                    >
                                        <Text style={[styles.editButtonText, { color: currentTheme.primary }]}>EDIT</Text>
                                    </TouchableOpacity>
                                </View>
                            )}
                        </View>

                        <View style={styles.identityActions}>
                            <TouchableOpacity
                                style={[styles.actionButton, {
                                    backgroundColor: currentTheme.surface,
                                    borderColor: currentTheme.primary
                                }]}
                                onPress={handleExportIdentity}
                                activeOpacity={0.7}
                            >
                                <Text style={[styles.actionButtonIcon, { color: currentTheme.primary }]}>↑</Text>
                                <Text style={[styles.actionButtonText, { color: currentTheme.primary }]}>EXPORT</Text>
                            </TouchableOpacity>

                            <TouchableOpacity
                                style={[styles.actionButton, {
                                    backgroundColor: currentTheme.surface,
                                    borderColor: currentTheme.primary
                                }]}
                                onPress={() => setShowImport(!showImport)}
                                activeOpacity={0.7}
                            >
                                <Text style={[styles.actionButtonIcon, { color: currentTheme.primary }]}>↓</Text>
                                <Text style={[styles.actionButtonText, { color: currentTheme.primary }]}>IMPORT</Text>
                            </TouchableOpacity>
                        </View>

                        {showExportData && (
                            <Animated.View style={[styles.notification, {
                                backgroundColor: currentTheme.surface,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.notificationIcon, { color: currentTheme.primary }]}>✓</Text>
                                <Text style={[styles.notificationText, { color: currentTheme.primary }]}>
                                    Identity exported to clipboard
                                </Text>
                            </Animated.View>
                        )}

                        {showImport && (
                            <View style={styles.importContainer}>
                                <TextInput
                                    style={[styles.importInput, {
                                        backgroundColor: currentTheme.background,
                                        borderColor: currentTheme.primary,
                                        color: currentTheme.primary
                                    }]}
                                    value={importData}
                                    onChangeText={setImportData}
                                    placeholder="Paste base64 identity data..."
                                    placeholderTextColor={currentTheme.textSecondary}
                                    multiline
                                    numberOfLines={4}
                                />
                                <TouchableOpacity
                                    style={[styles.importButton, {
                                        backgroundColor: currentTheme.surface,
                                        borderColor: currentTheme.primary
                                    }]}
                                    onPress={handleImportIdentity}
                                    activeOpacity={0.7}
                                >
                                    <Text style={[styles.importButtonText, { color: currentTheme.primary }]}>
                                        IMPORT IDENTITY
                                    </Text>
                                </TouchableOpacity>
                            </View>
                        )}
                    </Animated.View>
                )}

                {/* Network Section */}
                <TouchableOpacity
                    style={[styles.sectionHeader, {
                        backgroundColor: currentTheme.background,
                        borderBottomColor: currentTheme.border
                    }]}
                    onPress={() => toggleSection('network')}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>◉</Text>
                    <Text style={[styles.sectionTitle, { color: currentTheme.primary }]}>NETWORK</Text>
                    <Text style={[styles.sectionArrow, { color: currentTheme.primary }]}>
                        {expandedSection === 'network' ? '▼' : '▶'}
                    </Text>
                </TouchableOpacity>

                {expandedSection === 'network' && (
                    <View style={[styles.sectionContent, {
                        backgroundColor: currentTheme.surface,
                        borderBottomColor: currentTheme.primary
                    }]}>
                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>AUTO CONNECT</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Automatically connect to discovered nodes
                                </Text>
                            </View>
                            {renderToggle('autoConnect', settings.autoConnect)}
                        </View>

                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>AUTO SCAN</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Continuously scan for new nodes
                                </Text>
                            </View>
                            {renderToggle('autoScan', settings.autoScan)}
                        </View>

                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>MESSAGE TTL</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Time before messages expire
                                </Text>
                            </View>
                            <Text style={[styles.settingValue, { color: currentTheme.primary }]}>
                                {settings.messageTTL / 3600}h
                            </Text>
                        </View>

                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>MAX HOPS</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Maximum relay distance
                                </Text>
                            </View>
                            <Text style={[styles.settingValue, { color: currentTheme.primary }]}>
                                {settings.maxHops}
                            </Text>
                        </View>

                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>SCAN INTERVAL</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Time between scans
                                </Text>
                            </View>
                            <Text style={[styles.settingValue, { color: currentTheme.primary }]}>
                                {settings.scanInterval / 1000}s
                            </Text>
                        </View>
                    </View>
                )}

                {/* Preferences Section */}
                <TouchableOpacity
                    style={[styles.sectionHeader, {
                        backgroundColor: currentTheme.background,
                        borderBottomColor: currentTheme.border
                    }]}
                    onPress={() => toggleSection('preferences')}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>⚙</Text>
                    <Text style={[styles.sectionTitle, { color: currentTheme.primary }]}>PREFERENCES</Text>
                    <Text style={[styles.sectionArrow, { color: currentTheme.primary }]}>
                        {expandedSection === 'preferences' ? '▼' : '▶'}
                    </Text>
                </TouchableOpacity>

                {expandedSection === 'preferences' && (
                    <View style={[styles.sectionContent, {
                        backgroundColor: currentTheme.surface,
                        borderBottomColor: currentTheme.primary
                    }]}>
                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>NOTIFICATIONS</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Show message notifications
                                </Text>
                            </View>
                            {renderToggle('notifications', settings.notifications)}
                        </View>

                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>VIBRATION</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Haptic feedback
                                </Text>
                            </View>
                            {renderToggle('vibration', settings.vibration)}
                        </View>

                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>SOUND EFFECTS</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Audio feedback
                                </Text>
                            </View>
                            {renderToggle('soundEffects', settings.soundEffects)}
                        </View>

                        <View style={styles.settingItem}>
                            <View style={styles.settingInfo}>
                                <Text style={[styles.settingLabel, { color: currentTheme.primary }]}>DEBUG MODE</Text>
                                <Text style={[styles.settingDescription, { color: currentTheme.textSecondary }]}>
                                    Show verbose logs
                                </Text>
                            </View>
                            {renderToggle('debugMode', settings.debugMode)}
                        </View>
                    </View>
                )}

                {/* Statistics Section */}
                <TouchableOpacity
                    style={[styles.sectionHeader, {
                        backgroundColor: currentTheme.background,
                        borderBottomColor: currentTheme.border
                    }]}
                    onPress={() => toggleSection('statistics')}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>▦</Text>
                    <Text style={[styles.sectionTitle, { color: currentTheme.primary }]}>STATISTICS</Text>
                    <Text style={[styles.sectionArrow, { color: currentTheme.primary }]}>
                        {expandedSection === 'statistics' ? '▼' : '▶'}
                    </Text>
                </TouchableOpacity>

                {expandedSection === 'statistics' && (
                    <View style={[styles.sectionContent, {
                        backgroundColor: currentTheme.surface,
                        borderBottomColor: currentTheme.primary
                    }]}>
                        <View style={styles.statsGrid}>
                            <View style={[styles.statCard, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.statIcon, { color: currentTheme.primary }]}>⏱</Text>
                                <Text style={[styles.statValue, { color: currentTheme.primary }]}>
                                    {formatUptime()}
                                </Text>
                                <Text style={[styles.statLabel, { color: currentTheme.textSecondary }]}>UPTIME</Text>
                            </View>

                            <View style={[styles.statCard, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.statIcon, { color: currentTheme.primary }]}>↑</Text>
                                <Text style={[styles.statValue, { color: currentTheme.primary }]}>
                                    {networkStats.messagesSent}
                                </Text>
                                <Text style={[styles.statLabel, { color: currentTheme.textSecondary }]}>SENT</Text>
                            </View>

                            <View style={[styles.statCard, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.statIcon, { color: currentTheme.primary }]}>↓</Text>
                                <Text style={[styles.statValue, { color: currentTheme.primary }]}>
                                    {networkStats.messagesReceived}
                                </Text>
                                <Text style={[styles.statLabel, { color: currentTheme.textSecondary }]}>RECEIVED</Text>
                            </View>

                            <View style={[styles.statCard, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.statIcon, { color: currentTheme.primary }]}>⟲</Text>
                                <Text style={[styles.statValue, { color: currentTheme.primary }]}>
                                    {networkStats.messagesRelayed}
                                </Text>
                                <Text style={[styles.statLabel, { color: currentTheme.textSecondary }]}>RELAYED</Text>
                            </View>

                            <View style={[styles.statCard, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.statIcon, { color: currentTheme.primary }]}>◈</Text>
                                <Text style={[styles.statValue, { color: currentTheme.primary }]}>
                                    {networkStats.totalConnections}
                                </Text>
                                <Text style={[styles.statLabel, { color: currentTheme.textSecondary }]}>CONNECTIONS</Text>
                            </View>

                            <View style={[styles.statCard, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.statIcon, { color: currentTheme.primary }]}>⇅</Text>
                                <Text style={[styles.statValue, { color: currentTheme.primary }]}>
                                    {formatBytes(networkStats.bytesTransmitted + networkStats.bytesReceived)}
                                </Text>
                                <Text style={[styles.statLabel, { color: currentTheme.textSecondary }]}>TRAFFIC</Text>
                            </View>
                        </View>
                    </View>
                )}

                {/* Data Management Section */}
                <TouchableOpacity
                    style={[styles.sectionHeader, {
                        backgroundColor: currentTheme.background,
                        borderBottomColor: currentTheme.border
                    }]}
                    onPress={() => toggleSection('data')}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>▣</Text>
                    <Text style={[styles.sectionTitle, { color: currentTheme.primary }]}>DATA MANAGEMENT</Text>
                    <Text style={[styles.sectionArrow, { color: currentTheme.primary }]}>
                        {expandedSection === 'data' ? '▼' : '▶'}
                    </Text>
                </TouchableOpacity>

                {expandedSection === 'data' && (
                    <View style={[styles.sectionContent, {
                        backgroundColor: currentTheme.surface,
                        borderBottomColor: currentTheme.primary
                    }]}>
                        <TouchableOpacity
                            style={[styles.dataButton, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}
                            onPress={() => {
                                Alert.alert(
                                    'Clear Messages',
                                    'Delete all messages from this device?',
                                    [
                                        { text: 'Cancel', style: 'cancel' },
                                        {
                                            text: 'Clear',
                                            style: 'destructive',
                                            onPress: () => {
                                                clearMessages();
                                                addSystemLog('SUCCESS', 'Messages cleared');
                                            }
                                        }
                                    ]
                                );
                            }}
                            activeOpacity={0.7}
                        >
                            <Text style={[styles.dataButtonIcon, { color: currentTheme.primary }]}>✕</Text>
                            <Text style={[styles.dataButtonText, { color: currentTheme.primary }]}>CLEAR MESSAGES</Text>
                        </TouchableOpacity>

                        <TouchableOpacity
                            style={[styles.dataButton, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}
                            onPress={() => {
                                Alert.alert(
                                    'Clear Logs',
                                    'Delete all system logs?',
                                    [
                                        { text: 'Cancel', style: 'cancel' },
                                        {
                                            text: 'Clear',
                                            style: 'destructive',
                                            onPress: () => {
                                                clearLogs();
                                                addSystemLog('SUCCESS', 'Logs cleared');
                                            }
                                        }
                                    ]
                                );
                            }}
                            activeOpacity={0.7}
                        >
                            <Text style={[styles.dataButtonIcon, { color: currentTheme.primary }]}>✕</Text>
                            <Text style={[styles.dataButtonText, { color: currentTheme.primary }]}>CLEAR LOGS</Text>
                        </TouchableOpacity>

                        <TouchableOpacity
                            style={[styles.dangerButton, {
                                backgroundColor: '#110000',
                                borderColor: '#FF3333'
                            }]}
                            onPress={handleFactoryReset}
                            activeOpacity={0.7}
                        >
                            <Text style={[styles.dangerButtonIcon, { color: '#FF3333' }]}>⚠</Text>
                            <Text style={[styles.dangerButtonText, { color: '#FF3333' }]}>FACTORY RESET</Text>
                        </TouchableOpacity>
                    </View>
                )}

                {/* About Section */}
                <TouchableOpacity
                    style={[styles.sectionHeader, {
                        backgroundColor: currentTheme.background,
                        borderBottomColor: currentTheme.border
                    }]}
                    onPress={() => toggleSection('about')}
                    activeOpacity={0.7}
                >
                    <Text style={[styles.sectionIcon, { color: currentTheme.primary }]}>ℹ</Text>
                    <Text style={[styles.sectionTitle, { color: currentTheme.primary }]}>ABOUT</Text>
                    <Text style={[styles.sectionArrow, { color: currentTheme.primary }]}>
                        {expandedSection === 'about' ? '▼' : '▶'}
                    </Text>
                </TouchableOpacity>

                {expandedSection === 'about' && (
                    <View style={[styles.sectionContent, {
                        backgroundColor: currentTheme.surface,
                        borderBottomColor: currentTheme.primary
                    }]}>
                        <View style={styles.aboutContainer}>
                            <View style={[styles.aboutLogo, {
                                backgroundColor: currentTheme.surface,
                                borderColor: currentTheme.primary
                            }]}>
                                <Text style={[styles.aboutLogoText, { color: currentTheme.primary }]}>◈</Text>
                            </View>
                            <Text style={[styles.aboutTitle, { color: currentTheme.primary }]}>GHOSTCOMM</Text>
                            <Text style={[styles.aboutSubtitle, { color: currentTheme.textSecondary }]}>
                                SECURE MESH NETWORK
                            </Text>

                            <View style={[styles.aboutInfo, {
                                backgroundColor: currentTheme.background,
                                borderColor: currentTheme.primary
                            }]}>
                                <View style={styles.aboutRow}>
                                    <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>VERSION</Text>
                                    <Text style={[styles.aboutValue, { color: currentTheme.primary }]}>2.0.0</Text>
                                </View>
                                <View style={styles.aboutRow}>
                                    <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>BUILD</Text>
                                    <Text style={[styles.aboutValue, { color: currentTheme.primary }]}>2024.01.001</Text>
                                </View>
                                <View style={styles.aboutRow}>
                                    <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>PROTOCOL</Text>
                                    <Text style={[styles.aboutValue, { color: currentTheme.primary }]}>GHOSTMESH/1.0</Text>
                                </View>
                                <View style={styles.aboutRow}>
                                    <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>ENCRYPTION</Text>
                                    <Text style={[styles.aboutValue, { color: currentTheme.primary }]}>ChaCha20-Poly1305</Text>
                                </View>
                                <View style={styles.aboutRow}>
                                    <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>KEY EXCHANGE</Text>
                                    <Text style={[styles.aboutValue, { color: currentTheme.primary }]}>X25519-ECDH</Text>
                                </View>
                                <View style={styles.aboutRow}>
                                    <Text style={[styles.aboutLabel, { color: currentTheme.textSecondary }]}>SIGNATURE</Text>
                                    <Text style={[styles.aboutValue, { color: currentTheme.primary }]}>Ed25519</Text>
                                </View>
                            </View>

                            <Text style={[styles.aboutFooter, { color: currentTheme.textSecondary }]}>
                                SECURE • PEER-TO-PEER • OFF-GRID
                            </Text>
                        </View>
                    </View>
                )}

                {/* Add modals */}
                <ThemeModal />
                <ColorPickerModal />

                {/* Footer */}
                <View style={styles.footer}>
                    <Text style={[styles.footerText, { color: currentTheme.primary }]}>
                        ━━━ END OF CONFIGURATION ━━━
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
        padding: 20,
        borderBottomWidth: 1,
    },
    headerTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 16,
        fontWeight: 'bold',
        letterSpacing: 2,
        textAlign: 'center',
    },
    headerSubtitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        textAlign: 'center',
        marginTop: 5,
        letterSpacing: 1,
    },

    // Section Headers
    sectionHeader: {
        flexDirection: 'row',
        alignItems: 'center',
        paddingVertical: 15,
        paddingHorizontal: 20,
        borderBottomWidth: 1,
    },
    sectionIcon: {
        fontSize: 16,
        marginRight: 12,
        opacity: 0.8,
    },
    sectionTitle: {
        flex: 1,
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 13,
        fontWeight: 'bold',
        letterSpacing: 2,
    },
    sectionArrow: {
        fontSize: 12,
        opacity: 0.6,
    },
    sectionContent: {
        paddingVertical: 15,
        paddingHorizontal: 20,
        borderBottomWidth: 1,
    },

    // Theme Selector
    themeSelector: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: 15,
        borderWidth: 1,
        marginBottom: 10,
    },
    themeSelectorContent: {
        flex: 1,
    },
    themeSelectorLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        marginBottom: 5,
        letterSpacing: 1,
    },
    themeSelectorValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
    },
    themeSelectorArrow: {
        fontSize: 16,
    },
    themeNote: {
        padding: 10,
        borderRadius: 4,
    },
    themeNoteText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        lineHeight: 16,
    },

    // Modal Styles
    modalOverlay: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
    },
    modalContent: {
        width: SCREEN_WIDTH * 0.9,
        maxHeight: '80%',
        padding: 20,
        borderRadius: 8,
    },
    modalTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 16,
        fontWeight: 'bold',
        letterSpacing: 2,
        marginBottom: 20,
        textAlign: 'center',
    },
    themeList: {
        maxHeight: 400,
    },
    themeOption: {
        padding: 15,
        marginBottom: 10,
        borderRadius: 4,
    },
    themePreview: {
        flexDirection: 'row',
        alignItems: 'center',
    },
    colorSwatch: {
        width: 30,
        height: 30,
        borderRadius: 4,
        marginRight: 15,
    },
    themeInfo: {
        flex: 1,
    },
    themeName: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
    },
    activeIndicator: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        marginTop: 2,
    },
    modalCloseButton: {
        marginTop: 20,
        padding: 12,
        borderWidth: 1,
        alignItems: 'center',
    },
    modalCloseText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        letterSpacing: 1,
    },

    // Color Picker
    colorInputContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 20,
    },
    colorInput: {
        flex: 1,
        height: 40,
        borderWidth: 1,
        paddingHorizontal: 10,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 14,
        marginRight: 10,
    },
    colorPreview: {
        width: 40,
        height: 40,
        borderRadius: 4,
    },
    presetColors: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        marginBottom: 20,
    },
    presetColor: {
        width: 40,
        height: 40,
        borderRadius: 4,
        marginBottom: 10,
    },
    modalActions: {
        flexDirection: 'row',
        justifyContent: 'space-between',
    },
    modalButton: {
        flex: 1,
        padding: 12,
        borderWidth: 1,
        alignItems: 'center',
        marginHorizontal: 5,
    },
    modalButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        letterSpacing: 1,
    },

    // Identity Section
    identityCard: {
        borderWidth: 1,
        padding: 15,
        marginBottom: 15,
    },
    cardLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 1,
        marginBottom: 10,
    },
    fingerprintContainer: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
    },
    fingerprintText: {
        flex: 1,
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    copyButton: {
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderWidth: 1,
        marginLeft: 10,
    },
    copyButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        letterSpacing: 1,
    },
    aliasEditContainer: {
        gap: 10,
    },
    aliasInputWrapper: {
        flexDirection: 'row',
        alignItems: 'center',
        borderWidth: 1,
        paddingHorizontal: 12,
        height: 40,
    },
    inputPrefix: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        marginRight: 8,
    },
    aliasInput: {
        flex: 1,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        padding: 0,
    },
    inputCursor: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
    },
    aliasActions: {
        flexDirection: 'row',
        gap: 10,
    },
    aliasButton: {
        flex: 1,
        paddingVertical: 8,
        borderWidth: 1,
        alignItems: 'center',
    },
    aliasButtonCancel: {},
    aliasButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    aliasDisplayContainer: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
    },
    aliasText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
    },
    editButton: {
        paddingHorizontal: 12,
        paddingVertical: 6,
        borderWidth: 1,
    },
    editButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        letterSpacing: 1,
    },
    identityActions: {
        flexDirection: 'row',
        gap: 10,
    },
    actionButton: {
        flex: 1,
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 12,
        borderWidth: 1,
    },
    actionButtonIcon: {
        fontSize: 14,
        marginRight: 8,
    },
    actionButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    notification: {
        flexDirection: 'row',
        alignItems: 'center',
        borderWidth: 1,
        padding: 10,
        marginTop: 10,
    },
    notificationIcon: {
        fontSize: 14,
        marginRight: 10,
    },
    notificationText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
    },
    importContainer: {
        marginTop: 10,
    },
    importInput: {
        borderWidth: 1,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        padding: 10,
        height: 80,
        marginBottom: 10,
    },
    importButton: {
        paddingVertical: 10,
        borderWidth: 1,
        alignItems: 'center',
    },
    importButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },

    // Settings Items
    settingItem: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingVertical: 12,
        borderBottomWidth: 1,
        borderBottomColor: 'rgba(0,255,0,0.1)',
    },
    settingInfo: {
        flex: 1,
        marginRight: 15,
    },
    settingLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        marginBottom: 3,
    },
    settingDescription: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.5,
    },
    settingValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
    },

    // Toggle Switch
    toggle: {
        width: 40,
        height: 24,
        justifyContent: 'center',
    },
    toggleTrack: {
        width: 40,
        height: 20,
        borderRadius: 10,
        borderWidth: 1,
        justifyContent: 'center',
    },
    toggleThumb: {
        width: 16,
        height: 16,
        borderRadius: 8,
        borderWidth: 1,
    },

    // Statistics
    statsGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        marginHorizontal: -5,
    },
    statCard: {
        width: (SCREEN_WIDTH - 50) / 3,
        borderWidth: 1,
        padding: 12,
        margin: 5,
        alignItems: 'center',
    },
    statIcon: {
        fontSize: 18,
        marginBottom: 8,
        opacity: 0.8,
    },
    statValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        marginBottom: 5,
    },
    statLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.6,
        letterSpacing: 1,
    },

    // Data Management
    dataButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 12,
        borderWidth: 1,
        marginBottom: 10,
    },
    dataButtonIcon: {
        fontSize: 14,
        marginRight: 10,
    },
    dataButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 11,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    dangerButton: {
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'center',
        paddingVertical: 12,
        borderWidth: 2,
        marginTop: 20,
    },
    dangerButtonIcon: {
        fontSize: 16,
        marginRight: 10,
    },
    dangerButtonText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 12,
        fontWeight: 'bold',
        letterSpacing: 2,
    },

    // About Section
    aboutContainer: {
        alignItems: 'center',
        paddingVertical: 10,
    },
    aboutLogo: {
        width: 60,
        height: 60,
        borderWidth: 2,
        alignItems: 'center',
        justifyContent: 'center',
        marginBottom: 15,
        transform: [{ rotate: '45deg' }],
    },
    aboutLogoText: {
        fontSize: 24,
        transform: [{ rotate: '-45deg' }],
    },
    aboutTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 18,
        fontWeight: 'bold',
        letterSpacing: 3,
        marginBottom: 5,
    },
    aboutSubtitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 2,
        marginBottom: 20,
    },
    aboutInfo: {
        width: '100%',
        borderWidth: 1,
        padding: 15,
        marginBottom: 20,
    },
    aboutRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 8,
    },
    aboutLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 1,
    },
    aboutValue: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
    },
    aboutFooter: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.5,
        letterSpacing: 2,
        textAlign: 'center',
    },

    // Footer
    footer: {
        padding: 20,
        alignItems: 'center',
    },
    footerText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.3,
        letterSpacing: 1,
    },
});

export default SettingsScreen;