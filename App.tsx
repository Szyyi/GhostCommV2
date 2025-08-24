// mobile/App.tsx
import React, { useEffect, useState } from 'react';
import {
    SafeAreaView,
    StyleSheet,
    StatusBar,
    Alert,
    Platform,
    PermissionsAndroid,
    AppState,
    AppStateStatus,
    View,
    Text,
    ActivityIndicator,
    TouchableOpacity,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Import context providers
import { GhostCommProvider } from './src/context/GhostCommContext';
import { ThemeProvider, useTheme } from './src/context/ThemeContext';

// Import screens
import {
    TerminalScreen,
    MessagingScreen,
    NetworkScreen,
    SettingsScreen,
    OnboardingScreen,
} from './src/screens';

const STORAGE_KEYS = {
    FIRST_LAUNCH: '@ghostcomm_first_launch',
    ONBOARDING_COMPLETE: '@ghostcomm_onboarding_complete',
    KEYPAIR: '@ghostcomm_keypair',
};

// ASCII art for boot sequence
const GHOST_COMM_ASCII = `
╔══════════════════════════════════════╗
║         GHOST COMM v2.0.0            ║
║     Secure Mesh Communication        ║
╚══════════════════════════════════════╝
`;

// Boot sequence component (now themed)
const BootSequence: React.FC<{ onComplete: () => void }> = ({ onComplete }) => {
    const { currentTheme } = useTheme();
    const [bootLog, setBootLog] = useState<string[]>([]);
    const bootMessages = [
        '[BOOT] Initializing GhostComm...',
        '[BOOT] Loading encryption modules...',
        '[BOOT] Checking hardware capabilities...',
        '[BOOT] Bluetooth adapter: READY',
        '[BOOT] Generating node identity...',
        '[BOOT] Initializing mesh network stack...',
        '[BOOT] Loading secure storage...',
        '[BOOT] System ready.',
    ];

    useEffect(() => {
        let index = 0;
        const interval = setInterval(() => {
            if (index < bootMessages.length) {
                setBootLog(prev => [...prev, bootMessages[index]]);
                index++;
            } else {
                clearInterval(interval);
                setTimeout(onComplete, 500);
            }
        }, 200);

        return () => clearInterval(interval);
    }, [onComplete]);

    return (
        <View style={[styles.bootContainer, { backgroundColor: currentTheme.background }]}>
            <Text style={[styles.asciiArt, { color: currentTheme.primary }]}>{GHOST_COMM_ASCII}</Text>
            <View style={styles.bootLogContainer}>
                {bootLog.map((log, index) => (
                    <Text key={index} style={[styles.bootLogText, { color: currentTheme.text }]}>
                        {log}
                    </Text>
                ))}
                <Text style={[styles.bootCursor, { color: currentTheme.primary }]}>█</Text>
            </View>
        </View>
    );
};

// Simple tab bar component (now themed)
const TabBar: React.FC<{
    activeTab: string;
    onTabPress: (tab: string) => void;
}> = ({ activeTab, onTabPress }) => {
    const { currentTheme } = useTheme();

    const tabs = [
        { key: 'terminal', label: 'TERM', icon: '›_' },
        { key: 'messages', label: 'MSGS', icon: '[═]' },
        { key: 'network', label: 'NET', icon: '◈' },
        { key: 'settings', label: 'CONF', icon: '⚙' },
    ];

    return (
        <View style={[styles.tabBar, {
            backgroundColor: currentTheme.background,
            borderTopColor: currentTheme.primary
        }]}>
            {tabs.map((tab) => (
                <TouchableOpacity
                    key={tab.key}
                    style={styles.tabButton}
                    onPress={() => onTabPress(tab.key)}
                >
                    <Text
                        style={[
                            styles.tabIcon,
                            { color: currentTheme.textSecondary },
                            activeTab === tab.key && { color: currentTheme.primary },
                        ]}
                    >
                        {tab.icon}
                    </Text>
                    <Text
                        style={[
                            styles.tabLabel,
                            { color: currentTheme.textSecondary },
                            activeTab === tab.key && { color: currentTheme.primary },
                        ]}
                    >
                        {tab.label}
                    </Text>
                </TouchableOpacity>
            ))}
        </View>
    );
};

// Main navigation component (now themed)
const MainApp: React.FC = () => {
    const { currentTheme } = useTheme();
    const [activeTab, setActiveTab] = useState('terminal');

    const getHeaderTitle = () => {
        switch (activeTab) {
            case 'terminal':
                return '> TERMINAL_';
            case 'messages':
                return '> MESSAGES_';
            case 'network':
                return '> NETWORK_';
            case 'settings':
                return '> SETTINGS_';
            default:
                return '> GHOSTCOMM_';
        }
    };

    const renderScreen = () => {
        switch (activeTab) {
            case 'terminal':
                return <TerminalScreen />;
            case 'messages':
                return <MessagingScreen />;
            case 'network':
                return <NetworkScreen />;
            case 'settings':
                return <SettingsScreen />;
            default:
                return <TerminalScreen />;
        }
    };

    return (
        <View style={[styles.mainContainer, { backgroundColor: currentTheme.background }]}>
            {/* Header */}
            <View style={[styles.header, {
                backgroundColor: currentTheme.background,
                borderBottomColor: currentTheme.primary
            }]}>
                <Text style={[styles.headerTitle, { color: currentTheme.primary }]}>
                    {getHeaderTitle()}
                </Text>
            </View>

            {/* Screen Content */}
            <View style={styles.screenContainer}>
                {renderScreen()}
            </View>

            {/* Tab Bar */}
            <TabBar activeTab={activeTab} onTabPress={setActiveTab} />
        </View>
    );
};

// Inner App component that uses theme
const ThemedApp: React.FC = () => {
    const { currentTheme } = useTheme();
    const [isBooting, setIsBooting] = useState(true);
    const [isFirstLaunch, setIsFirstLaunch] = useState<boolean | null>(null);
    const [permissionsDenied, setPermissionsDenied] = useState(false);
    const [appState, setAppState] = useState(AppState.currentState);
    const [isCheckingFirstLaunch, setIsCheckingFirstLaunch] = useState(true);

    // Check if this is the first launch
    useEffect(() => {
        const checkFirstLaunch = async () => {
            try {
                const onboardingComplete = await AsyncStorage.getItem(STORAGE_KEYS.ONBOARDING_COMPLETE);
                const hasKeypair = await AsyncStorage.getItem(STORAGE_KEYS.KEYPAIR);

                // Consider onboarding complete if we have both the flag and a keypair
                setIsFirstLaunch(onboardingComplete !== 'true' || !hasKeypair);
            } catch (error) {
                console.error('[ERROR] Failed to check first launch:', error);
                setIsFirstLaunch(true); // Default to showing onboarding on error
            } finally {
                setIsCheckingFirstLaunch(false);
            }
        };
        checkFirstLaunch();
    }, []);

    // Request Android permissions
    const requestAndroidPermissions = async () => {
        if (Platform.OS !== 'android') return true;

        try {
            if (Platform.Version >= 31) {
                // Android 12+
                const permissions = [
                    PermissionsAndroid.PERMISSIONS.BLUETOOTH_SCAN,
                    PermissionsAndroid.PERMISSIONS.BLUETOOTH_CONNECT,
                    PermissionsAndroid.PERMISSIONS.BLUETOOTH_ADVERTISE,
                    PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
                ];

                const results = await PermissionsAndroid.requestMultiple(permissions);

                return Object.values(results).every(
                    result => result === PermissionsAndroid.RESULTS.GRANTED
                );
            } else {
                // Android < 12
                const granted = await PermissionsAndroid.request(
                    PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
                    {
                        title: 'PERMISSION_REQUEST',
                        message: 'GhostComm requires Bluetooth access for mesh networking.',
                        buttonNeutral: 'Later',
                        buttonNegative: 'Deny',
                        buttonPositive: 'Grant',
                    }
                );
                return granted === PermissionsAndroid.RESULTS.GRANTED;
            }
        } catch (err) {
            console.error('[ERROR] Permission request failed:', err);
            return false;
        }
    };

    // Handle app state changes
    useEffect(() => {
        const subscription = AppState.addEventListener('change', (nextAppState: AppStateStatus) => {
            if (appState.match(/inactive|background/) && nextAppState === 'active') {
                console.log('[SYSTEM] App resumed from background.');
            } else if (appState === 'active' && nextAppState.match(/inactive|background/)) {
                console.log('[SYSTEM] App entering background.');
            }
            setAppState(nextAppState);
        });

        return () => {
            subscription.remove();
        };
    }, [appState]);

    // Request permissions after boot (but not during onboarding)
    useEffect(() => {
        if (!isBooting && !isCheckingFirstLaunch && !isFirstLaunch) {
            requestAndroidPermissions().then(granted => {
                if (!granted) {
                    setPermissionsDenied(true);
                    Alert.alert(
                        'PERMISSIONS_REQUIRED',
                        'GhostComm requires Bluetooth permissions to function. Please grant permissions in settings.',
                        [{ text: 'OK', style: 'default' }]
                    );
                }
            });
        }
    }, [isBooting, isCheckingFirstLaunch, isFirstLaunch]);

    // Handle boot sequence completion
    const handleBootComplete = () => {
        setIsBooting(false);
    };

    // Handle onboarding completion
    const handleOnboardingComplete = async (keyPairData?: any) => {
        console.log('[SYSTEM] Onboarding complete.');

        try {
            // Save onboarding completion flag
            await AsyncStorage.setItem(STORAGE_KEYS.ONBOARDING_COMPLETE, 'true');

            // If keypair data was provided, save it
            if (keyPairData) {
                await AsyncStorage.setItem(STORAGE_KEYS.KEYPAIR, JSON.stringify(keyPairData));
            }

            // Update state to show main app
            setIsFirstLaunch(false);

            // Request permissions after onboarding
            const granted = await requestAndroidPermissions();
            if (!granted) {
                setPermissionsDenied(true);
            }
        } catch (error) {
            console.error('[ERROR] Failed to save onboarding state:', error);
            Alert.alert(
                'ERROR',
                'Failed to save your identity. Please restart the app.',
                [{ text: 'OK', style: 'default' }]
            );
        }
    };

    // Determine status bar style based on theme
    const statusBarStyle = currentTheme.background === '#FFFFFF' ? 'dark-content' : 'light-content';

    // Show boot sequence
    if (isBooting) {
        return (
            <SafeAreaView style={[styles.container, { backgroundColor: currentTheme.background }]}>
                <StatusBar barStyle={statusBarStyle} backgroundColor={currentTheme.background} />
                <BootSequence onComplete={handleBootComplete} />
            </SafeAreaView>
        );
    }

    // Show loading while checking first launch
    if (isCheckingFirstLaunch) {
        return (
            <SafeAreaView style={[styles.container, { backgroundColor: currentTheme.background }]}>
                <StatusBar barStyle={statusBarStyle} backgroundColor={currentTheme.background} />
                <View style={[styles.loadingContainer, { backgroundColor: currentTheme.background }]}>
                    <ActivityIndicator size="large" color={currentTheme.primary} />
                    <Text style={[styles.loadingText, { color: currentTheme.text }]}>
                        [SYSTEM] Checking configuration...
                    </Text>
                </View>
            </SafeAreaView>
        );
    }

    // Show onboarding for first launch (before permissions)
    if (isFirstLaunch) {
        return (
            <SafeAreaView style={[styles.container, { backgroundColor: currentTheme.background }]}>
                <StatusBar barStyle={statusBarStyle} backgroundColor={currentTheme.background} />
                <OnboardingScreen onComplete={handleOnboardingComplete} />
            </SafeAreaView>
        );
    }

    // Show permission denied screen
    if (permissionsDenied) {
        return (
            <SafeAreaView style={[styles.container, { backgroundColor: currentTheme.background }]}>
                <StatusBar barStyle={statusBarStyle} backgroundColor={currentTheme.background} />
                <View style={[styles.errorContainer, { backgroundColor: currentTheme.background }]}>
                    <Text style={[styles.errorTitle, { color: currentTheme.error }]}>
                        [ERROR] PERMISSIONS_DENIED
                    </Text>
                    <Text style={[styles.errorText, { color: currentTheme.text }]}>
                        GhostComm requires Bluetooth permissions to function.
                    </Text>
                    <Text style={[styles.errorText, { color: currentTheme.text }]}>
                        Grant permissions in system settings and restart.
                    </Text>
                </View>
            </SafeAreaView>
        );
    }

    // Main app with context provider
    return (
        <GhostCommProvider>
            <SafeAreaView style={[styles.container, { backgroundColor: currentTheme.background }]}>
                <StatusBar barStyle={statusBarStyle} backgroundColor={currentTheme.background} />
                <MainApp />
            </SafeAreaView>
        </GhostCommProvider>
    );
};

// Main App component that wraps everything with ThemeProvider
function App(): React.JSX.Element {
    return (
        <ThemeProvider>
            <ThemedApp />
        </ThemeProvider>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
    },
    mainContainer: {
        flex: 1,
    },
    bootContainer: {
        flex: 1,
        padding: 20,
        justifyContent: 'center',
    },
    asciiArt: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        textAlign: 'center',
        marginBottom: 30,
    },
    bootLogContainer: {
        paddingHorizontal: 20,
    },
    bootLogText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        marginBottom: 4,
    },
    bootCursor: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        opacity: 1,
    },
    loadingContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
    },
    loadingText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 14,
        marginTop: 20,
    },
    errorContainer: {
        flex: 1,
        justifyContent: 'center',
        alignItems: 'center',
        padding: 20,
    },
    errorTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 16,
        marginBottom: 20,
    },
    errorText: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        marginBottom: 10,
        textAlign: 'center',
    },
    header: {
        borderBottomWidth: 1,
        paddingVertical: 15,
        paddingHorizontal: 20,
    },
    headerTitle: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 16,
        fontWeight: '600',
    },
    screenContainer: {
        flex: 1,
    },
    tabBar: {
        borderTopWidth: 1,
        height: 60,
        flexDirection: 'row',
        paddingBottom: 5,
        paddingTop: 5,
    },
    tabButton: {
        flex: 1,
        alignItems: 'center',
        justifyContent: 'center',
    },
    tabIcon: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 20,
    },
    tabLabel: {
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        fontWeight: '600',
        marginTop: 2,
    },
});

export default App;