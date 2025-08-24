// mobile/src/screens/OnboardingScreen.tsx
import React, { useState, useEffect, useRef } from 'react';
import {
    View,
    Text,
    TextInput,
    TouchableOpacity,
    StyleSheet,
    ScrollView,
    Platform,
    KeyboardAvoidingView,
    Animated,
    Dimensions,
    Alert,
    Image,
    Easing,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { GhostKeyPair } from '../../core';
import { debug } from '../utils/debug';
import { safeVibrate, vibrationPatterns } from '../utils/vibration';

// Import logo - use require for React Native
const logo = require('../assets/images/logo.png');

interface OnboardingScreenProps {
    onComplete: (keyPairData?: any) => void;
}

const { width: SCREEN_WIDTH, height: SCREEN_HEIGHT } = Dimensions.get('window');

const OnboardingScreen: React.FC<OnboardingScreenProps> = ({ onComplete }) => {
    const [stage, setStage] = useState<'intro' | 'identity' | 'alias' | 'ready'>('intro');
    const [alias, setAlias] = useState('');
    const [keyPair, setKeyPair] = useState<GhostKeyPair | null>(null);
    const [fingerprint, setFingerprint] = useState('');
    const [showCursor, setShowCursor] = useState(true);
    const [matrixRain, setMatrixRain] = useState<string[]>([]);
    const [initializationStep, setInitializationStep] = useState(0);

    // Animation values
    const fadeAnim = useRef(new Animated.Value(0)).current;
    const slideAnim = useRef(new Animated.Value(50)).current;
    const pulseAnim = useRef(new Animated.Value(1)).current;
    const glitchAnim = useRef(new Animated.Value(0)).current;
    const logoRotate = useRef(new Animated.Value(0)).current;
    const scanLineAnim = useRef(new Animated.Value(0)).current;
    const initTextAnim = useRef(new Animated.Value(0)).current;

    // Initialization messages with delays
    const initMessages = [
        { text: "LOADING ENCRYPTION MODULES", delay: 800 },
        { text: "INITIALIZING CHACHA20-POLY1305", delay: 600 },
        { text: "CONFIGURING ED25519 SIGNATURES", delay: 700 },
        { text: "ESTABLISHING SECURE RANDOM", delay: 500 },
        { text: "LOADING MESH PROTOCOL", delay: 900 },
        { text: "INITIALIZING BLUETOOTH STACK", delay: 600 },
        { text: "CONFIGURING P2P DISCOVERY", delay: 700 },
        { text: "SETTING UP RELAY NODES", delay: 500 },
        { text: "VERIFYING CRYPTOGRAPHIC PRIMITIVES", delay: 800 },
        { text: "SYSTEM READY", delay: 1000 }
    ];

    // Cool tech phrases for intro
    const techPhrases = [
        "Decentralized Mesh Networking",
        "End-to-End Encryption",
        "Off-Grid Communication",
        "Untraceable Identity",
        "Peer-to-Peer Protocols",
        "Privacy by Design",
        "Self-Sovereign Identity",
    ];

    const [currentPhrase, setCurrentPhrase] = useState(0);
    const [typingText, setTypingText] = useState('');
    const [currentInitMessage, setCurrentInitMessage] = useState('');

    // Run initialization sequence on mount
    useEffect(() => {
        if (stage === 'intro' && initializationStep < initMessages.length) {
            const message = initMessages[initializationStep];

            // Fade in animation for each message
            Animated.sequence([
                Animated.timing(initTextAnim, {
                    toValue: 0,
                    duration: 100,
                    useNativeDriver: true,
                }),
                Animated.timing(initTextAnim, {
                    toValue: 1,
                    duration: 200,
                    useNativeDriver: true,
                }),
            ]).start();

            setCurrentInitMessage(message.text);

            const timer = setTimeout(() => {
                setInitializationStep(prev => prev + 1);
            }, message.delay);

            return () => clearTimeout(timer);
        }
    }, [stage, initializationStep]);

    // Cursor blink effect
    useEffect(() => {
        const interval = setInterval(() => {
            setShowCursor(prev => !prev);
        }, 500);
        return () => clearInterval(interval);
    }, []);

    // Logo pulse animation
    useEffect(() => {
        const pulse = Animated.loop(
            Animated.sequence([
                Animated.timing(pulseAnim, {
                    toValue: 1.1,
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
    }, []);

    // Scan line animation
    useEffect(() => {
        const scan = Animated.loop(
            Animated.timing(scanLineAnim, {
                toValue: SCREEN_HEIGHT,
                duration: 3000,
                easing: Easing.linear,
                useNativeDriver: true,
            })
        );
        scan.start();
        return () => scan.stop();
    }, []);

    // Stage transition animations
    useEffect(() => {
        // Reset animations
        fadeAnim.setValue(0);
        slideAnim.setValue(50);

        // Glitch effect on transition
        Animated.sequence([
            Animated.timing(glitchAnim, {
                toValue: 1,
                duration: 100,
                useNativeDriver: true,
            }),
            Animated.timing(glitchAnim, {
                toValue: 0,
                duration: 100,
                useNativeDriver: true,
            }),
        ]).start();

        // Fade in new content
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

        // Small vibration on stage change
        vibrationPatterns.tap();
    }, [stage]);

    // Rotating tech phrases (after initialization)
    useEffect(() => {
        if (stage === 'intro' && initializationStep >= initMessages.length) {
            const phraseInterval = setInterval(() => {
                setCurrentPhrase(prev => (prev + 1) % techPhrases.length);
            }, 2000);
            return () => clearInterval(phraseInterval);
        }
    }, [stage, initializationStep]);

    // Typing effect for current phrase
    useEffect(() => {
        if (initializationStep >= initMessages.length) {
            let index = 0;
            const text = techPhrases[currentPhrase];
            setTypingText('');

            const timer = setInterval(() => {
                if (index <= text.length) {
                    setTypingText(text.substring(0, index));
                    index++;
                } else {
                    clearInterval(timer);
                }
            }, 50);

            return () => clearInterval(timer);
        }
    }, [currentPhrase, initializationStep]);

    // Matrix rain effect characters
    useEffect(() => {
        const chars = '01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン';
        const rain = Array(20).fill(0).map(() =>
            chars[Math.floor(Math.random() * chars.length)]
        );
        setMatrixRain(rain);
    }, [stage]);

    const generateIdentity = async () => {
        try {
            debug.info('[ONBOARDING] Generating new keypair...');

            if (typeof global.crypto === 'undefined') {
                debug.error('[ONBOARDING] Crypto not available!');
                Alert.alert(
                    'System Error',
                    'Cryptographic module failed to initialize.',
                    [{ text: 'RETRY', onPress: () => generateIdentity() }]
                );
                throw new Error('Crypto polyfills not loaded');
            }

            // Logo spin animation during generation
            Animated.timing(logoRotate, {
                toValue: 1,
                duration: 1000,
                easing: Easing.linear,
                useNativeDriver: true,
            }).start();

            const newKeyPair = new GhostKeyPair();
            const exported = newKeyPair.exportKeys();

            await AsyncStorage.setItem('@ghostcomm_keypair', JSON.stringify(exported));

            setKeyPair(newKeyPair);
            setFingerprint(newKeyPair.getFingerprint());

            debug.success('[ONBOARDING] Keypair generated:', newKeyPair.getFingerprint());

            // Reset rotation
            logoRotate.setValue(0);

            return exported;
        } catch (error) {
            debug.error('[ONBOARDING] Failed to generate identity:', error);
            Alert.alert(
                'Generation Failed',
                'Identity generation failed. Retrying...',
                [{ text: 'OK' }]
            );
            throw error;
        }
    };

    const handleContinue = async () => {
        // Haptic feedback on button press
        vibrationPatterns.select();

        switch (stage) {
            case 'intro':
                setStage('identity');
                break;
            case 'identity':
                if (!keyPair) {
                    await generateIdentity();
                }
                setStage('alias');
                break;
            case 'alias':
                if (alias.trim()) {
                    await AsyncStorage.setItem('@ghostcomm_alias', alias.trim());
                }
                setStage('ready');
                break;
            case 'ready':
                vibrationPatterns.success();
                const exportedKeyPair = keyPair ? keyPair.exportKeys() : null;
                onComplete(exportedKeyPair);
                break;
        }
    };

    const copyToClipboard = (text: string) => {
        // TODO: Implement clipboard functionality
        vibrationPatterns.success();
        Alert.alert('Copied', 'Fingerprint copied to clipboard');
    };

    const renderIntroStage = () => (
        <Animated.View
            style={[
                styles.stageContainer,
                {
                    opacity: fadeAnim,
                    transform: [
                        { translateY: slideAnim },
                        { translateX: Animated.multiply(glitchAnim, 5) }
                    ],
                },
            ]}
        >
            {/* Logo */}
            <Animated.View style={[
                styles.logoContainer,
                { transform: [{ scale: pulseAnim }] }
            ]}>
                <Image source={logo} style={styles.logo} resizeMode="contain" />
            </Animated.View>

            {/* Initialization sequence or tech phrases */}
            <View style={styles.phraseContainer}>
                {initializationStep < initMessages.length ? (
                    <Animated.Text
                        style={[
                            styles.initMessage,
                            { opacity: initTextAnim }
                        ]}
                    >
                        [{initializationStep + 1}/{initMessages.length}] {currentInitMessage}
                        {showCursor ? '▊' : ' '}
                    </Animated.Text>
                ) : (
                    <Text style={styles.techPhrase}>
                        {typingText}
                        <Text style={styles.cursor}>{showCursor ? '▊' : ' '}</Text>
                    </Text>
                )}
            </View>

            {/* Matrix rain effect in background */}
            <View style={styles.matrixContainer}>
                {matrixRain.map((char, i) => (
                    <Text
                        key={i}
                        style={[
                            styles.matrixChar,
                            {
                                left: `${(i * 5) % 100}%`,
                                opacity: Math.random() * 0.5,
                                top: Math.random() * 100
                            }
                        ]}
                    >
                        {char}
                    </Text>
                ))}
            </View>

            <View style={styles.introContent}>
                <Text style={styles.introTitle}>GHOSTCOMM</Text>
                <Text style={styles.introSubtitle}>MESH PROTOCOL v2.0</Text>

                <View style={styles.featureGrid}>
                    <View style={styles.featureItem}>
                        <Text style={styles.featureIcon}>◉</Text>
                        <Text style={styles.featureText}>P2P MESH</Text>
                    </View>
                    <View style={styles.featureItem}>
                        <Text style={styles.featureIcon}>◉</Text>
                        <Text style={styles.featureText}>E2E ENCRYPTED</Text>
                    </View>
                    <View style={styles.featureItem}>
                        <Text style={styles.featureIcon}>◉</Text>
                        <Text style={styles.featureText}>OFF-GRID</Text>
                    </View>
                    <View style={styles.featureItem}>
                        <Text style={styles.featureIcon}>◉</Text>
                        <Text style={styles.featureText}>UNTRACEABLE</Text>
                    </View>
                </View>
            </View>

            {/* Show button only after initialization completes */}
            {initializationStep >= initMessages.length && (
                <Animated.View style={{ opacity: fadeAnim }}>
                    <TouchableOpacity
                        style={styles.initButton}
                        onPress={handleContinue}
                        activeOpacity={0.8}
                    >
                        <Text style={styles.initButtonText}>INITIALIZE →</Text>
                    </TouchableOpacity>
                </Animated.View>
            )}

            {/* Loading progress bar during initialization */}
            {initializationStep < initMessages.length && (
                <View style={styles.loadingContainer}>
                    <View style={styles.loadingBar}>
                        <View
                            style={[
                                styles.loadingProgress,
                                { width: `${(initializationStep / initMessages.length) * 100}%` }
                            ]}
                        />
                    </View>
                </View>
            )}
        </Animated.View>
    );

    const renderIdentityStage = () => (
        <Animated.View
            style={[
                styles.stageContainer,
                {
                    opacity: fadeAnim,
                    transform: [{ translateY: slideAnim }],
                },
            ]}
        >
            <View style={styles.headerSection}>
                <Text style={styles.stageNumber}>02</Text>
                <Text style={styles.stageTitle}>IDENTITY GENERATION</Text>
                <View style={styles.stageLine} />
            </View>

            {!keyPair ? (
                <View style={styles.generationContainer}>
                    <Text style={styles.generationText}>
                        Generate your cryptographic identity.{'\n'}
                        This creates your unique node signature.
                    </Text>

                    <Animated.View
                        style={[
                            styles.generateButton,
                            {
                                transform: [
                                    {
                                        rotate: logoRotate.interpolate({
                                            inputRange: [0, 1],
                                            outputRange: ['0deg', '360deg'],
                                        }),
                                    },
                                ],
                            },
                        ]}
                    >
                        <TouchableOpacity
                            style={styles.primaryButton}
                            onPress={() => {
                                vibrationPatterns.impact();
                                generateIdentity();
                            }}
                            activeOpacity={0.8}
                        >
                            <Text style={styles.primaryButtonText}>⚡ GENERATE IDENTITY</Text>
                        </TouchableOpacity>
                    </Animated.View>

                    <TouchableOpacity
                        style={styles.importButton}
                        onPress={() => {
                            vibrationPatterns.tap();
                            Alert.alert('Import', 'Feature coming soon');
                        }}
                    >
                        <Text style={styles.importButtonText}>↓ IMPORT EXISTING</Text>
                    </TouchableOpacity>
                </View>
            ) : (
                <View style={styles.identityReady}>
                    <View style={styles.fingerprintContainer}>
                        <Text style={styles.fingerprintLabel}>NODE FINGERPRINT</Text>
                        <TouchableOpacity
                            onPress={() => copyToClipboard(fingerprint)}
                            activeOpacity={0.7}
                        >
                            <View style={styles.fingerprintBox}>
                                <Text style={styles.fingerprintText}>
                                    {fingerprint.match(/.{1,4}/g)?.map((chunk, i) => (
                                        <Text key={i}>
                                            {chunk}
                                            {i < 3 ? ' ' : ''}
                                        </Text>
                                    ))}
                                </Text>
                                <Text style={styles.copyIcon}>📋</Text>
                            </View>
                        </TouchableOpacity>
                        <Text style={styles.fingerprintHint}>TAP TO COPY</Text>
                    </View>

                    <View style={styles.securityInfo}>
                        <Text style={styles.securityIcon}>🔐</Text>
                        <Text style={styles.securityText}>
                            ED25519 / CHACHA20-POLY1305
                        </Text>
                    </View>

                    <TouchableOpacity
                        style={styles.continueButton}
                        onPress={handleContinue}
                        activeOpacity={0.8}
                    >
                        <Text style={styles.continueButtonText}>CONTINUE →</Text>
                    </TouchableOpacity>
                </View>
            )}
        </Animated.View>
    );

    const renderAliasStage = () => (
        <Animated.View
            style={[
                styles.stageContainer,
                {
                    opacity: fadeAnim,
                    transform: [{ translateY: slideAnim }],
                },
            ]}
        >
            <View style={styles.headerSection}>
                <Text style={styles.stageNumber}>03</Text>
                <Text style={styles.stageTitle}>SELECT CALLSIGN</Text>
                <View style={styles.stageLine} />
            </View>

            <View style={styles.aliasContainer}>
                <Text style={styles.aliasInfo}>
                    Choose your network identifier.{'\n'}
                    This can be changed anytime.
                </Text>

                <View style={styles.aliasPreview}>
                    <Text style={styles.previewText}>
                        {alias || 'ghost'}@{fingerprint.substring(0, 8).toLowerCase()}
                    </Text>
                </View>

                <View style={styles.inputWrapper}>
                    <View style={styles.inputContainer}>
                        <Text style={styles.inputPrefix}>$</Text>
                        <TextInput
                            style={styles.aliasInput}
                            value={alias}
                            onChangeText={setAlias}
                            placeholder="ghost"
                            placeholderTextColor="#006600"
                            maxLength={16}
                            autoCapitalize="none"
                            autoCorrect={false}
                            returnKeyType="done"
                            onSubmitEditing={handleContinue}
                        />
                        <Text style={styles.inputCursor}>{showCursor ? '▊' : ' '}</Text>
                    </View>
                    <Text style={styles.charCounter}>{alias.length}/16</Text>
                </View>

                <View style={styles.suggestionsContainer}>
                    <Text style={styles.suggestionsTitle}>SUGGESTIONS:</Text>
                    <View style={styles.suggestions}>
                        {['cipher', 'phantom', 'shadow', 'spectre'].map((suggestion) => (
                            <TouchableOpacity
                                key={suggestion}
                                style={styles.suggestionChip}
                                onPress={() => {
                                    vibrationPatterns.select();
                                    setAlias(suggestion);
                                }}
                            >
                                <Text style={styles.suggestionText}>{suggestion}</Text>
                            </TouchableOpacity>
                        ))}
                    </View>
                </View>

                <TouchableOpacity
                    style={[styles.continueButton, !alias && styles.skipButton]}
                    onPress={handleContinue}
                    activeOpacity={0.8}
                >
                    <Text style={styles.continueButtonText}>
                        {alias ? 'SET CALLSIGN →' : 'SKIP →'}
                    </Text>
                </TouchableOpacity>
            </View>
        </Animated.View>
    );

    const renderReadyStage = () => (
        <Animated.View
            style={[
                styles.stageContainer,
                {
                    opacity: fadeAnim,
                    transform: [{ translateY: slideAnim }],
                },
            ]}
        >
            <View style={styles.headerSection}>
                <Text style={styles.stageNumber}>04</Text>
                <Text style={styles.stageTitle}>READY TO CONNECT</Text>
                <View style={styles.stageLine} />
            </View>

            <View style={styles.readyContainer}>
                <Animated.View
                    style={[
                        styles.nodeVisual,
                        { transform: [{ scale: pulseAnim }] }
                    ]}
                >
                    <View style={styles.nodeCenter}>
                        <Text style={styles.nodeIcon}>◈</Text>
                    </View>
                    <View style={styles.nodeRing} />
                    <View style={[styles.nodeRing, styles.nodeRingOuter]} />
                </Animated.View>

                <View style={styles.statusGrid}>
                    <View style={styles.statusItem}>
                        <Text style={styles.statusLabel}>IDENTITY</Text>
                        <Text style={styles.statusValue}>{fingerprint.substring(0, 8)}...</Text>
                    </View>
                    <View style={styles.statusItem}>
                        <Text style={styles.statusLabel}>CALLSIGN</Text>
                        <Text style={styles.statusValue}>{alias || 'ghost'}</Text>
                    </View>
                    <View style={styles.statusItem}>
                        <Text style={styles.statusLabel}>PROTOCOL</Text>
                        <Text style={styles.statusValue}>MESH/BLE</Text>
                    </View>
                    <View style={styles.statusItem}>
                        <Text style={styles.statusLabel}>STATUS</Text>
                        <Text style={[styles.statusValue, styles.statusOnline]}>ONLINE</Text>
                    </View>
                </View>

                <TouchableOpacity
                    style={styles.launchButton}
                    onPress={handleContinue}
                    activeOpacity={0.8}
                >
                    <Text style={styles.launchButtonText}>ENTER NETWORK →</Text>
                </TouchableOpacity>
            </View>

            {/* Scan line effect */}
            <Animated.View
                style={[
                    styles.scanLine,
                    {
                        transform: [{ translateY: scanLineAnim }],
                    },
                ]}
            />
        </Animated.View>
    );

    return (
        <KeyboardAvoidingView
            style={styles.container}
            behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        >
            <ScrollView
                contentContainerStyle={styles.scrollContainer}
                keyboardShouldPersistTaps="handled"
                showsVerticalScrollIndicator={false}
            >
                {stage === 'intro' && renderIntroStage()}
                {stage === 'identity' && renderIdentityStage()}
                {stage === 'alias' && renderAliasStage()}
                {stage === 'ready' && renderReadyStage()}

                {/* Progress indicator */}
                <View style={styles.progressContainer}>
                    <View style={styles.progressDots}>
                        {['intro', 'identity', 'alias', 'ready'].map((s, i) => (
                            <View
                                key={s}
                                style={[
                                    styles.progressDot,
                                    stage === s && styles.progressDotActive,
                                    ['intro', 'identity', 'alias'].indexOf(stage) > i && styles.progressDotComplete,
                                ]}
                            />
                        ))}
                    </View>
                </View>
            </ScrollView>
        </KeyboardAvoidingView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#000000',
    },
    scrollContainer: {
        flexGrow: 1,
        justifyContent: 'center',
        padding: 20,
        minHeight: SCREEN_HEIGHT,
    },
    stageContainer: {
        flex: 1,
        justifyContent: 'center',
    },

    // Logo styles
    logoContainer: {
        alignItems: 'center',
        marginBottom: 40,
    },
    logo: {
        width: 120,
        height: 120,
    },

    // Intro stage
    phraseContainer: {
        height: 30,
        justifyContent: 'center',
        alignItems: 'center',
        marginBottom: 30,
    },
    initMessage: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        letterSpacing: 1,
        opacity: 0.8,
    },
    techPhrase: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        letterSpacing: 2,
        opacity: 0.7,
    },
    loadingContainer: {
        marginTop: 30,
        paddingHorizontal: 40,
    },
    loadingBar: {
        height: 2,
        backgroundColor: '#001100',
        borderWidth: 1,
        borderColor: '#00FF00',
    },
    loadingProgress: {
        height: '100%',
        backgroundColor: '#00FF00',
    },
    matrixContainer: {
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        zIndex: -1,
    },
    matrixChar: {
        position: 'absolute',
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
    },
    introContent: {
        alignItems: 'center',
        marginBottom: 40,
    },
    introTitle: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 32,
        fontWeight: 'bold',
        letterSpacing: 4,
        marginBottom: 5,
    },
    introSubtitle: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        opacity: 0.6,
        letterSpacing: 2,
        marginBottom: 30,
    },
    featureGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'center',
        marginTop: 20,
    },
    featureItem: {
        flexDirection: 'row',
        alignItems: 'center',
        width: '45%',
        marginBottom: 15,
    },
    featureIcon: {
        color: '#00FF00',
        fontSize: 10,
        marginRight: 8,
    },
    featureText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 11,
        opacity: 0.8,
    },
    initButton: {
        backgroundColor: 'transparent',
        borderWidth: 2,
        borderColor: '#00FF00',
        paddingVertical: 15,
        paddingHorizontal: 40,
        alignSelf: 'center',
    },
    initButtonText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 2,
    },

    // Header section
    headerSection: {
        marginBottom: 40,
    },
    stageNumber: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 48,
        opacity: 0.2,
        marginBottom: 10,
    },
    stageTitle: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 18,
        fontWeight: 'bold',
        letterSpacing: 3,
        marginBottom: 10,
    },
    stageLine: {
        height: 1,
        backgroundColor: '#00FF00',
        opacity: 0.3,
    },

    // Identity stage
    generationContainer: {
        alignItems: 'center',
    },
    generationText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 13,
        textAlign: 'center',
        opacity: 0.8,
        lineHeight: 20,
        marginBottom: 40,
    },
    generateButton: {
        marginBottom: 20,
    },
    primaryButton: {
        backgroundColor: '#00FF00',
        paddingVertical: 15,
        paddingHorizontal: 30,
    },
    primaryButtonText: {
        color: '#000000',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 1,
    },
    importButton: {
        borderWidth: 1,
        borderColor: '#00FF00',
        paddingVertical: 12,
        paddingHorizontal: 25,
        opacity: 0.6,
    },
    importButtonText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
        letterSpacing: 1,
    },
    identityReady: {
        alignItems: 'center',
    },
    fingerprintContainer: {
        marginBottom: 30,
    },
    fingerprintLabel: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 2,
        marginBottom: 10,
        textAlign: 'center',
    },
    fingerprintBox: {
        backgroundColor: '#001100',
        borderWidth: 1,
        borderColor: '#00FF00',
        paddingVertical: 20,
        paddingHorizontal: 30,
        flexDirection: 'row',
        alignItems: 'center',
    },
    fingerprintText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 16,
        fontWeight: 'bold',
        letterSpacing: 2,
    },
    copyIcon: {
        marginLeft: 15,
        fontSize: 16,
    },
    fingerprintHint: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.4,
        marginTop: 5,
        textAlign: 'center',
        letterSpacing: 1,
    },
    securityInfo: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 30,
        paddingHorizontal: 20,
        paddingVertical: 10,
        backgroundColor: '#001100',
    },
    securityIcon: {
        fontSize: 16,
        marginRight: 10,
    },
    securityText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.6,
        letterSpacing: 1,
    },

    // Alias stage
    aliasContainer: {
        alignItems: 'center',
    },
    aliasInfo: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 13,
        textAlign: 'center',
        opacity: 0.8,
        lineHeight: 20,
        marginBottom: 30,
    },
    aliasPreview: {
        backgroundColor: '#001100',
        borderWidth: 1,
        borderColor: '#00FF00',
        borderStyle: 'dashed',
        paddingVertical: 15,
        paddingHorizontal: 20,
        marginBottom: 30,
        width: '100%',
    },
    previewText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 14,
        textAlign: 'center',
        opacity: 0.7,
    },
    inputWrapper: {
        width: '100%',
        marginBottom: 30,
    },
    inputContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        backgroundColor: '#001100',
        borderWidth: 1,
        borderColor: '#00FF00',
        paddingVertical: 15,
        paddingHorizontal: 20,
        marginBottom: 5,
    },
    inputPrefix: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 14,
        marginRight: 10,
    },
    aliasInput: {
        flex: 1,
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 14,
        padding: 0,
    },
    inputCursor: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 14,
    },
    charCounter: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.4,
        textAlign: 'right',
    },
    suggestionsContainer: {
        width: '100%',
        marginBottom: 30,
    },
    suggestionsTitle: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 10,
        opacity: 0.5,
        letterSpacing: 2,
        marginBottom: 10,
    },
    suggestions: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'center',
    },
    suggestionChip: {
        borderWidth: 1,
        borderColor: '#00FF00',
        paddingVertical: 8,
        paddingHorizontal: 15,
        margin: 5,
        opacity: 0.6,
    },
    suggestionText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
    },

    // Ready stage
    readyContainer: {
        alignItems: 'center',
    },
    nodeVisual: {
        width: 150,
        height: 150,
        justifyContent: 'center',
        alignItems: 'center',
        marginBottom: 40,
    },
    nodeCenter: {
        position: 'absolute',
        width: 50,
        height: 50,
        justifyContent: 'center',
        alignItems: 'center',
        backgroundColor: '#001100',
        borderWidth: 2,
        borderColor: '#00FF00',
    },
    nodeIcon: {
        color: '#00FF00',
        fontSize: 24,
    },
    nodeRing: {
        position: 'absolute',
        width: 100,
        height: 100,
        borderWidth: 1,
        borderColor: '#00FF00',
        borderRadius: 50,
        opacity: 0.3,
    },
    nodeRingOuter: {
        width: 140,
        height: 140,
        opacity: 0.1,
    },
    statusGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        width: '100%',
        marginBottom: 40,
    },
    statusItem: {
        width: '48%',
        backgroundColor: '#001100',
        borderWidth: 1,
        borderColor: '#00FF00',
        padding: 15,
        marginBottom: 10,
    },
    statusLabel: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 9,
        opacity: 0.5,
        letterSpacing: 1,
        marginBottom: 5,
    },
    statusValue: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 13,
        fontWeight: 'bold',
    },
    statusOnline: {
        color: '#00FF00',
        textShadowColor: '#00FF00',
        textShadowRadius: 5,
    },

    // Buttons
    continueButton: {
        backgroundColor: 'transparent',
        borderWidth: 2,
        borderColor: '#00FF00',
        paddingVertical: 15,
        paddingHorizontal: 30,
    },
    continueButtonText: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 14,
        fontWeight: 'bold',
        letterSpacing: 2,
        textAlign: 'center',
    },
    skipButton: {
        opacity: 0.5,
        borderStyle: 'dashed',
    },
    launchButton: {
        backgroundColor: '#00FF00',
        paddingVertical: 18,
        paddingHorizontal: 40,
    },
    launchButtonText: {
        color: '#000000',
        fontFamily: Platform.OS === 'ios' ? 'Courier-Bold' : 'monospace',
        fontSize: 16,
        fontWeight: 'bold',
        letterSpacing: 2,
    },

    // Progress indicator
    progressContainer: {
        position: 'absolute',
        bottom: 40,
        left: 0,
        right: 0,
        alignItems: 'center',
    },
    progressDots: {
        flexDirection: 'row',
        justifyContent: 'center',
    },
    progressDot: {
        width: 8,
        height: 8,
        borderRadius: 4,
        backgroundColor: 'transparent',
        borderWidth: 1,
        borderColor: '#00FF00',
        marginHorizontal: 8,
        opacity: 0.3,
    },
    progressDotActive: {
        backgroundColor: '#00FF00',
        opacity: 1,
        shadowColor: '#00FF00',
        shadowRadius: 10,
        shadowOpacity: 0.8,
    },
    progressDotComplete: {
        backgroundColor: '#00FF00',
        opacity: 0.5,
    },

    // Effects
    cursor: {
        color: '#00FF00',
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontSize: 12,
    },
    scanLine: {
        position: 'absolute',
        left: 0,
        right: 0,
        height: 2,
        backgroundColor: '#00FF00',
        opacity: 0.1,
    },
});

export default OnboardingScreen;