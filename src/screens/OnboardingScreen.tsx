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
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { GhostKeyPair } from '../../core';
import { debug } from '../utils/debug';
import { safeVibrate, vibrationPatterns } from '../utils/vibration';

// Import logo
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
    const [isGenerating, setIsGenerating] = useState(false);

    // Subtle fade animation
    const fadeAnim = useRef(new Animated.Value(0)).current;

    // Stage transition animation
    useEffect(() => {
        fadeAnim.setValue(0);
        Animated.timing(fadeAnim, {
            toValue: 1,
            duration: 600,
            useNativeDriver: true,
        }).start();
        
        vibrationPatterns.tap();
    }, [stage]);

    const generateIdentity = async () => {
        try {
            setIsGenerating(true);
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

            const newKeyPair = new GhostKeyPair();
            const exported = newKeyPair.exportKeys();

            await AsyncStorage.setItem('@ghostcomm_keypair', JSON.stringify(exported));

            setKeyPair(newKeyPair);
            setFingerprint(newKeyPair.getFingerprint());

            debug.success('[ONBOARDING] Keypair generated:', newKeyPair.getFingerprint());
            setIsGenerating(false);

            return exported;
        } catch (error) {
            setIsGenerating(false);
            debug.error('[ONBOARDING] Failed to generate identity:', error);
            Alert.alert(
                'Generation Failed',
                'Identity generation failed. Please retry.',
                [{ text: 'OK' }]
            );
            throw error;
        }
    };

    const handleContinue = async () => {
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
        vibrationPatterns.success();
        Alert.alert('Copied', 'Fingerprint copied to clipboard');
    };

    const renderIntro = () => (
        <Animated.View style={[styles.centerContainer, { opacity: fadeAnim }]}>
            {/* Logo Mark */}
            <View style={styles.logoContainer}>
                <Image 
                    source={logo} 
                    style={styles.logo} 
                    resizeMode="contain" 
                />
            </View>

            {/* Brand Name */}
            <View style={styles.brandContainer}>
                <Text style={styles.brandTitle}>GHOSTCOMM</Text>
                <Text style={styles.brandSubtitle}>SECURE MESH PROTOCOL</Text>
            </View>

            {/* Feature Grid */}
            <View style={styles.featureGrid}>
                <View style={styles.featureRow}>
                    <View style={styles.featureItem}>
                        <View style={styles.featureDot} />
                        <Text style={styles.featureText}>PEER TO PEER</Text>
                    </View>
                    <View style={styles.featureItem}>
                        <View style={styles.featureDot} />
                        <Text style={styles.featureText}>END-TO-END</Text>
                    </View>
                </View>
                <View style={styles.featureRow}>
                    <View style={styles.featureItem}>
                        <View style={styles.featureDot} />
                        <Text style={styles.featureText}>OFF-GRID</Text>
                    </View>
                    <View style={styles.featureItem}>
                        <View style={styles.featureDot} />
                        <Text style={styles.featureText}>UNTRACEABLE</Text>
                    </View>
                </View>
            </View>

            {/* Primary Action */}
            <TouchableOpacity
                style={styles.primaryButton}
                onPress={handleContinue}
                activeOpacity={0.9}
            >
                <Text style={styles.primaryButtonText}>BEGIN</Text>
            </TouchableOpacity>
        </Animated.View>
    );

    const renderIdentity = () => (
        <Animated.View style={[styles.centerContainer, { opacity: fadeAnim }]}>
            {/* Stage Header */}
            <View style={styles.stageHeader}>
                <Text style={styles.stageNumber}>01</Text>
                <Text style={styles.stageTitle}>CRYPTOGRAPHIC IDENTITY</Text>
                <View style={styles.divider} />
            </View>

            {/* Content */}
            {!keyPair ? (
                <View style={styles.contentContainer}>
                    <Text style={styles.description}>
                        Generate your unique cryptographic identity.{'\n'}
                        This creates your secure node signature.
                    </Text>

                    <TouchableOpacity
                        style={[styles.primaryButton, isGenerating && styles.buttonDisabled]}
                        onPress={generateIdentity}
                        activeOpacity={0.9}
                        disabled={isGenerating}
                    >
                        <Text style={styles.primaryButtonText}>
                            {isGenerating ? 'GENERATING...' : 'GENERATE IDENTITY'}
                        </Text>
                    </TouchableOpacity>

                    <TouchableOpacity
                        style={styles.secondaryButton}
                        onPress={() => Alert.alert('Import', 'Feature coming soon')}
                        activeOpacity={0.9}
                    >
                        <Text style={styles.secondaryButtonText}>IMPORT EXISTING</Text>
                    </TouchableOpacity>
                </View>
            ) : (
                <View style={styles.contentContainer}>
                    <View style={styles.fingerprintSection}>
                        <Text style={styles.labelText}>NODE FINGERPRINT</Text>
                        <TouchableOpacity
                            style={styles.fingerprintBox}
                            onPress={() => copyToClipboard(fingerprint)}
                            activeOpacity={0.9}
                        >
                            <Text style={styles.fingerprintText}>
                                {fingerprint.match(/.{1,4}/g)?.join(' ')}
                            </Text>
                        </TouchableOpacity>
                        <Text style={styles.hintText}>TAP TO COPY</Text>
                    </View>

                    <View style={styles.encryptionInfo}>
                        <Text style={styles.encryptionText}>ED25519 • CHACHA20-POLY1305</Text>
                    </View>

                    <TouchableOpacity
                        style={styles.primaryButton}
                        onPress={handleContinue}
                        activeOpacity={0.9}
                    >
                        <Text style={styles.primaryButtonText}>CONTINUE</Text>
                    </TouchableOpacity>
                </View>
            )}
        </Animated.View>
    );

    const renderAlias = () => (
        <Animated.View style={[styles.centerContainer, { opacity: fadeAnim }]}>
            {/* Stage Header */}
            <View style={styles.stageHeader}>
                <Text style={styles.stageNumber}>02</Text>
                <Text style={styles.stageTitle}>SELECT CALLSIGN</Text>
                <View style={styles.divider} />
            </View>

            {/* Content */}
            <View style={styles.contentContainer}>
                <Text style={styles.description}>
                    Choose your network identifier.{'\n'}
                    This can be changed anytime.
                </Text>

                {/* Preview */}
                <View style={styles.previewBox}>
                    <Text style={styles.previewText}>
                        {alias || 'anonymous'}@{fingerprint.substring(0, 8).toLowerCase()}
                    </Text>
                </View>

                {/* Input Field */}
                <View style={styles.inputContainer}>
                    <TextInput
                        style={styles.textInput}
                        value={alias}
                        onChangeText={setAlias}
                        placeholder="Enter callsign"
                        placeholderTextColor="#999999"
                        maxLength={16}
                        autoCapitalize="none"
                        autoCorrect={false}
                        returnKeyType="done"
                        onSubmitEditing={handleContinue}
                    />
                    <Text style={styles.charCount}>{alias.length}/16</Text>
                </View>

                {/* Suggestions */}
                <View style={styles.suggestionsRow}>
                    {['cipher', 'phantom', 'shadow', 'spectre'].map((suggestion) => (
                        <TouchableOpacity
                            key={suggestion}
                            style={styles.suggestionChip}
                            onPress={() => {
                                vibrationPatterns.select();
                                setAlias(suggestion);
                            }}
                            activeOpacity={0.9}
                        >
                            <Text style={styles.suggestionText}>{suggestion}</Text>
                        </TouchableOpacity>
                    ))}
                </View>

                <TouchableOpacity
                    style={styles.primaryButton}
                    onPress={handleContinue}
                    activeOpacity={0.9}
                >
                    <Text style={styles.primaryButtonText}>
                        {alias ? 'SET CALLSIGN' : 'SKIP'}
                    </Text>
                </TouchableOpacity>
            </View>
        </Animated.View>
    );

    const renderReady = () => (
        <Animated.View style={[styles.centerContainer, { opacity: fadeAnim }]}>
            {/* Stage Header */}
            <View style={styles.stageHeader}>
                <Text style={styles.stageNumber}>03</Text>
                <Text style={styles.stageTitle}>READY TO CONNECT</Text>
                <View style={styles.divider} />
            </View>

            {/* Node Visual */}
            <View style={styles.nodeContainer}>
                <View style={styles.node}>
                    <View style={styles.nodeInner} />
                </View>
            </View>

            {/* Status Summary */}
            <View style={styles.statusContainer}>
                <View style={styles.statusRow}>
                    <Text style={styles.statusLabel}>IDENTITY</Text>
                    <Text style={styles.statusValue}>{fingerprint.substring(0, 8)}...</Text>
                </View>
                <View style={styles.statusRow}>
                    <Text style={styles.statusLabel}>CALLSIGN</Text>
                    <Text style={styles.statusValue}>{alias || 'anonymous'}</Text>
                </View>
                <View style={styles.statusRow}>
                    <Text style={styles.statusLabel}>PROTOCOL</Text>
                    <Text style={styles.statusValue}>MESH/BLE</Text>
                </View>
                <View style={styles.statusRow}>
                    <Text style={styles.statusLabel}>STATUS</Text>
                    <Text style={styles.statusValue}>READY</Text>
                </View>
            </View>

            <TouchableOpacity
                style={[styles.primaryButton, styles.enterButton]}
                onPress={handleContinue}
                activeOpacity={0.9}
            >
                <Text style={styles.primaryButtonText}>ENTER NETWORK</Text>
            </TouchableOpacity>
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
                {stage === 'intro' && renderIntro()}
                {stage === 'identity' && renderIdentity()}
                {stage === 'alias' && renderAlias()}
                {stage === 'ready' && renderReady()}

                {/* Progress Indicator */}
                <View style={styles.progressContainer}>
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
            </ScrollView>
        </KeyboardAvoidingView>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#FFFFFF',
    },
    scrollContainer: {
        flexGrow: 1,
        justifyContent: 'center',
        minHeight: SCREEN_HEIGHT,
    },
    centerContainer: {
        flex: 1,
        justifyContent: 'center',
        paddingHorizontal: 40,
    },

    // Logo Styles
    logoContainer: {
        alignItems: 'center',
        marginBottom: 60,
    },
    logo: {
        width: 160,
        height: 160,
    },

    // Brand Styles
    brandContainer: {
        alignItems: 'center',
        marginBottom: 60,
    },
    brandTitle: {
        fontSize: 28,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '200',
        letterSpacing: 8,
        color: '#000000',
        marginBottom: 8,
    },
    brandSubtitle: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 3,
        color: '#666666',
    },

    // Feature Grid
    featureGrid: {
        marginBottom: 60,
    },
    featureRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 24,
    },
    featureItem: {
        flexDirection: 'row',
        alignItems: 'center',
        flex: 1,
    },
    featureDot: {
        width: 4,
        height: 4,
        borderRadius: 2,
        backgroundColor: '#000000',
        marginRight: 12,
    },
    featureText: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 2,
        color: '#000000',
    },

    // Stage Header
    stageHeader: {
        alignItems: 'center',
        marginBottom: 50,
    },
    stageNumber: {
        fontSize: 48,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '100',
        color: '#E5E5E5',
        marginBottom: 16,
    },
    stageTitle: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        letterSpacing: 4,
        color: '#000000',
        marginBottom: 16,
    },
    divider: {
        width: 40,
        height: 1,
        backgroundColor: '#E5E5E5',
    },

    // Content Container
    contentContainer: {
        alignItems: 'center',
    },
    description: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        color: '#666666',
        textAlign: 'center',
        lineHeight: 22,
        marginBottom: 40,
    },

    // Buttons
    primaryButton: {
        backgroundColor: '#000000',
        paddingVertical: 18,
        paddingHorizontal: 60,
        marginBottom: 16,
    },
    primaryButtonText: {
        color: '#FFFFFF',
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 3,
        textAlign: 'center',
    },
    secondaryButton: {
        borderWidth: 1,
        borderColor: '#E5E5E5',
        paddingVertical: 16,
        paddingHorizontal: 40,
    },
    secondaryButtonText: {
        color: '#999999',
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 2,
    },
    buttonDisabled: {
        opacity: 0.3,
    },
    enterButton: {
        marginTop: 20,
    },

    // Fingerprint Section
    fingerprintSection: {
        alignItems: 'center',
        marginBottom: 30,
    },
    labelText: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 2,
        color: '#999999',
        marginBottom: 12,
    },
    fingerprintBox: {
        backgroundColor: '#F8F8F8',
        paddingVertical: 20,
        paddingHorizontal: 30,
        marginBottom: 8,
    },
    fingerprintText: {
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        fontWeight: '400',
        color: '#000000',
        letterSpacing: 1,
    },
    hintText: {
        fontSize: 9,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1,
        color: '#CCCCCC',
    },

    // Encryption Info
    encryptionInfo: {
        marginBottom: 40,
    },
    encryptionText: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1.5,
        color: '#999999',
    },

    // Alias Input
    previewBox: {
        backgroundColor: '#F8F8F8',
        paddingVertical: 16,
        paddingHorizontal: 24,
        marginBottom: 24,
        width: '100%',
    },
    previewText: {
        fontSize: 14,
        fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
        color: '#666666',
        textAlign: 'center',
    },
    inputContainer: {
        flexDirection: 'row',
        alignItems: 'center',
        borderBottomWidth: 1,
        borderBottomColor: '#E5E5E5',
        marginBottom: 30,
        width: '100%',
    },
    textInput: {
        flex: 1,
        fontSize: 16,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '300',
        color: '#000000',
        paddingVertical: 12,
    },
    charCount: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        color: '#CCCCCC',
    },

    // Suggestions
    suggestionsRow: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'center',
        marginBottom: 40,
    },
    suggestionChip: {
        borderWidth: 1,
        borderColor: '#E5E5E5',
        paddingVertical: 8,
        paddingHorizontal: 16,
        margin: 4,
    },
    suggestionText: {
        fontSize: 11,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        color: '#666666',
    },

    // Ready Stage
    nodeContainer: {
        alignItems: 'center',
        marginBottom: 40,
    },
    node: {
        width: 120,
        height: 120,
        borderRadius: 60,
        borderWidth: 1,
        borderColor: '#E5E5E5',
        alignItems: 'center',
        justifyContent: 'center',
    },
    nodeInner: {
        width: 60,
        height: 60,
        borderRadius: 30,
        backgroundColor: '#000000',
    },

    // Status Summary
    statusContainer: {
        width: '100%',
        marginBottom: 30,
    },
    statusRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        paddingVertical: 12,
        borderBottomWidth: 1,
        borderBottomColor: '#F5F5F5',
    },
    statusLabel: {
        fontSize: 10,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        letterSpacing: 1.5,
        color: '#999999',
    },
    statusValue: {
        fontSize: 12,
        fontFamily: Platform.OS === 'ios' ? 'Helvetica Neue' : 'sans-serif',
        fontWeight: '400',
        color: '#000000',
    },

    // Progress Indicator
    progressContainer: {
        position: 'absolute',
        bottom: 50,
        left: 0,
        right: 0,
        flexDirection: 'row',
        justifyContent: 'center',
    },
    progressDot: {
        width: 6,
        height: 6,
        borderRadius: 3,
        backgroundColor: '#E5E5E5',
        marginHorizontal: 6,
    },
    progressDotActive: {
        backgroundColor: '#000000',
        width: 24,
    },
    progressDotComplete: {
        backgroundColor: '#000000',
    },
});

export default OnboardingScreen;