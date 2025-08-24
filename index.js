/**
 * @format
 * GhostComm Mobile Entry Point
 */

// ============================================================================
// CRITICAL: Polyfills MUST be imported BEFORE anything else
// ============================================================================

// Step 1: Import crypto polyfill FIRST
import 'react-native-get-random-values';

// Step 2: Import and setup Buffer
import { Buffer } from 'buffer';
global.Buffer = Buffer;
globalThis.Buffer = Buffer;

// Step 3: Setup text encoding
global.TextEncoder = class TextEncoder {
    encode(str) {
        if (!str) return new Uint8Array(0);
        const buf = Buffer.from(str, 'utf8');
        // Create proper Uint8Array from Buffer
        return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }
};

global.TextDecoder = class TextDecoder {
    constructor(encoding = 'utf-8') {
        this.encoding = encoding;
    }
    
    decode(arr) {
        if (!arr) return '';
        if (arr instanceof ArrayBuffer) {
            arr = new Uint8Array(arr);
        }
        return Buffer.from(arr).toString('utf8');
    }
};

globalThis.TextEncoder = global.TextEncoder;
globalThis.TextDecoder = global.TextDecoder;

// Step 4: Setup process
if (!global.process) {
    global.process = {
        version: 'v16.0.0',
        env: { NODE_ENV: __DEV__ ? 'development' : 'production' }
    };
}

// Step 5: Base64 encoding
global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
global.atob = (str) => Buffer.from(str, 'base64').toString('binary');

// Step 6: Ensure crypto is available on all global objects
globalThis.crypto = global.crypto;
if (typeof window !== 'undefined') {
    window.crypto = global.crypto;
}

// ============================================================================
// NOW import React Native and App (after all polyfills are set)
// ============================================================================

import { AppRegistry, LogBox, Platform } from 'react-native';
import App from './App';

const appName = 'GhostCommV2';

// Debug utility
let debug = null;
try {
    const debugModule = require('./src/utils/debug');
    debug = debugModule.debug;
} catch (e) {
    debug = {
        info: (...args) => console.log('[INFO]', ...args),
        error: (...args) => console.error('[ERROR]', ...args),
        warn: (...args) => console.warn('[WARN]', ...args),
        success: (...args) => console.log('[SUCCESS]', ...args),
        system: (...args) => console.log('[SYSTEM]', ...args),
        crypto: (...args) => console.log('[CRYPTO]', ...args),
        ble: (...args) => console.log('[BLE]', ...args),
    };
}

global.debug = debug;

// ============================================================================
// Development Configuration
// ============================================================================

if (__DEV__) {
    console.log('================================================================================');
    console.log('🚀 GHOSTCOMM DEVELOPMENT MODE');
    console.log('================================================================================');
    console.log('[INIT] Platform:', Platform.OS);
    console.log('[INIT] Platform Version:', Platform.Version);
    console.log('[INIT] App Name:', appName);

    // Check what's available
    console.log('[INIT] Crypto APIs:');
    console.log('  global.crypto:', typeof global.crypto !== 'undefined' ? '✅' : '❌');
    console.log('  globalThis.crypto:', typeof globalThis.crypto !== 'undefined' ? '✅' : '❌');
    console.log('  crypto.getRandomValues:', typeof crypto?.getRandomValues === 'function' ? '✅' : '❌');
    console.log('  Buffer:', typeof Buffer !== 'undefined' ? '✅' : '❌');
    console.log('  TextEncoder:', typeof TextEncoder !== 'undefined' ? '✅' : '❌');
    console.log('  TextDecoder:', typeof TextDecoder !== 'undefined' ? '✅' : '❌');

    // Ignore specific warnings
    LogBox.ignoreLogs([
        'Non-serializable values were found',
        'VirtualizedLists should never be nested',
        'Require cycle:',
        'Native module not found',
        'Native module cannot be null',
    ]);

    // Test crypto after a delay
    setTimeout(() => {
        console.log('\n[TEST] Testing crypto functions...');

        try {
            // Test getRandomValues
            const testBytes = new Uint8Array(32);
            crypto.getRandomValues(testBytes);
            const nonZero = testBytes.some(b => b !== 0);
            const unique = new Set(testBytes).size;

            console.log('[TEST] Random bytes generated:', nonZero ? '✅' : '❌');
            console.log('[TEST] Randomness quality: ' + unique + '/32 unique values');
            
            // Test if we can actually create noble keys
            console.log('[TEST] Testing noble library compatibility...');
            const { ed25519 } = require('@noble/curves/ed25519');
            const testPrivKey = ed25519.utils.randomPrivateKey();
            console.log('[TEST] Noble ed25519 key generation:', testPrivKey.length === 32 ? '✅' : '❌');
            
            console.log('[TEST] Crypto system ready for keypair generation\n');
        } catch (error) {
            console.error('[TEST] Crypto test failed:', error.message);
            console.error('[TEST] Stack:', error.stack);
        }
    }, 1000);
}

// ============================================================================
// Boot Messages
// ============================================================================

console.log('[SYSTEM] GhostComm initializing...');
console.log('[SYSTEM] Loading encryption modules...');
console.log('[SYSTEM] Preparing mesh network stack...');

// ============================================================================
// Register App
// ============================================================================

AppRegistry.registerComponent(appName, () => App);

console.log('[INIT] App registered as "' + appName + '"');
console.log('[INIT] Crypto polyfills installed - using secure randomness');
console.log('================================================================================\n');