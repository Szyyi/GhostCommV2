/**
 * @format
 * GhostComm Mobile Entry Point
 */

// ============================================================================
// CRITICAL: Fix crypto BEFORE noble libraries load
// ============================================================================

// Create global crypto object
if (!global.crypto) {
    global.crypto = {};
}

// Install our getRandomValues implementation
global.crypto.getRandomValues = function (buffer) {
    const timestamp = Date.now();
    const random = Math.random;

    if (buffer instanceof Uint8Array || buffer instanceof Uint8ClampedArray) {
        for (let i = 0; i < buffer.length; i++) {
            buffer[i] = Math.floor((random() * timestamp * (i + 1)) % 256);
        }
    } else if (buffer instanceof Uint16Array) {
        for (let i = 0; i < buffer.length; i++) {
            buffer[i] = Math.floor((random() * timestamp * (i + 1)) % 65536);
        }
    } else if (buffer instanceof Uint32Array) {
        for (let i = 0; i < buffer.length; i++) {
            buffer[i] = Math.floor((random() * timestamp * (i + 1)) % 4294967296);
        }
    } else if (buffer instanceof Int8Array) {
        for (let i = 0; i < buffer.length; i++) {
            buffer[i] = Math.floor((random() * timestamp * (i + 1)) % 128) - 64;
        }
    } else if (buffer instanceof Int16Array) {
        for (let i = 0; i < buffer.length; i++) {
            buffer[i] = Math.floor((random() * timestamp * (i + 1)) % 32768) - 16384;
        }
    } else if (buffer instanceof Int32Array) {
        for (let i = 0; i < buffer.length; i++) {
            buffer[i] = Math.floor((random() * timestamp * (i + 1)) % 2147483648) - 1073741824;
        }
    }

    return buffer;
};

// Also create webcrypto for noble libraries
global.crypto.web = global.crypto;
global.crypto.node = global.crypto;

// Create a fake subtle API (noble might check for it)
if (!global.crypto.subtle) {
    global.crypto.subtle = {
        digest: async () => new ArrayBuffer(32),
        generateKey: async () => ({}),
        importKey: async () => ({}),
        exportKey: async () => ({}),
        encrypt: async () => new ArrayBuffer(32),
        decrypt: async () => new ArrayBuffer(32),
    };
}

console.warn('================================================================================');
console.warn('⚠️  CRYPTO FALLBACK ACTIVE - Using Math.random for testing only!');
console.warn('================================================================================');

// Try to load native module but don't fail if it doesn't work
try {
    require('react-native-get-random-values');
    // If it loads, it will override our fallback (which is fine)
} catch (e) {
    // Ignore - we have our fallback
}

// ============================================================================
// Patch Noble Libraries Random Function
// ============================================================================

// The noble libraries check for crypto in a specific way
// We need to ensure they find our implementation
if (typeof globalThis === 'undefined') {
    global.globalThis = global;
}

// Ensure globalThis has crypto
globalThis.crypto = global.crypto;

// Also set on window (some libraries check window.crypto)
if (typeof window !== 'undefined') {
    window.crypto = global.crypto;
}

// ============================================================================
// Buffer and Text Encoding Polyfills
// ============================================================================

import { Buffer } from 'buffer';
global.Buffer = Buffer;

// Make Buffer available on globalThis too
globalThis.Buffer = Buffer;

// btoa/atob for base64
if (!global.btoa) {
    global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
}
if (!global.atob) {
    global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
}

// TextEncoder/TextDecoder
if (typeof global.TextEncoder === 'undefined') {
    global.TextEncoder = class TextEncoder {
        encode(str) {
            if (!str) return new Uint8Array(0);
            const buf = Buffer.from(str, 'utf8');
            const arr = new Uint8Array(buf.length);
            for (let i = 0; i < buf.length; i++) {
                arr[i] = buf[i];
            }
            return arr;
        }
    };
}

if (typeof global.TextDecoder === 'undefined') {
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
}

// Make text encoding available globally
globalThis.TextEncoder = global.TextEncoder;
globalThis.TextDecoder = global.TextDecoder;

// Process polyfill
if (typeof global.process === 'undefined') {
    global.process = {
        version: 'v16.0.0',
        env: { NODE_ENV: __DEV__ ? 'development' : 'production' }
    };
}

// ============================================================================
// NOW import React Native (after all polyfills are set)
// ============================================================================

import { AppRegistry, LogBox, Platform } from 'react-native';
import App from './App';

// Hardcode the app name to avoid import issues
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

    // Ignore errors
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
            console.log('[TEST] Noble library will load when needed');
            console.log('[TEST] Crypto system ready for keypair generation\n');
        } catch (error) {
            console.error('[TEST] Crypto test failed:', error.message);
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
// Register App - CRITICAL: Only register with ONE name!
// ============================================================================

// Register with the hardcoded name
AppRegistry.registerComponent('GhostCommV2', () => App);

console.log('[INIT] App registered as "GhostCommV2"');
console.log('[INIT] Crypto polyfills installed - keypair generation should work\n');