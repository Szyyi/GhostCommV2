// mobile/src/ble/index.ts

// ============================================================================
// React Native BLE Implementations
// ============================================================================

export { ReactNativeBLEAdvertiser } from './ReactNativeBLEAdvertiser';
export { ReactNativeBLEScanner } from './ReactNativeBLEScanner';
export { ReactNativeBLEConnectionManager } from './ReactNativeBLEConnectionManager';
export { ReactNativeBLEManager } from './ReactNativeBLEManager';

// ============================================================================
// BLE Manager Factory
// ============================================================================

import { GhostKeyPair, IGhostKeyPair } from '../../core';
import { ReactNativeBLEManager } from './ReactNativeBLEManager';

/**
 * Factory function to create BLE manager with v2.0 architecture
 */
export async function createBLEManager(keyPair?: IGhostKeyPair): Promise<ReactNativeBLEManager> {
    const keys = keyPair || new GhostKeyPair();
    const manager = new ReactNativeBLEManager(keys);
    await manager.initialize();
    return manager;
}

// ============================================================================
// Re-export everything from Core
// ============================================================================

// Re-export all types and classes from core
export * from '../../core';

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Format node ID for display
 */
export function formatNodeId(nodeId: string): string {
    if (nodeId.length <= 8) {
        return nodeId;
    }
    return `${nodeId.substring(0, 6)}...${nodeId.substring(nodeId.length - 4)}`;
}

/**
 * Calculate signal strength category from RSSI
 */
export function getSignalStrength(rssi?: number): 'excellent' | 'good' | 'fair' | 'poor' | 'unknown' {
    if (rssi === undefined) return 'unknown';
    if (rssi >= -50) return 'excellent';
    if (rssi >= -60) return 'good';
    if (rssi >= -70) return 'fair';
    return 'poor';
}

/**
 * Get signal bars visualization
 */
export function getSignalBars(rssi?: number): string {
    const strength = getSignalStrength(rssi);
    switch (strength) {
        case 'excellent': return '████';
        case 'good': return '███░';
        case 'fair': return '██░░';
        case 'poor': return '█░░░';
        default: return '░░░░';
    }
}

/**
 * Format timestamp for display
 */
export function formatTimestamp(timestamp: number): string {
    const date = new Date(timestamp);
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const seconds = date.getSeconds().toString().padStart(2, '0');
    return `${hours}:${minutes}:${seconds}`;
}

/**
 * Calculate message age
 */
export function getMessageAge(timestamp: number): string {
    const age = Date.now() - timestamp;
    if (age < 1000) return 'now';
    if (age < 60000) return `${Math.floor(age / 1000)}s`;
    if (age < 3600000) return `${Math.floor(age / 60000)}m`;
    if (age < 86400000) return `${Math.floor(age / 3600000)}h`;
    return `${Math.floor(age / 86400000)}d`;
}

// ============================================================================
// Debug Utilities
// ============================================================================

import { Platform } from 'react-native';

/**
 * Check if running in development mode
 */
export function isDevelopment(): boolean {
    return __DEV__ || false;
}

/**
 * Debug log with v2.0 context
 */
export function debugLog(component: string, message: string, data?: any): void {
    if (isDevelopment()) {
        console.log(`[GhostComm v2.0][${component}] ${message}`, data || '');
    }
}