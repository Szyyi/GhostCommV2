// mobile/src/utils/blePermissions.ts
import { Platform, PermissionsAndroid } from 'react-native';

/**
 * BLE Permission Helper
 * Handles the complexity of Android BLE permissions across different API levels
 */

// Define Android 12+ Bluetooth permissions as constants
// These might not be in React Native's TypeScript definitions yet
export const ANDROID_12_BLUETOOTH_PERMISSIONS = {
    BLUETOOTH_SCAN: 'android.permission.BLUETOOTH_SCAN',
    BLUETOOTH_CONNECT: 'android.permission.BLUETOOTH_CONNECT',
    BLUETOOTH_ADVERTISE: 'android.permission.BLUETOOTH_ADVERTISE',
} as const;

// Background location permission (Android 10+)
export const BACKGROUND_LOCATION_PERMISSION = 'android.permission.ACCESS_BACKGROUND_LOCATION';

/**
 * Request all necessary BLE permissions for Android
 * @returns Promise<boolean> - true if all critical permissions granted
 */
export async function requestBLEPermissions(): Promise<boolean> {
    // iOS doesn't need runtime permissions for BLE
    if (Platform.OS === 'ios') {
        console.log('📱 iOS: BLE permissions handled via Info.plist');
        return true;
    }

    try {
        const apiLevel = Platform.Version;
        let permissionsToRequest: string[] = [];

        if (typeof apiLevel === 'number' && apiLevel >= 31) {
            // Android 12+ (API 31+)
            console.log('📱 Android 12+: Requesting new Bluetooth permissions');
            permissionsToRequest = [
                ANDROID_12_BLUETOOTH_PERMISSIONS.BLUETOOTH_SCAN,
                ANDROID_12_BLUETOOTH_PERMISSIONS.BLUETOOTH_CONNECT,
                ANDROID_12_BLUETOOTH_PERMISSIONS.BLUETOOTH_ADVERTISE,
                PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
            ];
        } else if (typeof apiLevel === 'number' && apiLevel >= 29) {
            // Android 10-11 (API 29-30)
            console.log('📱 Android 10-11: Requesting location permissions');
            permissionsToRequest = [
                PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
                BACKGROUND_LOCATION_PERMISSION,
            ];
        } else {
            // Android < 10 (API < 29)
            console.log('📱 Android <10: Requesting basic location permissions');
            permissionsToRequest = [
                PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
                PermissionsAndroid.PERMISSIONS.ACCESS_COARSE_LOCATION,
            ];
        }

        if (permissionsToRequest.length === 0) {
            console.log('ℹ️ No permissions to request');
            return true;
        }

        // Request permissions using 'any' type to avoid TypeScript issues
        const results = await PermissionsAndroid.requestMultiple(permissionsToRequest as any);
        
        // Check results
        let allCriticalGranted = true;
        let locationGranted = false;

        for (const permission of permissionsToRequest) {
            const result = results[permission as keyof typeof results];
            const isGranted = result === PermissionsAndroid.RESULTS.GRANTED;
            
            console.log(`  ${permission}: ${isGranted ? '✅' : '❌'} (${result})`);
            
            // Check if this is a location permission
            if (permission.includes('LOCATION')) {
                if (isGranted) {
                    locationGranted = true;
                } else if (permission.includes('BACKGROUND')) {
                    // Background location is not critical
                    console.warn('⚠️ Background location not granted - app will work in foreground only');
                } else {
                    // Foreground location is critical
                    console.error('❌ Location permission is required for BLE');
                    allCriticalGranted = false;
                }
            } else if (!isGranted && typeof apiLevel === 'number' && apiLevel >= 31) {
                // For Android 12+, Bluetooth permissions are critical
                console.error(`❌ Bluetooth permission required: ${permission}`);
                allCriticalGranted = false;
            }
        }

        // For older Android versions, only location is critical
        if (typeof apiLevel === 'number' && apiLevel < 31) {
            return locationGranted;
        }

        return allCriticalGranted;

    } catch (error) {
        console.error('❌ Error requesting BLE permissions:', error);
        // Don't block the app, allow it to continue in demo mode
        return false;
    }
}

/**
 * Check if BLE permissions are already granted
 * @returns Promise<boolean> - true if permissions are granted
 */
export async function checkBLEPermissions(): Promise<boolean> {
    if (Platform.OS === 'ios') {
        return true;
    }

    try {
        const apiLevel = Platform.Version;
        let permissionsToCheck: string[] = [];

        if (typeof apiLevel === 'number' && apiLevel >= 31) {
            permissionsToCheck = [
                ANDROID_12_BLUETOOTH_PERMISSIONS.BLUETOOTH_SCAN,
                ANDROID_12_BLUETOOTH_PERMISSIONS.BLUETOOTH_CONNECT,
                ANDROID_12_BLUETOOTH_PERMISSIONS.BLUETOOTH_ADVERTISE,
                PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
            ];
        } else {
            permissionsToCheck = [
                PermissionsAndroid.PERMISSIONS.ACCESS_FINE_LOCATION,
            ];
        }

        for (const permission of permissionsToCheck) {
            const result = await PermissionsAndroid.check(permission as any);
            if (!result) {
                console.log(`❌ Permission not granted: ${permission}`);
                return false;
            }
        }

        return true;

    } catch (error) {
        console.error('❌ Error checking BLE permissions:', error);
        return false;
    }
}

/**
 * Get human-readable permission status
 */
export function getPermissionStatusText(status: string | undefined): string {
    switch (status) {
        case PermissionsAndroid.RESULTS.GRANTED:
            return 'Granted';
        case PermissionsAndroid.RESULTS.DENIED:
            return 'Denied';
        case PermissionsAndroid.RESULTS.NEVER_ASK_AGAIN:
            return 'Never Ask Again';
        default:
            return 'Unknown';
    }
}