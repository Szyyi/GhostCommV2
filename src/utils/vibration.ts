// mobile/src/utils/vibration.ts
import { Vibration, Platform } from 'react-native';

/**
 * Safe vibration utility that handles permissions and platform differences
 */
export const safeVibrate = (duration: number = 50) => {
    try {
        // Only vibrate on actual devices, not web
        if (Platform.OS === 'ios' || Platform.OS === 'android') {
            Vibration.vibrate(duration);
        }
    } catch (error) {
        // Silently fail if vibration is not available
        console.log('Vibration not available:', error);
    }
};

/**
 * Vibration patterns for different feedback types
 */
export const vibrationPatterns = {
    // Single short tap
    tap: () => safeVibrate(50),

    // Success feedback
    success: () => {
        if (Platform.OS === 'android') {
            try {
                Vibration.vibrate([0, 50, 100, 50]);
            } catch {
                safeVibrate(50);
            }
        } else {
            safeVibrate(50);
        }
    },

    // Error feedback
    error: () => {
        if (Platform.OS === 'android') {
            try {
                Vibration.vibrate([0, 100, 50, 100]);
            } catch {
                safeVibrate(100);
            }
        } else {
            safeVibrate(100);
        }
    },

    // Warning feedback
    warning: () => {
        if (Platform.OS === 'android') {
            try {
                Vibration.vibrate([0, 75, 75, 75]);
            } catch {
                safeVibrate(75);
            }
        } else {
            safeVibrate(75);
        }
    },

    // Selection feedback
    select: () => safeVibrate(30),

    // Heavy impact
    impact: () => safeVibrate(100),
};

export default {
    vibrate: safeVibrate,
    patterns: vibrationPatterns,
};