// mobile/src/context/ThemeContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

export interface Theme {
    name: string;
    primary: string;      // Main action color
    background: string;   // Main background
    surface: string;      // Card/panel backgrounds
    text: string;         // Primary text
    textSecondary: string; // Secondary/muted text
    textTertiary: string; // Disabled/very muted text
    error: string;        // Error states
    warning: string;      // Warning states
    success: string;      // Success states
    border: string;       // Border colors
    divider: string;      // Divider lines
    overlay: string;      // Modal overlays
}

// Premium, minimal themes
export const themes: { [key: string]: Theme } = {
    mono: {
        name: 'Monochrome',
        primary: '#000000',
        background: '#FFFFFF',
        surface: '#F8F8F8',
        text: '#000000',
        textSecondary: '#666666',
        textTertiary: '#999999',
        error: '#FF3B30',
        warning: '#FF9500',
        success: '#34C759',
        border: '#E5E5E5',
        divider: '#F0F0F0',
        overlay: 'rgba(0, 0, 0, 0.5)',
    },
    noir: {
        name: 'Noir',
        primary: '#FFFFFF',
        background: '#000000',
        surface: '#0A0A0A',
        text: '#FFFFFF',
        textSecondary: '#999999',
        textTertiary: '#666666',
        error: '#FF453A',
        warning: '#FF9F0A',
        success: '#30D158',
        border: '#1C1C1C',
        divider: '#1A1A1A',
        overlay: 'rgba(255, 255, 255, 0.1)',
    },
    graphite: {
        name: 'Graphite',
        primary: '#000000',
        background: '#F5F5F5',
        surface: '#FFFFFF',
        text: '#1A1A1A',
        textSecondary: '#6C6C6C',
        textTertiary: '#A0A0A0',
        error: '#DC2626',
        warning: '#F59E0B',
        success: '#10B981',
        border: '#D4D4D4',
        divider: '#E5E5E5',
        overlay: 'rgba(0, 0, 0, 0.4)',
    },
    midnight: {
        name: 'Midnight',
        primary: '#4A5FFF',
        background: '#0A0B14',
        surface: '#13141F',
        text: '#FFFFFF',
        textSecondary: '#8B92B9',
        textTertiary: '#5A607A',
        error: '#FF5555',
        warning: '#FFB84D',
        success: '#50FA7B',
        border: '#1F2133',
        divider: '#1A1C2E',
        overlay: 'rgba(0, 0, 0, 0.7)',
    },
    paper: {
        name: 'Paper',
        primary: '#2C2C2C',
        background: '#FAFAF8',
        surface: '#FFFFFF',
        text: '#2C2C2C',
        textSecondary: '#757575',
        textTertiary: '#B0B0B0',
        error: '#D32F2F',
        warning: '#F57C00',
        success: '#388E3C',
        border: '#E0E0E0',
        divider: '#F5F5F5',
        overlay: 'rgba(0, 0, 0, 0.3)',
    },
    ink: {
        name: 'Ink',
        primary: '#1A1A1A',
        background: '#FFFEF9',
        surface: '#FFFFF5',
        text: '#1A1A1A',
        textSecondary: '#606060',
        textTertiary: '#909090',
        error: '#B91C1C',
        warning: '#D97706',
        success: '#15803D',
        border: '#D6D3C7',
        divider: '#EEEBE2',
        overlay: 'rgba(26, 26, 26, 0.4)',
    },
    sage: {
        name: 'Sage',
        primary: '#2F4F3A',
        background: '#FAFBF8',
        surface: '#FFFFFF',
        text: '#1E1E1E',
        textSecondary: '#5F6B5F',
        textTertiary: '#9CA59C',
        error: '#C84B4B',
        warning: '#D4A04A',
        success: '#5B8C5B',
        border: '#DDE2D8',
        divider: '#EFF1EC',
        overlay: 'rgba(47, 79, 58, 0.3)',
    },
    carbon: {
        name: 'Carbon',
        primary: '#E5E5E5',
        background: '#0D0D0D',
        surface: '#1A1A1A',
        text: '#E5E5E5',
        textSecondary: '#A0A0A0',
        textTertiary: '#606060',
        error: '#FF6B6B',
        warning: '#FFC107',
        success: '#4CAF50',
        border: '#2A2A2A',
        divider: '#222222',
        overlay: 'rgba(0, 0, 0, 0.8)',
    },
    minimal: {
        name: 'Minimal',
        primary: '#000000',
        background: '#FFFFFF',
        surface: '#FAFAFA',
        text: '#000000',
        textSecondary: '#737373',
        textTertiary: '#A3A3A3',
        error: '#EF4444',
        warning: '#F59E0B',
        success: '#10B981',
        border: '#E5E5E5',
        divider: '#F5F5F5',
        overlay: 'rgba(0, 0, 0, 0.5)',
    },
    classic: {
        name: 'Classic Terminal',
        primary: '#00FF00',
        background: '#000000',
        surface: '#0A0A0A',
        text: '#00FF00',
        textSecondary: '#00AA00',
        textTertiary: '#006600',
        error: '#FF3333',
        warning: '#FFAA00',
        success: '#00FF00',
        border: '#003300',
        divider: '#001100',
        overlay: 'rgba(0, 255, 0, 0.1)',
    },
    custom: {
        name: 'Custom',
        primary: '#000000',
        background: '#FFFFFF',
        surface: '#F8F8F8',
        text: '#000000',
        textSecondary: '#666666',
        textTertiary: '#999999',
        error: '#FF3B30',
        warning: '#FF9500',
        success: '#34C759',
        border: '#E5E5E5',
        divider: '#F0F0F0',
        overlay: 'rgba(0, 0, 0, 0.5)',
    }
};

interface ThemeContextType {
    currentTheme: Theme;
    themeName: string;
    setTheme: (themeName: string) => void;
    setCustomColor: (color: string) => void;
    availableThemes: typeof themes;
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

export const useTheme = () => {
    const context = useContext(ThemeContext);
    if (!context) {
        throw new Error('useTheme must be used within ThemeProvider');
    }
    return context;
};

export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
    const [themeName, setThemeName] = useState<string>('mono');
    const [currentTheme, setCurrentTheme] = useState<Theme>(themes.mono);
    const [customColor, setCustomColorState] = useState<string>('#000000');

    // Load saved theme on mount
    useEffect(() => {
        const loadTheme = async () => {
            try {
                const savedTheme = await AsyncStorage.getItem('@ghostcomm_theme');
                const savedCustomColor = await AsyncStorage.getItem('@ghostcomm_custom_color');

                if (savedCustomColor) {
                    setCustomColorState(savedCustomColor);
                }

                if (savedTheme && themes[savedTheme]) {
                    setThemeName(savedTheme);

                    if (savedTheme === 'custom' && savedCustomColor) {
                        // Apply custom color to the custom theme
                        const customTheme = {
                            ...themes.custom,
                            primary: savedCustomColor,
                            text: savedCustomColor,
                            // Calculate secondary colors based on primary
                            textSecondary: adjustColorOpacity(savedCustomColor, 0.7),
                            textTertiary: adjustColorOpacity(savedCustomColor, 0.5),
                            border: adjustColorOpacity(savedCustomColor, 0.2),
                            divider: adjustColorOpacity(savedCustomColor, 0.1),
                        };
                        setCurrentTheme(customTheme);
                    } else {
                        setCurrentTheme(themes[savedTheme]);
                    }
                }
            } catch (error) {
                console.error('Failed to load theme:', error);
            }
        };

        loadTheme();
    }, []);

    const setTheme = async (newThemeName: string) => {
        try {
            setThemeName(newThemeName);

            if (newThemeName === 'custom') {
                const customTheme = {
                    ...themes.custom,
                    primary: customColor,
                    text: customColor,
                    textSecondary: adjustColorOpacity(customColor, 0.7),
                    textTertiary: adjustColorOpacity(customColor, 0.5),
                    border: adjustColorOpacity(customColor, 0.2),
                    divider: adjustColorOpacity(customColor, 0.1),
                };
                setCurrentTheme(customTheme);
            } else {
                setCurrentTheme(themes[newThemeName]);
            }

            await AsyncStorage.setItem('@ghostcomm_theme', newThemeName);
        } catch (error) {
            console.error('Failed to save theme:', error);
        }
    };

    const setCustomColor = async (color: string) => {
        try {
            setCustomColorState(color);

            // Update custom theme with new color
            const customTheme = {
                ...themes.custom,
                primary: color,
                text: color,
                textSecondary: adjustColorOpacity(color, 0.7),
                textTertiary: adjustColorOpacity(color, 0.5),
                border: adjustColorOpacity(color, 0.2),
                divider: adjustColorOpacity(color, 0.1),
            };

            // If currently using custom theme, apply immediately
            if (themeName === 'custom') {
                setCurrentTheme(customTheme);
            }

            await AsyncStorage.setItem('@ghostcomm_custom_color', color);
        } catch (error) {
            console.error('Failed to save custom color:', error);
        }
    };

    const value: ThemeContextType = {
        currentTheme,
        themeName,
        setTheme,
        setCustomColor,
        availableThemes: themes,
    };

    return (
        <ThemeContext.Provider value={value}>
            {children}
        </ThemeContext.Provider>
    );
};

// Helper function to adjust color opacity
function adjustColorOpacity(color: string, opacity: number): string {
    // If it's already an rgba/rgb color, parse and adjust
    if (color.startsWith('rgb')) {
        return color.replace(/[\d.]+\)$/g, `${opacity})`);
    }
    
    // Convert hex to rgba
    const hex = color.replace('#', '');
    const r = parseInt(hex.substring(0, 2), 16);
    const g = parseInt(hex.substring(2, 4), 16);
    const b = parseInt(hex.substring(4, 6), 16);
    
    return `rgba(${r}, ${g}, ${b}, ${opacity})`;
}