// mobile/src/context/ThemeContext.tsx
import React, { createContext, useContext, useState, useEffect } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';

export interface Theme {
    name: string;
    primary: string;      // Main color (was green #00FF00)
    background: string;   // Terminal background
    surface: string;      // UI panels background
    text: string;         // Primary text
    textSecondary: string; // Secondary/dimmed text
    error: string;        // Error messages
    warning: string;      // Warning messages
    border: string;       // Borders
}

// Predefined themes
export const themes: { [key: string]: Theme } = {
    classic: {
        name: 'Classic Green',
        primary: '#00FF00',
        background: '#000000',
        surface: '#0A0A0A',
        text: '#00FF00',
        textSecondary: '#666666',
        error: '#FF3333',
        warning: '#FFAA00',
        border: '#1a1a1a',
    },
    arctic: {
        name: 'Arctic Blue',
        primary: '#00FFFF',
        background: '#000511',
        surface: '#001122',
        text: '#00FFFF',
        textSecondary: '#5588AA',
        error: '#FF6B6B',
        warning: '#FFD93D',
        border: '#003366',
    },
    amber: {
        name: 'Amber',
        primary: '#FFA500',
        background: '#0A0500',
        surface: '#1A0F00',
        text: '#FFA500',
        textSecondary: '#806030',
        error: '#FF4444',
        warning: '#FFFF00',
        border: '#332200',
    },
    matrix: {
        name: 'Matrix',
        primary: '#00FF41',
        background: '#0D0208',
        surface: '#1A0D11',
        text: '#00FF41',
        textSecondary: '#008F11',
        error: '#FF0000',
        warning: '#FFD300',
        border: '#003B00',
    },
    daylight: {
        name: 'Daylight',
        primary: '#000000',
        background: '#FFFFFF',
        surface: '#F5F5F5',
        text: '#000000',
        textSecondary: '#666666',
        error: '#CC0000',
        warning: '#FF8800',
        border: '#DDDDDD',
    },
    highContrast: {
        name: 'High Contrast',
        primary: '#FFFFFF',
        background: '#000000',
        surface: '#111111',
        text: '#FFFFFF',
        textSecondary: '#AAAAAA',
        error: '#FF0000',
        warning: '#FFFF00',
        border: '#FFFFFF',
    },
    ocean: {
        name: 'Ocean',
        primary: '#4A9EFF',
        background: '#001020',
        surface: '#002040',
        text: '#4A9EFF',
        textSecondary: '#6080A0',
        error: '#FF6B6B',
        warning: '#FFB84D',
        border: '#003060',
    },
    sunset: {
        name: 'Sunset',
        primary: '#FF6B35',
        background: '#1A0A05',
        surface: '#2A1510',
        text: '#FF6B35',
        textSecondary: '#AA6040',
        error: '#FF0040',
        warning: '#FFD700',
        border: '#552211',
    },
    custom: {
        name: 'Custom',
        primary: '#00FF00',
        background: '#000000',
        surface: '#0A0A0A',
        text: '#00FF00',
        textSecondary: '#666666',
        error: '#FF3333',
        warning: '#FFAA00',
        border: '#1a1a1a',
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
    const [themeName, setThemeName] = useState<string>('classic');
    const [currentTheme, setCurrentTheme] = useState<Theme>(themes.classic);
    const [customColor, setCustomColorState] = useState<string>('#00FF00');

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
                            textSecondary: savedCustomColor + '99', // Add transparency
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
                    textSecondary: customColor + '99',
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
                textSecondary: color + '99',
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