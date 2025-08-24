// mobile/src/utils/debug.ts
import { Platform } from 'react-native';

export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS' | 'SYSTEM' | 'CRYPTO' | 'BLE' | 'MESH';

interface LogEntry {
    timestamp: Date;
    level: LogLevel;
    category?: string;
    message: string;
    data?: any;
    stackTrace?: string;
}

interface DebugConfig {
    enabled: boolean;
    minLevel: LogLevel;
    maxLogs: number;
    showTimestamp: boolean;
    showMilliseconds: boolean;
    useColors: boolean;
    useEmojis: boolean;
    persistLogs: boolean;
    remoteLogging: boolean;
}

export class DebugLogger {
    private static instance: DebugLogger;
    private config: DebugConfig;
    private logs: LogEntry[] = [];
    private startTime: number = Date.now();

    // Terminal color codes for Metro bundler
    private colors = {
        reset: '\x1b[0m',
        bright: '\x1b[1m',
        dim: '\x1b[2m',

        // Foreground colors
        black: '\x1b[30m',
        red: '\x1b[31m',
        green: '\x1b[32m',
        yellow: '\x1b[33m',
        blue: '\x1b[34m',
        magenta: '\x1b[35m',
        cyan: '\x1b[36m',
        white: '\x1b[37m',

        // Background colors
        bgBlack: '\x1b[40m',
        bgRed: '\x1b[41m',
        bgGreen: '\x1b[42m',
        bgYellow: '\x1b[43m',
    };

    // Level-specific configurations
    private levelConfig: Record<LogLevel, {
        color: string;
        emoji: string;
        priority: number;
        consoleMethod: 'log' | 'info' | 'warn' | 'error';
    }> = {
            DEBUG: {
                color: this.colors.dim,
                emoji: '🔍',
                priority: 0,
                consoleMethod: 'log'
            },
            INFO: {
                color: this.colors.cyan,
                emoji: 'ℹ️',
                priority: 1,
                consoleMethod: 'info'
            },
            WARN: {
                color: this.colors.yellow,
                emoji: '⚠️',
                priority: 2,
                consoleMethod: 'warn'
            },
            ERROR: {
                color: this.colors.red,
                emoji: '❌',
                priority: 3,
                consoleMethod: 'error'
            },
            SUCCESS: {
                color: this.colors.green,
                emoji: '✅',
                priority: 1,
                consoleMethod: 'log'
            },
            SYSTEM: {
                color: this.colors.magenta,
                emoji: '⚙️',
                priority: 1,
                consoleMethod: 'log'
            },
            CRYPTO: {
                color: this.colors.blue,
                emoji: '🔐',
                priority: 1,
                consoleMethod: 'log'
            },
            BLE: {
                color: this.colors.cyan,
                emoji: '📡',
                priority: 1,
                consoleMethod: 'log'
            },
            MESH: {
                color: this.colors.magenta,
                emoji: '🌐',
                priority: 1,
                consoleMethod: 'log'
            }
        };

    private constructor() {
        this.config = {
            enabled: __DEV__,
            minLevel: 'DEBUG',
            maxLogs: 1000,
            showTimestamp: true,
            showMilliseconds: true,
            useColors: true,
            useEmojis: true,
            persistLogs: true,
            remoteLogging: false
        };

        // Terminal-style initialization message
        if (this.config.enabled) {
            this.printBanner();
        }
    }

    static getInstance(): DebugLogger {
        if (!DebugLogger.instance) {
            DebugLogger.instance = new DebugLogger();
        }
        return DebugLogger.instance;
    }

    private printBanner(): void {
        const banner = `
╔════════════════════════════════════════╗
║     GHOSTCOMM DEBUG CONSOLE v1.0.0     ║
║        Terminal Mode: ACTIVE            ║
║     Encryption: ChaCha20-Poly1305      ║
╚════════════════════════════════════════╝`;

        console.log(this.colors.green + this.colors.bright + banner + this.colors.reset);
    }

    private formatTimestamp(): string {
        const now = new Date();
        const elapsed = Date.now() - this.startTime;
        const hours = now.getHours().toString().padStart(2, '0');
        const minutes = now.getMinutes().toString().padStart(2, '0');
        const seconds = now.getSeconds().toString().padStart(2, '0');

        let timestamp = `${hours}:${minutes}:${seconds}`;

        if (this.config.showMilliseconds) {
            const ms = now.getMilliseconds().toString().padStart(3, '0');
            timestamp += `.${ms}`;
        }

        // Add elapsed time
        const elapsedSec = Math.floor(elapsed / 1000);
        const elapsedMin = Math.floor(elapsedSec / 60);
        const elapsedDisplay = elapsedMin > 0
            ? `+${elapsedMin}m${(elapsedSec % 60)}s`
            : `+${elapsedSec}s`;

        return `${timestamp} ${elapsedDisplay}`;
    }

    private formatMessage(
        level: LogLevel,
        message: string,
        category?: string,
        data?: any
    ): string {
        const levelCfg = this.levelConfig[level];
        const parts: string[] = [];

        // Add emoji if enabled
        if (this.config.useEmojis) {
            parts.push(levelCfg.emoji);
        }

        // Add timestamp
        if (this.config.showTimestamp) {
            const timestamp = this.formatTimestamp();
            parts.push(`[${timestamp}]`);
        }

        // Add level
        parts.push(`[${level}]`);

        // Add category if provided
        if (category) {
            parts.push(`[${category}]`);
        }

        // Add message
        parts.push(message);

        // Format the complete message
        let formatted = parts.join(' ');

        // Add color if enabled
        if (this.config.useColors) {
            formatted = levelCfg.color + formatted + this.colors.reset;
        }

        // Add data if provided
        if (data !== undefined && data !== null) {
            let dataStr: string;

            try {
                if (data instanceof Error) {
                    dataStr = `\n  Error: ${data.message}\n  Stack: ${data.stack}`;
                } else if (typeof data === 'object') {
                    dataStr = '\n' + JSON.stringify(data, null, 2)
                        .split('\n')
                        .map(line => '  ' + line)
                        .join('\n');
                } else {
                    dataStr = '\n  ' + String(data);
                }

                if (this.config.useColors) {
                    dataStr = this.colors.dim + dataStr + this.colors.reset;
                }

                formatted += dataStr;
            } catch (e) {
                formatted += '\n  [Unserializable data]';
            }
        }

        return formatted;
    }

    private log(
        level: LogLevel,
        message: string,
        category?: string,
        data?: any
    ): void {
        // Check if logging is enabled
        if (!this.config.enabled) return;

        // Check minimum level
        const levelPriority = this.levelConfig[level].priority;
        const minPriority = this.levelConfig[this.config.minLevel].priority;
        if (levelPriority < minPriority) return;

        // Create log entry
        const entry: LogEntry = {
            timestamp: new Date(),
            level,
            category,
            message,
            data,
            stackTrace: level === 'ERROR' ? new Error().stack : undefined
        };

        // Store log if persistence is enabled
        if (this.config.persistLogs) {
            this.logs.push(entry);

            // Trim logs if exceeding max
            if (this.logs.length > this.config.maxLogs) {
                this.logs = this.logs.slice(-this.config.maxLogs);
            }
        }

        // Format and output message
        const formatted = this.formatMessage(level, message, category, data);
        const consoleMethod = this.levelConfig[level].consoleMethod;
        console[consoleMethod](formatted);

        // Platform-specific logging
        if (Platform.OS === 'android' && level === 'ERROR') {
            // Can be viewed with: adb logcat -s GhostComm
            console.log(`GhostComm:${level}: ${message}`);
        }

        // Remote logging (if enabled and configured)
        if (this.config.remoteLogging && level === 'ERROR') {
            this.sendToRemote(entry);
        }
    }

    private sendToRemote(entry: LogEntry): void {
        // Placeholder for remote logging
        // Could send to a crash reporting service
    }

    // Public logging methods
    public debug(message: string, data?: any): void {
        this.log('DEBUG', message, undefined, data);
    }

    public info(message: string, data?: any): void {
        this.log('INFO', message, undefined, data);
    }

    public warn(message: string, data?: any): void {
        this.log('WARN', message, undefined, data);
    }

    public error(message: string, error?: any): void {
        this.log('ERROR', message, undefined, error);
    }

    public success(message: string, data?: any): void {
        this.log('SUCCESS', message, undefined, data);
    }

    // Specialized logging methods for GhostComm
    public system(message: string, data?: any): void {
        this.log('SYSTEM', message, undefined, data);
    }

    public crypto(message: string, data?: any): void {
        this.log('CRYPTO', message, undefined, data);
    }

    public ble(message: string, data?: any): void {
        this.log('BLE', message, undefined, data);
    }

    public mesh(message: string, data?: any): void {
        this.log('MESH', message, undefined, data);
    }

    // Group logging
    public group(label: string): void {
        if (!this.config.enabled) return;
        console.group(this.colors.bright + `▼ ${label}` + this.colors.reset);
    }

    public groupEnd(): void {
        if (!this.config.enabled) return;
        console.groupEnd();
    }

    // Table logging
    public table(data: any, columns?: string[]): void {
        if (!this.config.enabled) return;
        console.table(data, columns);
    }

    // Timing utilities
    private timers: Map<string, number> = new Map();

    public time(label: string): void {
        if (!this.config.enabled) return;
        this.timers.set(label, Date.now());
        this.debug(`Timer started: ${label}`);
    }

    public timeEnd(label: string): void {
        if (!this.config.enabled) return;
        const start = this.timers.get(label);
        if (!start) {
            this.warn(`Timer not found: ${label}`);
            return;
        }
        const duration = Date.now() - start;
        this.timers.delete(label);
        this.info(`Timer ${label}: ${duration}ms`);
    }

    // Assertion
    public assert(condition: boolean, message: string): void {
        if (!condition) {
            this.error(`Assertion failed: ${message}`);
        }
    }

    // Configuration methods
    public setEnabled(enabled: boolean): void {
        this.config.enabled = enabled;
    }

    public setMinLevel(level: LogLevel): void {
        this.config.minLevel = level;
    }

    public setUseColors(useColors: boolean): void {
        this.config.useColors = useColors;
    }

    public setUseEmojis(useEmojis: boolean): void {
        this.config.useEmojis = useEmojis;
    }

    // Log management
    public getLogs(): LogEntry[] {
        return [...this.logs];
    }

    public clearLogs(): void {
        this.logs = [];
        this.success('Logs cleared');
    }

    public exportLogs(): string {
        return this.logs.map(log => {
            const timestamp = log.timestamp.toISOString();
            const data = log.data ? ` | ${JSON.stringify(log.data)}` : '';
            return `[${timestamp}] [${log.level}] ${log.message}${data}`;
        }).join('\n');
    }

    // Terminal-style output for special messages
    public box(title: string, content: string): void {
        if (!this.config.enabled) return;

        const lines = content.split('\n');
        const maxLength = Math.max(title.length, ...lines.map(l => l.length)) + 4;

        const top = '╔' + '═'.repeat(maxLength) + '╗';
        const titleLine = `║ ${title.padEnd(maxLength - 2)} ║`;
        const separator = '╟' + '─'.repeat(maxLength) + '╢';
        const bottom = '╚' + '═'.repeat(maxLength) + '╝';

        const contentLines = lines.map(line =>
            `║ ${line.padEnd(maxLength - 2)} ║`
        );

        const box = [top, titleLine, separator, ...contentLines, bottom].join('\n');

        console.log(this.colors.green + box + this.colors.reset);
    }

    // Progress indicator
    private progressBars: Map<string, any> = new Map();

    public progress(label: string, current: number, total: number): void {
        if (!this.config.enabled) return;

        const percent = Math.min(100, Math.round((current / total) * 100));
        const barLength = 20;
        const filled = Math.round((percent / 100) * barLength);
        const empty = barLength - filled;

        const bar = '█'.repeat(filled) + '░'.repeat(empty);
        const message = `${label}: [${bar}] ${percent}% (${current}/${total})`;

        // Use carriage return to update same line
        process.stdout.write('\r' + this.colors.cyan + message + this.colors.reset);

        if (current >= total) {
            console.log(''); // New line when complete
        }
    }
}

// Singleton instance
export const debug = DebugLogger.getInstance();

// BLE-specific debug helpers with enhanced formatting
export const debugBLE = {
    scan: (event: string, data?: any) => {
        debug.ble(`SCAN: ${event}`, data);
    },

    connection: (event: string, deviceId?: string, data?: any) => {
        const id = deviceId ? ` [${deviceId.substring(0, 8)}...]` : '';
        debug.ble(`CONNECTION: ${event}${id}`, data);
    },

    message: (event: string, messageId?: string, data?: any) => {
        const id = messageId ? ` [${messageId.substring(0, 8)}...]` : '';
        debug.ble(`MESSAGE: ${event}${id}`, data);
    },

    advertisement: (event: string, data?: any) => {
        debug.ble(`ADVERTISE: ${event}`, data);
    },

    discovery: (nodeId: string, rssi: number) => {
        const signal = rssi >= -50 ? '████' :
            rssi >= -60 ? '███░' :
                rssi >= -70 ? '██░░' :
                    rssi >= -80 ? '█░░░' : '░░░░';
        debug.ble(`DISCOVERED: ${nodeId} [${signal}] ${rssi}dBm`);
    },

    error: (operation: string, error: any) => {
        debug.error(`BLE:${operation} failed`, error);
    }
};

// Crypto-specific debug helpers
export const debugCrypto = {
    keyGeneration: (fingerprint: string) => {
        debug.crypto(`Keypair generated: ${fingerprint}`);
    },

    encryption: (messageId: string, recipientId?: string) => {
        const recipient = recipientId ? ` for ${recipientId.substring(0, 8)}...` : '';
        debug.crypto(`Message encrypted: ${messageId}${recipient}`);
    },

    decryption: (messageId: string, senderId?: string) => {
        const sender = senderId ? ` from ${senderId.substring(0, 8)}...` : '';
        debug.crypto(`Message decrypted: ${messageId}${sender}`);
    },

    error: (operation: string, error: any) => {
        debug.error(`CRYPTO:${operation} failed`, error);
    }
};

// Mesh network debug helpers
export const debugMesh = {
    route: (from: string, to: string, hops: number) => {
        debug.mesh(`Route: ${from} → ${to} (${hops} hops)`);
    },

    relay: (messageId: string, fromNode: string, toNode: string) => {
        debug.mesh(`Relaying: ${messageId} | ${fromNode} → ${toNode}`);
    },

    topology: (nodes: number, connections: number) => {
        debug.mesh(`Topology: ${nodes} nodes, ${connections} connections`);
    },

    error: (operation: string, error: any) => {
        debug.error(`MESH:${operation} failed`, error);
    }
};

// Performance monitoring
export const debugPerf = {
    start: (operation: string) => {
        debug.time(operation);
    },

    end: (operation: string) => {
        debug.timeEnd(operation);
    },

    memory: () => {
        if (
            typeof performance !== 'undefined' &&
            typeof (performance as any).memory !== 'undefined'
        ) {
            const mem = (performance as any).memory;
            debug.system('Memory Usage', {
                used: `${Math.round(mem.usedJSHeapSize / 1048576)}MB`,
                total: `${Math.round(mem.totalJSHeapSize / 1048576)}MB`,
                limit: `${Math.round(mem.jsHeapSizeLimit / 1048576)}MB`
            });
        }
    }
};

// Export types for TypeScript
export type Debug = typeof debug;
export type DebugBLE = typeof debugBLE;
export type DebugCrypto = typeof debugCrypto;
export type DebugMesh = typeof debugMesh;
export type DebugPerf = typeof debugPerf;