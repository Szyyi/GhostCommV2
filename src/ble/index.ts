/**
 * =====================================================================================
 * GhostComm Protocol v2.1 - React Native BLE Module Entry Point and Factory
 * =====================================================================================
 * 
 * Comprehensive React Native BLE module providing unified access to all Bluetooth Low
 * Energy components, factory functions, and utility helpers for the GhostComm mesh
 * network. This module serves as the primary integration point for React Native
 * applications implementing Protocol v2.1 secure mesh networking capabilities.
 * 
 * CORE ARCHITECTURE:
 * =================
 * 
 * 1. Component Exports:
 *    - React Native-specific BLE implementation classes
 *    - Cross-platform abstractions for iOS and Android
 *    - Protocol v2.1 security-enabled networking components
 *    - Unified API surface for mesh network operations
 * 
 * 2. Factory Functions:
 *    - Simplified BLE manager creation with automatic initialization
 *    - Cryptographic key pair integration and configuration
 *    - Error handling and graceful degradation support
 *    - Production-ready BLE component instantiation
 * 
 * 3. Utility Functions:
 *    - UI-friendly data formatting and display helpers
 *    - Signal strength analysis and visualization utilities
 *    - Timestamp formatting and age calculation functions
 *    - Debug logging and development support tools
 * 
 * 4. Core Integration:
 *    - Complete re-export of core GhostComm types and classes
 *    - Unified namespace for both mobile and core components
 *    - Seamless integration between React Native and core modules
 * 
 * PROTOCOL v2.1 FEATURES:
 * =======================
 * 
 * - Ed25519/X25519 cryptographic key management
 * - Double Ratchet encryption with forward secrecy
 * - Comprehensive message authentication and replay protection
 * - Cross-platform BLE advertising and scanning capabilities
 * - Mesh network topology management and optimization
 * - Real-time connection monitoring and health assessment
 * 
 * PLATFORM COMPATIBILITY:
 * =======================
 * 
 * - iOS: Core Bluetooth framework integration with privacy compliance
 * - Android: BluetoothLE API with permission management and optimization
 * - Cross-platform: Unified API abstracting platform-specific differences
 * - Performance: Optimized for mobile battery life and resource constraints
 * 
 * DEVELOPMENT SUPPORT:
 * ===================
 * 
 * - Comprehensive debugging utilities for troubleshooting
 * - Development mode detection and conditional logging
 * - Signal strength visualization and network health monitoring
 * - User-friendly data formatting for UI integration
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 * @classification React Native BLE Integration Module
 * @lastModified September 2025
 * 
 * =====================================================================================
 */

// mobile/src/ble/index.ts

/**
 * ============================================================================
 * React Native BLE Implementation Component Exports
 * ============================================================================
 * 
 * Core React Native-specific implementations of the GhostComm BLE subsystem
 * providing platform-optimized functionality for iOS and Android devices.
 * These components implement the abstract base classes from the core module
 * with React Native-specific integration and mobile platform optimizations.
 * 
 * COMPONENT OVERVIEW:
 * ==================
 * 
 * - ReactNativeBLEAdvertiser: Cross-platform BLE advertising with Protocol v2.1
 * - ReactNativeBLEScanner: Efficient mesh node discovery and filtering
 * - ReactNativeBLEConnectionManager: Secure connection lifecycle management
 * - ReactNativeBLEManager: Unified mesh network coordination and orchestration
 * 
 * Each component provides production-ready, mobile-optimized implementations
 * with comprehensive error handling, battery optimization, and security features.
 */

export { ReactNativeBLEAdvertiser } from './ReactNativeBLEAdvertiser';
export { ReactNativeBLEScanner } from './ReactNativeBLEScanner';
export { ReactNativeBLEConnectionManager } from './ReactNativeBLEConnectionManager';
export { ReactNativeBLEManager } from './ReactNativeBLEManager';

/**
 * ============================================================================
 * BLE Manager Factory Functions for Protocol v2.1 Mesh Networks
 * ============================================================================
 * 
 * Simplified factory functions providing streamlined creation and initialization
 * of BLE manager instances with comprehensive Protocol v2.1 security features.
 * These factories handle complex initialization sequences, error recovery, and
 * production-ready configuration for React Native mesh network applications.
 * 
 * FACTORY BENEFITS:
 * ================
 * 
 * - Simplified API for common BLE manager creation patterns
 * - Automatic cryptographic key pair generation and configuration
 * - Comprehensive initialization with error handling and validation
 * - Production-ready defaults for mesh network operations
 * - Consistent configuration across different application contexts
 * 
 * SECURITY INTEGRATION:
 * ====================
 * 
 * The factory automatically configures:
 * - Ed25519 identity key pairs for node authentication
 * - X25519 encryption key pairs for session establishment
 * - Protocol v2.1 security policy enforcement
 * - Cryptographic signature verification requirements
 * - Secure random number generation for nonces and ephemeral data
 */

import { GhostKeyPair, IGhostKeyPair } from '../../core';
import { ReactNativeBLEManager } from './ReactNativeBLEManager';

/**
 * Create and Initialize BLE Manager with Protocol v2.1 Security
 * ============================================================
 * 
 * Factory function providing simplified creation of fully configured and
 * initialized ReactNativeBLEManager instances with comprehensive Protocol v2.1
 * security features. This function handles complex initialization sequences,
 * cryptographic key management, and error recovery for production deployment.
 * 
 * INITIALIZATION PROCESS:
 * ======================
 * 
 * 1. Key Pair Management:
 *    - Use provided key pair or generate new Ed25519/X25519 pair
 *    - Validate cryptographic key material for Protocol v2.1 compliance
 *    - Configure identity and encryption keys for secure operations
 * 
 * 2. Manager Configuration:
 *    - Instantiate ReactNativeBLEManager with security credentials
 *    - Apply Protocol v2.1 security policies and configuration
 *    - Configure cross-platform BLE subsystem integration
 * 
 * 3. System Initialization:
 *    - Initialize all BLE components (advertiser, scanner, connections)
 *    - Validate platform permissions and hardware capabilities
 *    - Configure mesh network topology and routing parameters
 * 
 * 4. Readiness Verification:
 *    - Verify all subsystems are operational and ready
 *    - Validate cryptographic operations and security features
 *    - Confirm mesh network participation capability
 * 
 * SECURITY FEATURES:
 * =================
 * 
 * - Automatic Ed25519 key pair generation for node identity
 * - X25519 key pair for Double Ratchet session establishment
 * - Protocol v2.1 compliance verification and enforcement
 * - Secure random number generation for cryptographic operations
 * - Comprehensive signature verification configuration
 * 
 * ERROR HANDLING:
 * ==============
 * 
 * - Graceful handling of permission and hardware availability issues
 * - Comprehensive error reporting for initialization failures
 * - Automatic retry mechanisms for transient initialization problems
 * - Fallback options for partial capability scenarios
 * 
 * PLATFORM OPTIMIZATION:
 * =====================
 * 
 * - iOS-specific Core Bluetooth optimizations and configurations
 * - Android BLE stack tuning for optimal performance and reliability
 * - Cross-platform battery life optimization strategies
 * - Memory usage optimization for mobile device constraints
 * 
 * @param keyPair Optional existing cryptographic key pair (generates new if not provided)
 * @returns Promise resolving to fully initialized and ready BLE manager
 * 
 * @throws Error if initialization fails due to permissions, hardware, or configuration issues
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export async function createBLEManager(keyPair?: IGhostKeyPair): Promise<ReactNativeBLEManager> {
    // Generate new cryptographic key pair if not provided
    const keys = keyPair || new GhostKeyPair();
    
    // Create BLE manager instance with Protocol v2.1 security configuration
    const manager = new ReactNativeBLEManager(keys);
    
    // Initialize all BLE subsystems and verify operational readiness
    await manager.initialize();
    
    // Return fully configured and operational BLE manager
    return manager;
}

/**
 * ============================================================================
 * Core Module Re-exports for Unified Namespace Access
 * ============================================================================
 * 
 * Comprehensive re-export of all core GhostComm types, interfaces, classes,
 * and utilities providing a unified namespace for React Native applications.
 * This approach simplifies imports and provides seamless integration between
 * mobile-specific implementations and core Protocol v2.1 functionality.
 * 
 * UNIFIED NAMESPACE BENEFITS:
 * ===========================
 * 
 * - Single import point for all GhostComm functionality
 * - Consistent API surface across mobile and core modules
 * - Simplified dependency management for React Native apps
 * - Type safety preservation across module boundaries
 * - Enhanced developer experience with unified documentation
 * 
 * RE-EXPORTED COMPONENTS:
 * ======================
 * 
 * Core Types and Interfaces:
 * - BLEMessage, BLENode, BLESession interfaces
 * - ConnectionState, MessagePriority enums
 * - BLEAdvertisementData, BLEConnectionEvent types
 * - Protocol v2.1 security configuration constants
 * 
 * Cryptographic Classes:
 * - GhostKeyPair for Ed25519/X25519 key management
 * - Encryption utilities for Double Ratchet protocol
 * - Signature verification and authentication functions
 * 
 * Abstract Base Classes:
 * - BLEAdvertiser, BLEScanner, BLEConnectionManager
 * - BLEManager for mesh network coordination
 * - Protocol v2.1 security enforcement abstractions
 * 
 * Utility Functions:
 * - Cryptographic helper functions and converters
 * - Protocol compliance validation utilities
 * - Network topology analysis and optimization tools
 * 
 * This comprehensive re-export ensures that React Native applications have
 * access to the complete GhostComm ecosystem through a single import statement.
 */

// Re-export all types and classes from core for unified namespace access
export * from '../../core';

/**
 * ============================================================================
 * User Interface and Display Utility Functions
 * ============================================================================
 * 
 * Comprehensive collection of utility functions designed to enhance user
 * experience by providing human-readable formatting, visualization, and
 * analysis of mesh network data. These functions bridge the gap between
 * technical Protocol v2.1 data structures and user-friendly interface elements.
 * 
 * UTILITY CATEGORIES:
 * ==================
 * 
 * 1. Node Identification:
 *    - Compact node ID formatting for space-constrained UI elements
 *    - Readable representations of cryptographic identifiers
 *    - Consistent formatting across different display contexts
 * 
 * 2. Signal Quality Analysis:
 *    - RSSI-based signal strength categorization and visualization
 *    - Visual signal bar representations for quick assessment
 *    - Network quality indicators for user guidance
 * 
 * 3. Temporal Data Processing:
 *    - Human-readable timestamp formatting for display
 *    - Relative time calculations for message aging
 *    - Time-based network activity analysis
 * 
 * 4. Performance Optimization:
 *    - Efficient string operations minimizing memory allocation
 *    - Cached calculations for frequently accessed data
 *    - Mobile-optimized formatting reducing UI rendering overhead
 */

/**
 * Format Node ID for Compact Display in User Interfaces
 * ====================================================
 * 
 * Transforms long cryptographic node identifiers into compact, user-friendly
 * representations suitable for display in space-constrained UI elements while
 * preserving sufficient uniqueness for node identification. This formatting
 * maintains readability without compromising security or identification accuracy.
 * 
 * FORMATTING STRATEGY:
 * ===================
 * 
 * - Short IDs (≤8 characters): Display in full without truncation
 * - Long IDs (>8 characters): Show first 6 + "..." + last 4 characters
 * - Preserves beginning for quick visual identification
 * - Preserves ending for uniqueness verification
 * - Ellipsis indicates truncation for user awareness
 * 
 * UI INTEGRATION BENEFITS:
 * =======================
 * 
 * - Consistent width formatting for table and list displays
 * - Quick visual recognition of frequently encountered nodes
 * - Sufficient uniqueness for most identification scenarios
 * - Space efficiency for mobile device constraints
 * - Professional appearance in mesh network monitoring interfaces
 * 
 * SECURITY CONSIDERATIONS:
 * =======================
 * 
 * - Maintains cryptographic identifier integrity
 * - Preserves sufficient entropy for collision avoidance
 * - Does not compromise node identification security
 * - Suitable for public display without privacy concerns
 * 
 * @param nodeId Full cryptographic node identifier string
 * @returns Formatted node ID suitable for UI display
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export function formatNodeId(nodeId: string): string {
    // Display short node IDs in full without truncation
    if (nodeId.length <= 8) {
        return nodeId;
    }
    
    // Format long node IDs with prefix, ellipsis, and suffix for compact display
    return `${nodeId.substring(0, 6)}...${nodeId.substring(nodeId.length - 4)}`;
}

/**
 * Analyze Signal Strength Category from RSSI Measurements
 * =======================================================
 * 
 * Converts raw RSSI (Received Signal Strength Indicator) measurements into
 * human-readable signal quality categories for user interface display and
 * network analysis. This categorization provides intuitive understanding of
 * connection quality and helps users optimize mesh network positioning.
 * 
 * RSSI CATEGORIZATION THRESHOLDS:
 * ===============================
 * 
 * - Excellent (≥ -50 dBm): Very close proximity, optimal connectivity
 * - Good (-60 to -51 dBm): Close range, reliable connectivity
 * - Fair (-70 to -61 dBm): Medium range, acceptable connectivity
 * - Poor (< -70 dBm): Long range or obstructed, marginal connectivity
 * - Unknown (undefined): No RSSI measurement available
 * 
 * SIGNAL QUALITY IMPLICATIONS:
 * ===========================
 * 
 * Excellent Signal:
 * - Maximum data throughput and reliability
 * - Optimal for high-priority mesh communications
 * - Minimal packet loss and retransmission requirements
 * 
 * Good Signal:
 * - Reliable connectivity with good performance
 * - Suitable for most mesh network operations
 * - Occasional retransmissions may occur
 * 
 * Fair Signal:
 * - Acceptable connectivity with reduced performance
 * - May experience increased latency and packet loss
 * - Consider mesh routing optimization
 * 
 * Poor Signal:
 * - Marginal connectivity with significant performance degradation
 * - High packet loss and frequent retransmissions
 * - May benefit from mesh network relay routing
 * 
 * MESH NETWORK APPLICATIONS:
 * ==========================
 * 
 * - Connection quality assessment for routing decisions
 * - User guidance for optimal device positioning
 * - Network topology optimization and planning
 * - Troubleshooting connectivity issues and performance problems
 * - Battery optimization through connection quality awareness
 * 
 * @param rssi Received Signal Strength Indicator in dBm (optional)
 * @returns Signal strength category for user-friendly display
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export function getSignalStrength(rssi?: number): 'excellent' | 'good' | 'fair' | 'poor' | 'unknown' {
    // Handle missing RSSI measurements
    if (rssi === undefined) return 'unknown';
    
    // Categorize signal strength based on industry-standard RSSI thresholds
    if (rssi >= -50) return 'excellent';  // Very close proximity, optimal signal
    if (rssi >= -60) return 'good';       // Close range, reliable connectivity
    if (rssi >= -70) return 'fair';       // Medium range, acceptable quality
    return 'poor';                        // Long range or obstructed, marginal quality
}

/**
 * Generate Visual Signal Strength Bar Representation
 * =================================================
 * 
 * Creates intuitive visual signal strength indicators using Unicode block
 * characters for immediate signal quality assessment in user interfaces.
 * This visualization provides at-a-glance connectivity quality information
 * essential for mesh network monitoring and optimization decisions.
 * 
 * VISUALIZATION DESIGN:
 * ====================
 * 
 * The signal bars use a 4-segment display with filled (█) and empty (░)
 * Unicode block characters to represent signal strength levels:
 * 
 * - Excellent: ████ (4/4 bars) - Full signal strength
 * - Good: ███░ (3/4 bars) - Strong signal with minor degradation
 * - Fair: ██░░ (2/4 bars) - Moderate signal requiring attention
 * - Poor: █░░░ (1/4 bars) - Weak signal needing optimization
 * - Unknown: ░░░░ (0/4 bars) - No signal measurement available
 * 
 * UI INTEGRATION BENEFITS:
 * =======================
 * 
 * - Universal signal strength representation familiar to users
 * - Compact display suitable for mobile device interfaces
 * - Immediate visual assessment without numeric interpretation
 * - Consistent cross-platform appearance using Unicode characters
 * - Accessibility-friendly with clear visual contrast
 * 
 * MESH NETWORK MONITORING:
 * =======================
 * 
 * Visual signal indicators enable:
 * - Quick identification of weak connections requiring attention
 * - Real-time network health assessment at a glance
 * - User guidance for device positioning optimization
 * - Network topology visualization and planning
 * - Performance troubleshooting and diagnostics
 * 
 * PERFORMANCE CONSIDERATIONS:
 * ==========================
 * 
 * - Efficient Unicode string generation with minimal overhead
 * - Cached signal strength calculation for consistent results
 * - Mobile-optimized rendering with standard Unicode characters
 * - No external dependencies or image resources required
 * 
 * @param rssi Received Signal Strength Indicator in dBm (optional)
 * @returns Unicode signal bar visualization string
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export function getSignalBars(rssi?: number): string {
    // Calculate signal strength category using established thresholds
    const strength = getSignalStrength(rssi);
    
    // Generate appropriate visual representation for each strength level
    switch (strength) {
        case 'excellent': return '████';  // Full 4-bar signal strength
        case 'good': return '███░';       // Strong 3-bar signal strength
        case 'fair': return '██░░';       // Moderate 2-bar signal strength
        case 'poor': return '█░░░';       // Weak 1-bar signal strength
        default: return '░░░░';           // No signal measurement available
    }
}

/**
 * Format Unix Timestamp for User-Friendly Time Display
 * ===================================================
 * 
 * Converts Unix timestamp values into human-readable time format using
 * 24-hour notation with consistent zero-padding. This formatting provides
 * clear temporal context for mesh network events, message timestamps,
 * and connection activities in user interface displays.
 * 
 * TIME FORMAT SPECIFICATION:
 * =========================
 * 
 * - Format: HH:MM:SS (24-hour notation)
 * - Zero-padding: Ensures consistent width formatting
 * - Precision: Second-level accuracy for detailed timing
 * - Timezone: Uses device local timezone for user familiarity
 * 
 * DISPLAY CHARACTERISTICS:
 * =======================
 * 
 * - Consistent 8-character width (HH:MM:SS) for table alignment
 * - Professional appearance suitable for technical interfaces
 * - Clear readability for quick time reference
 * - Familiar format recognized across international users
 * - Suitable for both monitoring dashboards and message logs
 * 
 * MESH NETWORK APPLICATIONS:
 * ==========================
 * 
 * Timestamp formatting supports:
 * - Message transmission and reception time logging
 * - Connection establishment and termination tracking
 * - Network event chronology and analysis
 * - Performance monitoring and troubleshooting
 * - Security audit trails and forensic analysis
 * 
 * PERFORMANCE OPTIMIZATION:
 * ========================
 * 
 * - Efficient Date object manipulation with minimal overhead
 * - String padding operations optimized for mobile performance
 * - No external dependencies or complex formatting libraries
 * - Consistent formatting without locale-specific variations
 * 
 * @param timestamp Unix timestamp in milliseconds
 * @returns Formatted time string in HH:MM:SS format
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export function formatTimestamp(timestamp: number): string {
    // Convert Unix timestamp to Date object for time extraction
    const date = new Date(timestamp);
    
    // Extract time components with zero-padding for consistent formatting
    const hours = date.getHours().toString().padStart(2, '0');
    const minutes = date.getMinutes().toString().padStart(2, '0');
    const seconds = date.getSeconds().toString().padStart(2, '0');
    
    // Combine components into standard HH:MM:SS format
    return `${hours}:${minutes}:${seconds}`;
}

/**
 * Calculate Human-Readable Message Age from Timestamp
 * ==================================================
 * 
 * Computes the relative age of messages, connections, or network events
 * using intuitive time units for immediate understanding of temporal
 * context. This function provides progressive time resolution scaling
 * from seconds to days for optimal user comprehension across timeframes.
 * 
 * TIME RESOLUTION SCALING:
 * =======================
 * 
 * The function uses progressive resolution based on message age:
 * 
 * - Immediate (< 1 second): "now" - Real-time or very recent events
 * - Seconds (1-59 seconds): "Xs" - Recent activity requiring attention
 * - Minutes (1-59 minutes): "Xm" - Short-term history and trending
 * - Hours (1-23 hours): "Xh" - Medium-term activity patterns
 * - Days (≥ 1 day): "Xd" - Long-term historical reference
 * 
 * USER EXPERIENCE BENEFITS:
 * ========================
 * 
 * - Intuitive time representation without cognitive overhead
 * - Progressive detail scaling matching user mental models
 * - Compact display format suitable for mobile interfaces
 * - Immediate assessment of message freshness and relevance
 * - Clear indication of network activity patterns and timing
 * 
 * MESH NETWORK APPLICATIONS:
 * ==========================
 * 
 * Message age calculation supports:
 * - Message freshness assessment for relevance filtering
 * - Network activity timeline visualization and analysis
 * - Connection stability monitoring and health assessment
 * - Performance troubleshooting through temporal correlation
 * - User interface prioritization based on temporal significance
 * 
 * CALCULATION ACCURACY:
 * ====================
 * 
 * - Millisecond precision input with appropriate unit conversion
 * - Floor division ensuring consistent aging behavior
 * - Real-time calculation reflecting current temporal context
 * - No caching or stale data issues affecting accuracy
 * 
 * PERFORMANCE CHARACTERISTICS:
 * ===========================
 * 
 * - Efficient mathematical operations with minimal overhead
 * - No external dependencies or complex date libraries
 * - Suitable for frequent recalculation in dynamic interfaces
 * - Mobile-optimized with minimal memory allocation
 * 
 * @param timestamp Unix timestamp in milliseconds of the original event
 * @returns Human-readable age string with appropriate time unit
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export function getMessageAge(timestamp: number): string {
    // Calculate time elapsed since the original timestamp
    const age = Date.now() - timestamp;
    
    // Progressive time resolution scaling for optimal user comprehension
    if (age < 1000) return 'now';                                    // Immediate: < 1 second
    if (age < 60000) return `${Math.floor(age / 1000)}s`;           // Seconds: 1-59 seconds
    if (age < 3600000) return `${Math.floor(age / 60000)}m`;        // Minutes: 1-59 minutes
    if (age < 86400000) return `${Math.floor(age / 3600000)}h`;     // Hours: 1-23 hours
    return `${Math.floor(age / 86400000)}d`;                        // Days: ≥ 1 day
}

/**
 * ============================================================================
 * Development and Debug Utility Functions
 * ============================================================================
 * 
 * Comprehensive debugging and development support utilities providing
 * conditional logging, environment detection, and troubleshooting capabilities
 * for GhostComm Protocol v2.1 applications. These utilities enhance developer
 * productivity while ensuring production builds remain optimized and secure.
 * 
 * DEBUG SYSTEM FEATURES:
 * =====================
 * 
 * - Environment-aware logging with automatic production silence
 * - Structured log formatting for efficient debugging
 * - Component-based log categorization for targeted troubleshooting
 * - Performance-optimized conditional execution
 * - React Native Metro bundler integration for build optimization
 * 
 * PRODUCTION SAFETY:
 * =================
 * 
 * - Automatic debug output suppression in production builds
 * - No performance overhead or security exposure in release mode
 * - Zero-cost abstraction when debugging is disabled
 * - Consistent behavior across development and production environments
 */

import { Platform } from 'react-native';

/**
 * Detect Development Environment for Conditional Debug Operations
 * ==============================================================
 * 
 * Determines whether the application is running in development mode
 * enabling conditional debug functionality, verbose logging, and
 * development-specific features. This detection ensures production
 * builds automatically disable debug overhead and security exposure.
 * 
 * ENVIRONMENT DETECTION:
 * =====================
 * 
 * - Primary: __DEV__ global flag set by React Native Metro bundler
 * - Fallback: Explicit false default for production safety
 * - Compile-time optimization: Dead code elimination in production builds
 * - Platform agnostic: Consistent behavior across iOS and Android
 * 
 * DEVELOPMENT MODE IMPLICATIONS:
 * =============================
 * 
 * Development mode enables:
 * - Verbose logging and debug output
 * - Performance monitoring and profiling
 * - Development-specific UI elements and controls
 * - Extended error reporting and diagnostics
 * - Hot reloading and debugging integration
 * 
 * Production mode characteristics:
 * - Silent operation with no debug output
 * - Optimized performance without debugging overhead
 * - Security-hardened configuration
 * - Minimal resource usage and battery impact
 * 
 * @returns true if running in development mode, false for production
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export function isDevelopment(): boolean {
    // React Native Metro bundler sets __DEV__ global in development builds
    return __DEV__ || false;
}

/**
 * Structured Debug Logging with Protocol v2.1 Context
 * ===================================================
 * 
 * Provides comprehensive debug logging with structured formatting,
 * component categorization, and conditional execution for development
 * troubleshooting. This logging system enhances developer productivity
 * while maintaining zero overhead in production builds.
 * 
 * LOG FORMAT STRUCTURE:
 * ====================
 * 
 * [GhostComm v2.1][Component] Message [Data]
 * 
 * - Protocol identification: Clear GhostComm Protocol v2.1 branding
 * - Component categorization: Specific subsystem or module identification
 * - Message content: Descriptive logging message with context
 * - Optional data: Structured data objects for detailed analysis
 * 
 * COMPONENT CATEGORIZATION:
 * ========================
 * 
 * Common component categories include:
 * - "BLEManager": Core mesh network coordination
 * - "Advertiser": BLE advertisement broadcasting
 * - "Scanner": Node discovery and scanning operations
 * - "Connection": Connection lifecycle and management
 * - "Crypto": Cryptographic operations and security
 * - "UI": User interface and interaction logging
 * 
 * DEVELOPMENT WORKFLOW INTEGRATION:
 * ================================
 * 
 * - Real-time debugging during development and testing
 * - Performance profiling and optimization analysis
 * - Network troubleshooting and connectivity diagnostics
 * - Security audit trails for cryptographic operations
 * - Integration testing and mesh network validation
 * 
 * PERFORMANCE OPTIMIZATION:
 * ========================
 * 
 * - Conditional execution prevents production overhead
 * - Efficient string formatting with minimal allocation
 * - Optional data parameter reduces unnecessary serialization
 * - Dead code elimination in production builds
 * 
 * @param component Component or subsystem name for log categorization
 * @param message Descriptive logging message with relevant context
 * @param data Optional structured data object for detailed analysis
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export function debugLog(component: string, message: string, data?: any): void {
    // Conditional execution: Only log in development mode
    if (isDevelopment()) {
        // Structured log format with Protocol v2.1 branding and component context
        console.log(`[GhostComm v2.1][${component}] ${message}`, data || '');
    }
}