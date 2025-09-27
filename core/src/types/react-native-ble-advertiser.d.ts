/**
 * =====================================================================================
 * GhostComm Protocol v2.1 - React Native BLE Advertiser Type Definitions
 * =====================================================================================
 * 
 * Comprehensive TypeScript type definitions for the react-native-ble-advertiser
 * library providing Bluetooth Low Energy advertising capabilities for the GhostComm
 * mesh network. These definitions enable type-safe integration of BLE advertising
 * functionality with Protocol v2.1 security features and mesh networking requirements.
 * 
 * LIBRARY OVERVIEW:
 * ================
 * 
 * The react-native-ble-advertiser library provides native BLE advertising capabilities
 * across Android and iOS platforms, enabling nodes to broadcast their presence and
 * mesh network information to other nearby devices. This is essential for the
 * GhostComm discovery and connection establishment process.
 * 
 * PROTOCOL v2.1 INTEGRATION:
 * ==========================
 * 
 * These type definitions support Protocol v2.1 features including:
 * - Cryptographically signed advertisement packets
 * - Extended advertising for full public key inclusion
 * - Service UUID identification for mesh network discovery
 * - Custom data payloads for node capabilities and routing information
 * - Permission management for secure advertising operations
 * 
 * CROSS-PLATFORM COMPATIBILITY:
 * =============================
 * 
 * The library provides unified APIs across platforms while handling:
 * - Android BLE advertising limitations and capabilities
 * - iOS Core Bluetooth peripheral management
 * - Platform-specific permission requirements
 * - Hardware capability detection and adaptation
 * 
 * MESH NETWORK APPLICATIONS:
 * ==========================
 * 
 * - Node Discovery: Broadcast node presence for mesh network formation
 * - Capability Advertisement: Share node features and supported protocols
 * - Routing Information: Propagate network topology and connectivity data
 * - Identity Proof: Include cryptographic signatures for authentication
 * - Privacy Protection: Support ephemeral identity rotation
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 * @classification BLE Advertising Interface Definitions
 * @lastModified September 2025
 * 
 * =====================================================================================
 */

// mobile/src/types/react-native-ble-advertiser.d.ts
// Type definitions for react-native-ble-advertiser library integration

declare module 'react-native-ble-advertiser' {
    /**
     * React Native BLE Advertiser Interface
     * ====================================
     * 
     * Primary interface for Bluetooth Low Energy advertising functionality
     * providing comprehensive control over BLE peripheral operations, service
     * advertisement, and platform-specific adapter management. This interface
     * enables GhostComm nodes to broadcast their presence and capabilities
     * across the mesh network with Protocol v2.1 security features.
     * 
     * ADVERTISING LIFECYCLE:
     * =====================
     * 
     * 1. Initialization: Configure service UUID and advertising parameters
     * 2. Permission Management: Request and verify BLE permissions
     * 3. Adapter Control: Enable BLE adapter and verify operational state
     * 4. Broadcasting: Start advertisement with encrypted payload data
     * 5. Management: Monitor advertising state and handle lifecycle events
     * 6. Cleanup: Stop advertising and release system resources
     * 
     * SECURITY INTEGRATION:
     * ====================
     * 
     * The advertising interface supports Protocol v2.1 security through:
     * - Custom service UUIDs for mesh network identification
     * - Encrypted data payloads with cryptographic signatures
     * - Permission validation for secure advertising operations
     * - Adapter state monitoring for security policy enforcement
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    const BLEAdvertiser: {
        setCompanyId(arg0: number): unknown;
        /**
         * Configure BLE Service UUID for Mesh Network Identification
         * =========================================================
         * 
         * Sets the primary service UUID used for BLE advertisements, enabling
         * GhostComm nodes to identify and filter mesh network communications
         * from other BLE devices. This UUID serves as the primary identifier
         * for Protocol v2.1 compatible nodes in the discovery process.
         * 
         * SERVICE UUID REQUIREMENTS:
         * =========================
         * 
         * - Must be a valid 128-bit UUID in standard format
         * - Should be unique to GhostComm mesh network protocols
         * - Used by scanning nodes to filter relevant advertisements
         * - Required before starting any advertising operations
         * 
         * MESH NETWORK INTEGRATION:
         * ========================
         * 
         * The service UUID enables:
         * - Rapid identification of compatible mesh nodes
         * - Filtering of non-GhostComm BLE traffic
         * - Protocol version negotiation and compatibility checking
         * - Efficient discovery in crowded BLE environments
         * 
         * PLATFORM COMPATIBILITY:
         * =======================
         * 
         * - Android: Configures BLE advertising service identifier
         * - iOS: Sets Core Bluetooth peripheral service UUID
         * - Cross-platform: Ensures consistent mesh network identification
         * 
         * @param uuid 128-bit service UUID in standard format (e.g., "550e8400-e29b-41d4-a716-446655440000")
         * @returns void - Configuration applied immediately
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        setServiceUUID(uuid: string): void;
        
        /**
         * Start BLE Advertisement Broadcasting with Protocol v2.1 Data
         * ==========================================================
         * 
         * Initiates BLE advertisement broadcasting with encrypted mesh network
         * data including node capabilities, routing information, and cryptographic
         * signatures. This method implements the core advertising functionality
         * required for GhostComm mesh network discovery and connection establishment.
         * 
         * BROADCASTING PROCESS:
         * ====================
         * 
         * 1. Payload Preparation:
         *    - Validate service UUID configuration
         *    - Encrypt data payload with Protocol v2.1 features
         *    - Apply advertising options and platform optimizations
         * 
         * 2. Advertisement Configuration:
         *    - Configure BLE advertising parameters (interval, power, etc.)
         * 
         * 3. Platform Broadcasting:
         *    - Android: Start BLE advertising with specified parameters
         *    - iOS: Begin Core Bluetooth peripheral advertising
         *    - Handle platform-specific limitations and capabilities
         * 
         * 4. State Management:
         *    - Update internal advertising state tracking
         *    - Enable continuous broadcasting until explicitly stopped
         *    - Handle advertising failures and recovery mechanisms
         * 
         * PROTOCOL v2.1 DATA FORMAT:
         * ==========================
         * 
         * The data parameter typically contains:
         * - Encrypted node capabilities and mesh information
         * - Cryptographic signatures for authenticity verification
         * - Ephemeral identity data for privacy protection
         * - Routing and network topology information
         * - Protocol version and compatibility indicators
         * 
         * ADVERTISING OPTIONS:
         * ===================
         * 
         * Platform-specific options may include:
         * - Advertising interval and duration settings
         * - Transmission power level optimization
         * - Extended advertising support for large payloads
         * - Advertising mode and discoverability settings
         * 
         * ERROR HANDLING:
         * ==============
         * 
         * - Promise rejection for advertising initialization failures
         * - Platform-specific error codes and messages
         * - Automatic retry mechanisms for transient failures
         * - Comprehensive error logging for debugging
         * 
         * @param uuid Service UUID for the advertisement (must match setServiceUUID)
         * @param data Optional encrypted payload data for mesh network information
         * @param options Platform-specific advertising configuration options
         * @returns Promise resolving when advertising starts successfully
         * 
         * @throws Error if UUID not configured, permissions insufficient, or adapter unavailable
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        broadcast(uuid: string, data?: string | null, options?: any): Promise<void>;
        
        /**
         * Stop BLE Advertisement Broadcasting and Release Resources
         * =======================================================
         * 
         * Terminates active BLE advertisement broadcasting and releases all
         * associated system resources. This method ensures clean shutdown
         * of advertising operations while maintaining system stability and
         * preventing resource leakage in the mesh network application.
         * 
         * SHUTDOWN PROCESS:
         * ================
         * 
         * 1. Advertisement Termination:
         *    - Stop active BLE advertising on all configured services
         *    - Cancel any pending advertising operations
         *    - Clear advertisement data and configuration cache
         * 
         * 2. Resource Cleanup:
         *    - Release BLE hardware resources and system handles
         *    - Clear internal state tracking and timers
         *    - Notify system of advertising service availability
         * 
         * 3. Platform Integration:
         *    - Android: Stop BLE advertising service and clear callbacks
         *    - iOS: Stop Core Bluetooth peripheral advertising
         *    - Handle platform-specific cleanup requirements
         * 
         * 4. State Synchronization:
         *    - Update internal advertising state to inactive
         *    - Clear service UUID configuration if required
         *    - Ensure consistent state for future operations
         * 
         * USE CASES:
         * =========
         * 
         * - Application lifecycle: Stop advertising when app goes background
         * - Power management: Disable advertising to conserve battery
         * - Network stealth: Temporarily hide node from mesh discovery
         * - Reconfiguration: Stop before changing advertising parameters
         * - Cleanup: Ensure proper resource release on application exit
         * 
         * RELIABILITY FEATURES:
         * ====================
         * 
         * - Idempotent operation: Safe to call multiple times
         * - Graceful degradation: Continues even if already stopped
         * - Resource safety: Prevents resource leaks and system instability
         * - Error recovery: Handles platform-specific shutdown failures
         * 
         * @returns Promise resolving when advertising stops and resources are released
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        stopBroadcast(): Promise<void>;
        
        /**
         * Request Required Bluetooth Permissions for Advertising Operations
         * ===============================================================
         * 
         * Initiates the platform-specific permission request process required
         * for BLE advertising operations. This method handles the complex
         * permission requirements across Android and iOS platforms, ensuring
         * proper authorization for mesh network advertising functionality.
         * 
         * PERMISSION REQUIREMENTS:
         * =======================
         * 
         * Android Permissions:
         * - BLUETOOTH: Basic Bluetooth functionality
         * - BLUETOOTH_ADMIN: Bluetooth adapter management
         * - ACCESS_FINE_LOCATION: Required for BLE advertising on Android 6+
         * - BLUETOOTH_ADVERTISE: Required for BLE advertising on Android 12+
         * 
         * iOS Permissions:
         * - Bluetooth usage description in Info.plist
         * - Core Bluetooth peripheral usage authorization
         * - Background app refresh for continuous advertising
         * 
         * PERMISSION FLOW:
         * ===============
         * 
         * 1. Permission Assessment:
         *    - Check current permission status for all required permissions
         *    - Identify missing or denied permissions requiring user action
         *    - Determine platform-specific permission request strategy
         * 
         * 2. User Interaction:
         *    - Display system permission dialogs for required permissions
         *    - Handle user approval, denial, or "don't ask again" responses
         *    - Provide clear explanation of permission necessity for mesh networking
         * 
         * 3. Result Processing:
         *    - Evaluate final permission status after user interaction
         *    - Return boolean indicating successful permission acquisition
         *    - Log permission results for debugging and compliance tracking
         * 
         * 4. Error Handling:
         *    - Handle permission request failures and system errors
         *    - Provide fallback options for partial permission grants
         *    - Guide users through manual permission configuration if needed
         * 
         * SECURITY CONSIDERATIONS:
         * =======================
         * 
         * - Minimal permission principle: Request only necessary permissions
         * - User privacy: Clear explanation of data usage and mesh networking
         * - Permission persistence: Handle revoked permissions gracefully
         * - Platform compliance: Follow platform-specific permission guidelines
         * 
         * MESH NETWORK IMPLICATIONS:
         * =========================
         * 
         * Without proper permissions:
         * - Node cannot advertise presence to mesh network
         * - Discovery by other nodes becomes impossible
         * - Mesh network connectivity severely limited
         * - Protocol v2.1 security features may be unavailable
         * 
         * @returns Promise resolving to true if all permissions granted, false otherwise
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        requestBTPermissions(): Promise<boolean>;
        
        /**
         * Check Current Bluetooth Permission Status
         * ========================================
         * 
         * Evaluates the current status of all Bluetooth permissions required
         * for BLE advertising operations without triggering permission request
         * dialogs. This method provides real-time permission status information
         * essential for mesh network capability assessment and user guidance.
         * 
         * PERMISSION VALIDATION:
         * =====================
         * 
         * Checks status of all required permissions:
         * - Bluetooth hardware access permissions
         * - BLE advertising specific permissions
         * - Location permissions (Android-specific requirement)
         * - Background execution permissions (for continuous advertising)
         * 
         * PLATFORM-SPECIFIC CHECKS:
         * =========================
         * 
         * Android Permission Validation:
         * - BLUETOOTH and BLUETOOTH_ADMIN for basic functionality
         * - ACCESS_FINE_LOCATION for BLE operations on Android 6+
         * - BLUETOOTH_ADVERTISE for advertising on Android 12+
         * - Runtime permission status evaluation
         * 
         * iOS Permission Validation:
         * - Core Bluetooth authorization status
         * - Peripheral usage permissions
         * - Background app refresh capabilities
         * - Privacy settings compliance
         * 
         * STATUS INTERPRETATION:
         * =====================
         * 
         * - true: All required permissions granted and advertising possible
         * - false: One or more required permissions missing or denied
         * 
         * The boolean result provides immediate actionability for the application
         * to determine whether advertising operations can proceed or if user
         * interaction is required for permission acquisition.
         * 
         * USE CASES:
         * =========
         * 
         * - Pre-flight checks: Validate permissions before advertising attempts
         * - UI state management: Show appropriate user interface based on permissions
         * - Capability assessment: Determine available mesh network functionality
         * - Troubleshooting: Identify permission-related connectivity issues
         * - Compliance monitoring: Track permission status for security auditing
         * 
         * PERFORMANCE CONSIDERATIONS:
         * ==========================
         * 
         * - Synchronous permission status checking for immediate results
         * - Minimal system overhead with cached permission state
         * - No user interaction or dialog prompts
         * - Suitable for frequent permission status monitoring
         * 
         * @returns Promise resolving to true if all permissions are available, false otherwise
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        checkBTPermissions(): Promise<boolean>;
        
        /**
         * Enable Bluetooth Adapter for Mesh Network Operations
         * ===================================================
         * 
         * Programmatically enables the device's Bluetooth adapter to support
         * BLE advertising and mesh network operations. This method provides
         * platform-abstracted adapter management ensuring the Bluetooth
         * hardware is properly configured for GhostComm Protocol v2.1 operations.
         * 
         * ADAPTER ENABLEMENT PROCESS:
         * ===========================
         * 
         * 1. Hardware State Assessment:
         *    - Check current Bluetooth adapter state and availability
         *    - Verify hardware capability for BLE operations
         *    - Identify any hardware-level restrictions or limitations
         * 
         * 2. Platform-Specific Enablement:
         *    - Android: Request Bluetooth adapter enablement through BluetoothAdapter
         *    - iOS: Guide user through Settings app for Bluetooth enablement
         *    - Handle platform differences in programmatic control capabilities
         * 
         * 3. State Verification:
         *    - Confirm successful adapter enablement
         *    - Validate BLE advertising capability availability
         *    - Ensure adapter is ready for mesh network operations
         * 
         * 4. Error Handling:
         *    - Handle user denial of adapter enablement requests
         *    - Manage hardware failures or unavailability
         *    - Provide appropriate error context for troubleshooting
         * 
         * PLATFORM BEHAVIOR:
         * ==================
         * 
         * Android Implementation:
         * - May prompt user for Bluetooth enablement confirmation
         * - Programmatic enablement possible with proper permissions
         * - Returns when adapter state changes complete
         * 
         * iOS Implementation:
         * - Cannot programmatically enable Bluetooth due to platform restrictions
         * - May guide user to Settings app for manual enablement
         * - Monitors state changes for enablement confirmation
         * 
         * MESH NETWORK REQUIREMENTS:
         * =========================
         * 
         * Bluetooth adapter enablement is essential for:
         * - BLE advertisement broadcasting capabilities
         * - Mesh network node discovery and connectivity
         * - Protocol v2.1 security feature operations
         * - Cross-platform mesh communication compatibility
         * 
         * USER EXPERIENCE:
         * ===============
         * 
         * - Clear indication of Bluetooth requirement necessity
         * - Graceful handling of user enablement decisions
         * - Appropriate fallback options for disabled Bluetooth
         * - Seamless integration with application workflow
         * 
         * @returns Promise resolving when Bluetooth adapter is successfully enabled
         * 
         * @throws Error if adapter enablement fails or user denies permission
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        enableAdapter(): Promise<void>;
        
        /**
         * Disable Bluetooth Adapter for Power Management
         * =============================================
         * 
         * Programmatically disables the device's Bluetooth adapter to conserve
         * power and disable mesh network operations. This method provides
         * controlled shutdown of Bluetooth functionality while ensuring
         * proper cleanup of all BLE advertising and connection resources.
         * 
         * ADAPTER DISABLEMENT PROCESS:
         * ===========================
         * 
         * 1. Resource Cleanup:
         *    - Stop all active BLE advertising operations
         *    - Terminate existing mesh network connections
         *    - Clear advertisement data and service configurations
         * 
         * 2. Platform-Specific Disablement:
         *    - Android: Request Bluetooth adapter disablement through system APIs
         *    - iOS: Guide user through Settings for manual Bluetooth control
         *    - Handle platform restrictions on programmatic adapter control
         * 
         * 3. State Synchronization:
         *    - Update internal state to reflect disabled adapter
         *    - Clear any cached adapter capabilities and configuration
         *    - Ensure consistent application state during disablement
         * 
         * 4. Verification and Confirmation:
         *    - Confirm successful adapter disablement
         *    - Validate all mesh network operations are terminated
         *    - Provide completion confirmation for calling applications
         * 
         * PLATFORM CONSIDERATIONS:
         * =======================
         * 
         * Android Capabilities:
         * - Programmatic adapter disablement with proper permissions
         * - System-level Bluetooth stack shutdown
         * - Complete hardware resource release
         * 
         * iOS Limitations:
         * - Cannot programmatically disable Bluetooth due to platform restrictions
         * - Application-level resource cleanup only
         * - User must manually disable through Settings app
         * 
         * USE CASES:
         * =========
         * 
         * - Power conservation: Disable Bluetooth to extend battery life
         * - Security isolation: Disconnect from mesh network for privacy
         * - Troubleshooting: Reset Bluetooth state to resolve connectivity issues
         * - Compliance requirements: Disable radio communications in restricted areas
         * - Application lifecycle: Clean shutdown during app termination
         * 
         * MESH NETWORK IMPACT:
         * ===================
         * 
         * Adapter disablement results in:
         * - Complete disconnection from mesh network
         * - Loss of node discovery and communication capabilities
         * - Termination of all Protocol v2.1 security sessions
         * - Inability to participate in mesh routing and forwarding
         * 
         * @returns Promise resolving when Bluetooth adapter is successfully disabled
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        disableAdapter(): Promise<void>;
        
        /**
         * Get Current Bluetooth Adapter State for Status Monitoring
         * ========================================================
         * 
         * Retrieves the current operational state of the device's Bluetooth
         * adapter providing real-time status information essential for mesh
         * network capability assessment and user interface state management.
         * This method enables applications to respond appropriately to adapter
         * state changes and provide accurate mesh connectivity information.
         * 
         * ADAPTER STATE INFORMATION:
         * =========================
         * 
         * Returns detailed adapter state including:
         * - Hardware availability and operational status
         * - Enablement state and user configuration
         * - BLE advertising capability status
         * - Platform-specific adapter characteristics
         * 
         * POSSIBLE STATE VALUES:
         * =====================
         * 
         * Standard Bluetooth States:
         * - "STATE_OFF": Bluetooth adapter is disabled
         * - "STATE_ON": Bluetooth adapter is enabled and operational
         * - "STATE_TURNING_ON": Adapter is in the process of enabling
         * - "STATE_TURNING_OFF": Adapter is in the process of disabling
         * 
         * Extended State Information:
         * - "STATE_BLE_TURNING_ON": BLE-specific enablement in progress
         * - "STATE_BLE_ON": BLE functionality specifically available
         * - "STATE_UNSUPPORTED": Hardware does not support Bluetooth/BLE
         * - "STATE_UNAUTHORIZED": Permissions insufficient for adapter access
         * 
         * MESH NETWORK IMPLICATIONS:
         * =========================
         * 
         * State Impact on Mesh Operations:
         * - STATE_ON: Full mesh network participation possible
         * - STATE_OFF: No mesh network connectivity available
         * - STATE_TURNING_*: Transitional state, mesh operations pending
         * - STATE_UNSUPPORTED: Device cannot participate in mesh network
         * 
         * APPLICATION INTEGRATION:
         * =======================
         * 
         * State information enables:
         * - Dynamic UI updates reflecting connectivity status
         * - Intelligent mesh operation scheduling based on adapter availability
         * - User guidance for optimal mesh network configuration
         * - Troubleshooting support for connectivity issues
         * 
         * MONITORING STRATEGY:
         * ===================
         * 
         * - Periodic polling for state change detection
         * - Event-driven updates when adapter state transitions occur
         * - Cached state information for performance optimization
         * - Integration with platform state change notifications
         * 
         * PERFORMANCE CONSIDERATIONS:
         * ==========================
         * 
         * - Lightweight operation suitable for frequent monitoring
         * - Platform-optimized state retrieval mechanisms
         * - Minimal system overhead for real-time status updates
         * - Efficient caching for repeated state queries
         * 
         * @returns Promise resolving to string representation of current adapter state
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        getAdapterState(): Promise<string>;
        
        /**
         * Check BLE Advertisement Active Status for Operation Monitoring
         * ============================================================
         * 
         * Determines whether BLE advertisement broadcasting is currently active
         * and operational. This method provides real-time status information
         * about the advertising state essential for mesh network monitoring,
         * troubleshooting, and user interface state synchronization.
         * 
         * ACTIVE STATE DETERMINATION:
         * ==========================
         * 
         * Evaluates multiple factors to determine advertising status:
         * - BLE advertising service operational state
         * - Service UUID configuration and validity
         * - Platform-specific advertising hardware status
         * - Advertisement data transmission status
         * 
         * STATUS ACCURACY:
         * ===============
         * 
         * The returned boolean reflects:
         * - true: Advertising is actively broadcasting and discoverable
         * - false: No advertising activity or advertising stopped
         * 
         * This status information is synchronized with actual hardware
         * advertising state and provides accurate operational visibility.
         * 
         * PLATFORM STATE TRACKING:
         * ========================
         * 
         * Android Status Monitoring:
         * - BluetoothLeAdvertiser operational state tracking
         * - Advertisement callback status evaluation
         * - Hardware advertising capability verification
         * 
         * iOS Status Monitoring:
         * - Core Bluetooth peripheral manager state assessment
         * - Advertisement service publication status
         * - Peripheral advertising state synchronization
         * 
         * MESH NETWORK APPLICATIONS:
         * =========================
         * 
         * Active status monitoring enables:
         * - Real-time connectivity status display for users
         * - Automated troubleshooting for mesh network issues
         * - Performance monitoring and optimization decisions
         * - Integration with mesh network health assessment systems
         * 
         * USE CASES:
         * =========
         * 
         * - User Interface: Display current mesh network participation status
         * - Health Monitoring: Verify advertising operations for network diagnostics
         * - Automatic Recovery: Detect advertising failures and trigger restart
         * - Power Management: Confirm advertising status for battery optimization
         * - Compliance Verification: Ensure advertising matches intended operation
         * 
         * PERFORMANCE CHARACTERISTICS:
         * ===========================
         * 
         * - Fast synchronous status check with minimal overhead
         * - Real-time accuracy with platform state synchronization
         * - Suitable for frequent monitoring and status polling
         * - Efficient implementation minimizing battery impact
         * 
         * RELIABILITY FEATURES:
         * ====================
         * 
         * - Comprehensive platform state evaluation
         * - Error-resistant status determination
         * - Consistent behavior across platform implementations
         * - Graceful handling of edge cases and error conditions
         * 
         * @returns Promise resolving to true if advertising is active, false otherwise
         * 
         * @author LCpl 'Si' Procak
         * @version Protocol v2.1.0
         */
        isActive(): Promise<boolean>;
    };
    
    export default BLEAdvertiser;
}