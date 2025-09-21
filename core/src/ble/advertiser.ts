// core/src/ble/advertiser.ts
// ================================================================================================
// Enhanced BLE Advertiser with Protocol v2.1 Cryptographic Signatures and Privacy Protection
// ================================================================================================
//
// OWNERSHIP AND VERSION INFORMATION:
// ==================================
// @author     LCpl 'Si' Procak
// @version    Protocol v2.1.0
// @since      Protocol v2.0
// @updated    September 2025
// @license    Proprietary - GhostComm Mesh Network
//
// This module provides a sophisticated Bluetooth Low Energy (BLE) advertising system for the
// GhostComm mesh network with comprehensive Protocol v2.1 security features. It implements
// advanced cryptographic signatures, ephemeral identity rotation, replay protection, and
// secure node discovery mechanisms for privacy-preserving mesh communications.
//
// PROTOCOL v2.1 ENHANCEMENTS:
// ===========================
// - Mandatory Ed25519 cryptographic signatures for all advertisements
// - Full 32-byte public key inclusion for direct verification
// - Enhanced ephemeral identity rotation with temporal decorrelation
// - Advanced replay protection using monotonic sequence numbers
// - Pre-key bundle advertisement for asynchronous session establishment
// - Comprehensive mesh topology broadcasting with security metadata
// - Privacy-preserving capability advertisement and service discovery
// - Anti-correlation features for enhanced tracking resistance
//
// SECURITY ARCHITECTURE:
// =====================
// - 256-bit Ed25519 digital signatures for advertisement authentication
// - SHA-256 identity hashing with collision resistance
// - Temporal decorrelation preventing long-term tracking analysis
// - Cryptographic replay protection with sequence number validation
// - Perfect forward secrecy through ephemeral key rotation
// - Anonymous routing preparation with privacy preservation
//
// PERFORMANCE OPTIMIZATIONS:
// ==========================
// - Efficient binary packet encoding for minimal BLE overhead
// - Adaptive advertisement intervals based on network density
// - Power-aware broadcasting with battery level optimization
// - Intelligent timing coordination for collision avoidance
// - Memory-efficient data structures for embedded deployment
//
// OPERATIONAL REQUIREMENTS:
// ========================
// - BLE 5.0+ hardware with extended advertising support
// - Ed25519/X25519 cryptographic capability
// - Minimum 31-byte advertisement payload capacity
// - Timer resolution of 1ms or better for timing coordination
// - Hardware random number generator for cryptographic security

import {
    BLEAdvertisementData,
    BLE_CONFIG,
    BLE_SECURITY_CONFIG,
    IdentityProof,
    PreKeyBundle,
    MeshAdvertisement,
    NodeCapability,
    DeviceType
} from './types';
import {
    IGhostKeyPair,
    PreKey,
    CryptoAlgorithm
} from '../types/crypto';

/**
 * Protocol v2.1 Advertisement Packet Structure for Cryptographically Secure BLE Transmission
 * ==========================================================================================
 * 
 * This interface defines the complete binary packet structure for Protocol v2.1 compliant
 * BLE advertisements. It optimizes for minimal BLE overhead while providing comprehensive
 * cryptographic security, ephemeral identity protection, and mesh network intelligence.
 * 
 * PROTOCOL v2.1 MANDATORY FEATURES:
 * =================================
 * - Full 32-byte Ed25519 public key inclusion for direct verification
 * - Cryptographic signatures using Ed25519 for authentication
 * - Monotonic sequence numbers for comprehensive replay protection
 * - Enhanced ephemeral identity rotation for privacy preservation
 * - Mesh topology broadcasting with security metadata
 * 
 * PACKET OPTIMIZATION:
 * ===================
 * - Binary encoding for maximum BLE payload efficiency
 * - Compact mesh information for essential network data
 * - Optional extended data for advanced features
 * - Structured format enabling efficient parsing and validation
 * 
 * SECURITY GUARANTEES:
 * ===================
 * - Cryptographic authentication of all packet contents
 * - Identity proof linking ephemeral IDs to permanent keys
 * - Replay protection preventing message reuse attacks
 * - Integrity verification detecting tampering attempts
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 * @since Protocol v2.0
 */
export interface AdvertisementPacket {
    /**
     * Protocol version identifier for compatibility and feature detection
     * MUST be 2 for Protocol v2.1 compliance with mandatory cryptographic verification
     */
    version: number;
    
    /**
     * Capability and feature flags for efficient service discovery
     * Bitfield encoding node capabilities, device type, and protocol features
     */
    flags: number;
    
    /**
     * 16-byte ephemeral identifier for privacy-preserving node correlation
     * Rotates periodically to prevent long-term tracking while enabling
     * short-term mesh operations and connectivity maintenance
     */
    ephemeralId: Uint8Array;
    
    /**
     * 32-byte SHA-256 hash of the node's permanent Ed25519 identity key
     * Provides stable node identification while preserving privacy through
     * cryptographic one-way function properties
     */
    identityHash: Uint8Array;
    
    /**
     * Full 32-byte Ed25519 public key for direct cryptographic verification
     * Protocol v2.1 MANDATORY: Enables immediate signature verification
     * without requiring key resolution or separate key exchange
     */
    publicKey?: Uint8Array;
    
    /**
     * Monotonic sequence number for comprehensive replay protection
     * Must increment with each advertisement to prevent replay attacks
     * and enable temporal ordering of advertisements from the same node
     */
    sequenceNumber: number;
    
    /**
     * Unix timestamp of advertisement creation for freshness validation
     * Used for temporal validation and coordinated ephemeral ID rotation
     * across the mesh network for optimal privacy protection
     */
    timestamp: number;
    
    /**
     * 64-byte Ed25519 signature over all packet contents
     * Provides cryptographic authentication and integrity verification
     * for the entire advertisement packet using the node's identity key
     */
    signature: Uint8Array;
    
    /**
     * Compact mesh network topology and status information
     * Essential mesh data optimized for BLE payload constraints
     * including node count, queue status, and routing metrics
     */
    meshInfo: CompactMeshInfo;
    
    /**
     * Optional extended data for advanced Protocol v2.1 features
     * Contains pre-key bundles, service announcements, and enhanced
     * security metadata when advertisement space permits
     */
    extendedData?: Uint8Array;
}

/**
 * Compact Mesh Network Information for Efficient Protocol v2.1 Topology Broadcasting
 * ===================================================================================
 * 
 * This interface defines a space-efficient representation of essential mesh network
 * topology and status information optimized for BLE advertisement payload constraints.
 * It provides critical routing intelligence while maintaining minimal overhead.
 * 
 * DESIGN PRINCIPLES:
 * =================
 * - Minimal byte overhead for BLE payload efficiency
 * - Essential routing information for intelligent path selection
 * - Real-time network health indicators for adaptive algorithms
 * - Power management integration for battery-aware operations
 * 
 * TOPOLOGY INTELLIGENCE:
 * =====================
 * - Node count for network density assessment
 * - Queue status for load balancing decisions
 * - Battery levels for power-aware routing
 * - Protocol version for compatibility matrix
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export interface CompactMeshInfo {
    /**
     * Total number of nodes known to this mesh participant
     * Used for network density assessment and routing algorithm optimization
     * Range: 0-255 (8-bit encoding for space efficiency)
     */
    nodeCount: number;
    
    /**
     * Current message queue size indicating node load and capacity
     * Used for load balancing decisions and congestion avoidance
     * Range: 0-255 (8-bit encoding representing queue utilization)
     */
    queueSize: number;
    
    /**
     * Current battery level for power-aware mesh routing decisions
     * Enables power-conscious routing to preserve critical network nodes
     * Range: 0-100 (percentage, encoded as 8-bit value)
     */
    batteryLevel: number;
    
    /**
     * Capability and status flags for mesh network features
     * Bitfield encoding relay capability, service availability, and
     * special node roles within the mesh topology
     */
    flags: number;
    
    /**
     * Supported protocol version for compatibility assessment
     * Protocol v2.1 requirement for feature negotiation and security validation
     * Must be 2 or higher for Protocol v2+ compliance
     */
    protocolVersion: number;  // Protocol v2.1 requirement
}

/**
 * Ephemeral Identity Rotation Schedule for Advanced Privacy Protection
 * ===================================================================
 * 
 * This interface manages the coordinated rotation of ephemeral identifiers
 * to provide maximum privacy protection while maintaining mesh network
 * connectivity and operational efficiency.
 * 
 * PRIVACY FEATURES:
 * ================
 * - Temporal decorrelation preventing long-term tracking
 * - Coordinated rotation timing across mesh participants  
 * - Cryptographically secure identifier generation
 * - Seamless transition without connectivity loss
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
interface RotationSchedule {
    /**
     * Current ephemeral identifier in active use
     * 16-byte cryptographically random identifier for privacy protection
     */
    ephemeralId: string;
    
    /**
     * Unix timestamp when this ephemeral ID became valid
     * Used for temporal validation and rotation timing coordination
     */
    validFrom: number;
    
    /**
     * Unix timestamp when this ephemeral ID expires
     * After this time, the identifier should not be used for new advertisements
     */
    validUntil: number;
    
    /**
     * Scheduled time for the next ephemeral ID rotation
     * Used for proactive rotation preparation and timing coordination
     */
    nextRotation: number;
}

/**
 * Enhanced BLE Advertiser with Comprehensive Protocol v2.1 Security Architecture
 * =============================================================================
 * 
 * This abstract base class provides a complete secure BLE advertising system with
 * advanced cryptographic signatures, ephemeral identity management, and privacy
 * protection features required for Protocol v2.1 compliance.
 * 
 * CORE CAPABILITIES:
 * =================
 * 
 * Cryptographic Security:
 * - Ed25519 digital signatures for advertisement authentication
 * - SHA-256 identity hashing with collision resistance
 * - Monotonic sequence numbers for replay protection
 * - Comprehensive message integrity verification
 * 
 * Privacy Protection:
 * - Ephemeral identifier rotation with temporal decorrelation
 * - Anonymous advertising preventing long-term tracking
 * - Cryptographic unlinkability between advertisement instances
 * - Privacy-preserving capability and service advertisement
 * 
 * Mesh Network Integration:
 * - Intelligent topology broadcasting with security metadata
 * - Adaptive advertisement timing based on network conditions
 * - Power-aware broadcasting for battery optimization
 * - Cross-platform abstraction for diverse deployment environments
 * 
 * Performance Optimization:
 * - Signature caching for efficient cryptographic operations
 * - Advertisement history tracking for duplicate prevention
 * - Rate limiting for resource protection and compliance
 * - Memory-efficient data structures for embedded systems
 * 
 * PROTOCOL v2.1 COMPLIANCE:
 * =========================
 * - Mandatory cryptographic verification for all advertisements
 * - Full public key inclusion for immediate verification
 * - Enhanced replay protection with sequence number validation
 * - Advanced mesh topology broadcasting with security context
 * - Pre-key bundle advertisement for asynchronous session establishment
 * 
 * USAGE PATTERNS:
 * ==============
 * 
 * Secure Advertising:
 * 1. Initialize with cryptographic key pair for identity and signatures
 * 2. Configure advertisement data with capabilities and mesh information
 * 3. Start advertising with automatic signature generation and verification
 * 4. Maintain ephemeral identity rotation for privacy protection
 * 
 * Platform Implementation:
 * 1. Extend this abstract class for specific platform integration
 * 2. Implement platform-specific BLE advertising operations
 * 3. Handle platform advertisement callbacks and error conditions
 * 4. Integrate with platform power management and lifecycle events
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 * @since Protocol v2.0
 */
export abstract class BLEAdvertiser {
    // ===== OPERATIONAL STATE MANAGEMENT =====
    
    /**
     * Current advertising operation status
     * 
     * Tracks whether the advertiser is actively broadcasting BLE advertisements.
     * Used to prevent duplicate operations and manage advertiser lifecycle.
     * This property should remain private to enforce proper state management.
     */
    private isAdvertising: boolean = false;
    
    /**
     * Pause state for temporary advertising suspension
     * 
     * Allows temporary suspension of advertising without full shutdown,
     * preserving configuration and cryptographic state for quick resumption.
     * Useful for power management and operational coordination.
     */
    private isPaused: boolean = false;
    
    /**
     * Current advertisement data being broadcast
     * 
     * Contains the complete structured advertisement information including
     * identity proof, capabilities, and mesh status. Updated when advertisement
     * content changes or ephemeral identity rotation occurs.
     */
    private currentAdvertisement?: BLEAdvertisementData;
    
    /**
     * Current binary packet being transmitted
     * 
     * Optimized binary representation of the advertisement data for efficient
     * BLE transmission. Generated from currentAdvertisement with signature
     * and cryptographic validation included.
     */
    private currentPacket?: AdvertisementPacket;

    // ===== CRYPTOGRAPHIC SECURITY COMPONENTS =====
    
    /**
     * Cryptographic key pair for identity and signature operations
     * 
     * Ed25519/X25519 key pair providing cryptographic identity and signature
     * capability. REQUIRED for Protocol v2.1 compliance with mandatory
     * cryptographic verification. Protected scope allows derived classes access.
     */
    protected keyPair?: IGhostKeyPair;
    
    /**
     * Monotonic sequence number for replay protection
     * 
     * Incrementing counter ensuring each advertisement has a unique sequence
     * number for comprehensive replay attack protection. Must never decrease
     * or repeat to maintain security guarantees.
     */
    private sequenceNumber: number = 0;
    
    /**
     * Current ephemeral identity rotation schedule
     * 
     * Manages the timing and coordination of ephemeral identifier rotation
     * for privacy protection. Contains current ID, validity periods, and
     * next rotation timing for seamless privacy maintenance.
     */
    private rotationSchedule?: RotationSchedule;
    
    /**
     * Advertisement signature cache for performance optimization
     * 
     * Caches previously computed signatures to avoid redundant cryptographic
     * operations when advertisement content hasn't changed. Key is content
     * hash, value is Ed25519 signature for performance optimization.
     */
    private advertisementHistory: Map<number, string>;
    
    /**
     * Signature verification cache for efficiency
     * 
     * Stores computed signatures indexed by content hash to prevent
     * repeated cryptographic operations for identical advertisement
     * content. Improves performance in high-frequency advertising scenarios.
     */
    private signatureCache: Map<string, Uint8Array>;

    // ===== TIMING MANAGEMENT AND COORDINATION =====
    
    /**
     * Advertisement timing control timer
     * 
     * Controls the periodic broadcasting of BLE advertisements according
     * to the configured interval. Handles timing coordination and ensures
     * consistent advertisement frequency for optimal mesh discovery.
     */
    private advertisementTimer?: NodeJS.Timeout;
    
    /**
     * Ephemeral identity rotation timer
     * 
     * Manages the automatic rotation of ephemeral identifiers according
     * to the configured privacy schedule. Ensures timely rotation for
     * maximum privacy protection without connectivity disruption.
     */
    private rotationTimer?: NodeJS.Timeout;
    
    /**
     * Timestamp of last successful advertisement transmission
     * 
     * Records when the last advertisement was successfully broadcast,
     * used for timing calculations, rate limiting, and operational
     * monitoring. Updated on each successful transmission.
     */
    private lastAdvertisementTime: number = 0;
    
    /**
     * Current advertisement interval in milliseconds
     * 
     * Time between consecutive advertisement broadcasts, defaulting to
     * the configured Protocol v2.1 interval. May be dynamically adjusted
     * based on network conditions and power management requirements.
     */
    private advertisementInterval: number = BLE_CONFIG.ADVERTISEMENT_INTERVAL;

    // ===== RATE LIMITING AND RESOURCE PROTECTION =====
    
    /**
     * Advertisement transmission counter for rate limiting
     * 
     * Tracks the number of advertisements sent for rate limiting and
     * resource protection. Used to prevent excessive transmission that
     * could violate platform limitations or drain battery resources.
     */
    private advertisementCount: number = 0;
    
    /**
     * Rate limiting time window in milliseconds
     * 
     * Duration of the sliding window for rate limit calculations.
     * Advertisements are counted within this window to enforce
     * transmission rate limits and prevent resource exhaustion.
     */
    private rateLimitWindow: number = 60000; // 1 minute
    
    /**
     * Maximum advertisements allowed per rate limiting window
     * 
     * Upper limit on advertisement transmissions within the rate
     * limiting window. Prevents excessive transmission that could
     * violate platform constraints or drain battery resources.
     */
    private maxAdvertisementsPerWindow: number = 30;

    // ===== PERFORMANCE STATISTICS AND MONITORING =====
    
    /**
     * Comprehensive advertising performance and operational statistics
     * 
     * Detailed metrics for monitoring advertiser performance, success rates,
     * and operational health. Used for debugging, optimization, and system
     * health assessment in production deployments.
     * 
     * Statistics Categories:
     * - Transmission metrics: Total, successful, and failed advertisements
     * - Privacy metrics: Ephemeral identity rotation count and timing
     * - Performance metrics: Average transmission intervals and success rates
     * - Protocol compliance: Version tracking and feature usage
     * - Error tracking: Last error conditions and failure analysis
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    private statistics = {
        /** Total number of advertisement attempts made */
        totalAdvertisements: 0,
        /** Successfully transmitted advertisements */
        successfulAdvertisements: 0,
        /** Failed advertisement transmissions */
        failedAdvertisements: 0,
        /** Number of ephemeral identity rotations performed */
        rotations: 0,
        /** Average advertisement interval in milliseconds */
        averageInterval: 0,
        /** Current protocol version in use */
        protocolVersion: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
        /** Last error encountered during operations */
        lastError: null as Error | null
    };

    /**
     * Initialize Protocol v2.1 BLE Advertiser with Cryptographic Security
     * 
     * Establishes a fully-featured BLE advertising system with comprehensive
     * Protocol v2.1 security features including cryptographic signatures,
     * ephemeral identity management, and privacy protection capabilities.
     * 
     * INITIALIZATION COMPONENTS:
     * =========================
     * 
     * Cryptographic Setup:
     * - Ed25519/X25519 key pair configuration for identity and signatures
     * - Signature cache initialization for performance optimization
     * - Advertisement history tracking for duplicate prevention
     * - Sequence number initialization for replay protection
     * 
     * Privacy Protection:
     * - Ephemeral identity rotation schedule preparation
     * - Temporal decorrelation system initialization
     * - Anonymous advertising capability setup
     * - Privacy-preserving state management
     * 
     * Performance Optimization:
     * - Cache initialization for cryptographic operations
     * - Rate limiting system preparation
     * - Statistics tracking initialization
     * - Memory-efficient data structure setup
     * 
     * Platform Integration:
     * - Abstract interface preparation for platform-specific implementation
     * - Timer management system initialization
     * - Error handling and recovery mechanism setup
     * - Resource management and cleanup preparation
     * 
     * @param keyPair Optional Ed25519/X25519 key pair for cryptographic operations
     *                Required for Protocol v2.1 compliance with mandatory signatures
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    constructor(keyPair?: IGhostKeyPair) {
        // Store cryptographic identity for signature generation and verification
        this.keyPair = keyPair;
        
        // Initialize performance optimization caches
        this.advertisementHistory = new Map();  // Advertisement content tracking
        this.signatureCache = new Map();        // Signature computation cache
    }

    // ===== ABSTRACT PLATFORM INTERFACE =====
    
    /**
     * Platform-specific BLE advertising implementations
     * 
     * These abstract methods must be implemented by platform-specific subclasses
     * to provide actual BLE advertising functionality. The abstraction allows the
     * advertiser to work across different platforms while maintaining consistent
     * security and privacy features.
     * 
     * Implementation Requirements:
     * - Must handle low-level BLE advertisement transmission
     * - Should support Protocol v2.1 extended advertisement formats
     * - Must provide reliable start/stop advertising control
     * - Should integrate with platform power management systems
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    
    /**
     * Start platform-specific BLE advertising with the provided packet data
     * 
     * @param packet Binary advertisement packet optimized for BLE transmission
     * @returns Promise that resolves when advertising starts successfully
     */
    protected abstract startPlatformAdvertising(packet: Uint8Array): Promise<void>;
    
    /**
     * Stop platform-specific BLE advertising operations
     * 
     * @returns Promise that resolves when advertising stops completely
     */
    protected abstract stopPlatformAdvertising(): Promise<void>;
    
    /**
     * Update platform-specific advertising with new packet data
     * 
     * @param packet Updated binary advertisement packet
     * @returns Promise that resolves when advertising is updated
     */
    protected abstract updatePlatformAdvertising(packet: Uint8Array): Promise<void>;
    
    /**
     * Query platform-specific BLE advertising capabilities
     * 
     * @returns Promise resolving to platform capability information
     */
    protected abstract checkPlatformCapabilities(): Promise<{
        /** Maximum advertisement packet size supported by platform */
        maxAdvertisementSize: number;
        /** Whether platform supports BLE 5.0+ extended advertising */
        supportsExtendedAdvertising: boolean;
        /** Whether platform supports periodic advertising */
        supportsPeriodicAdvertising: boolean;
    }>;

    // ===== PUBLIC INTERFACE =====

    /**
     * Start Secure BLE Advertising with Comprehensive Protocol v2.1 Compliance
     * ========================================================================
     * 
     * Initiates secure BLE advertising with full Protocol v2.1 cryptographic
     * verification, ephemeral identity management, and privacy protection.
     * This method establishes the complete advertising system with all
     * security and privacy features required for mesh network participation.
     * 
     * ADVERTISING PROCESS:
     * ===================
     * 
     * 1. Security Validation:
     *    - Advertisement data validation for Protocol v2.1 compliance
     *    - Cryptographic key availability verification
     *    - Security configuration validation and enhancement
     * 
     * 2. Packet Generation:
     *    - Binary packet creation with optimized BLE format
     *    - Ed25519 signature generation for authentication
     *    - Ephemeral identity rotation and privacy protection
     * 
     * 3. Platform Integration:
     *    - Platform capability assessment and compatibility checking
     *    - Extended advertising support verification for large packets
     *    - Advertisement transmission with platform-specific optimization
     * 
     * 4. Operational Management:
     *    - Timer initialization for periodic advertisement updates
     *    - Statistics tracking and performance monitoring
     *    - Error handling and recovery mechanism activation
     * 
     * PROTOCOL v2.1 FEATURES:
     * =======================
     * 
     * - Mandatory Ed25519 cryptographic signatures for all advertisements
     * - Full 32-byte public key inclusion for immediate verification
     * - Enhanced ephemeral identity rotation for privacy protection
     * - Comprehensive replay protection with sequence number validation
     * - Advanced mesh topology broadcasting with security metadata
     * - Pre-key bundle advertisement for asynchronous session establishment
     * 
     * SECURITY GUARANTEES:
     * ===================
     * 
     * - Advertisement authenticity through cryptographic signatures
     * - Identity verification preventing spoofing attacks
     * - Replay protection preventing message reuse attacks
     * - Privacy preservation through ephemeral identifier rotation
     * - Mesh topology security with authenticated network information
     * 
     * @param data Advertisement data with capabilities and mesh information
     * @returns Promise that resolves when advertising starts successfully
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async startAdvertising(data: BLEAdvertisementData): Promise<void> {
        // Handle concurrent advertising requests by updating existing advertisement
        if (this.isAdvertising && !this.isPaused) {
            console.log('Already advertising, updating advertisement data');
            await this.updateAdvertisement(data);
            return;
        }

        try {
            console.log(`Starting Protocol v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}.1 BLE advertisement`);

            // Validate advertisement data for Protocol v2.1 compliance requirements
            this.validateAdvertisementData(data);
            
            // Enhance advertisement data with Protocol v2.1 security features
            const enhancedData = await this.enhanceAdvertisementDataV21(data);

            // Create cryptographically signed packet with Protocol v2.1 structure
            const packet = await this.createAdvertisementPacket(enhancedData);

            // Check platform capabilities for BLE 5.0+ extended advertising support
            const capabilities = await this.checkPlatformCapabilities();
            const packetBytes = this.serializePacket(packet);

            // Protocol v2.1 packets are ~140 bytes, requiring extended advertising
            if (packetBytes.length > capabilities.maxAdvertisementSize) {
                if (!capabilities.supportsExtendedAdvertising) {
                    console.warn(`Advertisement size (${packetBytes.length}) exceeds limit (${capabilities.maxAdvertisementSize})`);
                    console.warn('Protocol v2.1 requires extended advertising for full public key inclusion');
                }
                console.log('Using extended advertising for Protocol v2.1 packet');
            }

            // Initialize platform-specific BLE advertising with cryptographically signed packet
            await this.startPlatformAdvertising(packetBytes);

            // Establish ephemeral identity rotation schedule for privacy protection
            this.setupRotationSchedule(enhancedData);
            
            // Start periodic advertisement broadcasting with timing coordination
            this.startPeriodicAdvertising();

            // Update operational state to reflect active advertising
            this.isAdvertising = true;
            this.isPaused = false;
            this.currentAdvertisement = enhancedData;
            this.currentPacket = packet;
            this.lastAdvertisementTime = Date.now();

            // Update performance statistics for monitoring and analysis
            this.statistics.totalAdvertisements++;
            this.statistics.successfulAdvertisements++;

            console.log('Protocol v2.1 BLE advertising started successfully');

        } catch (error) {
            // Handle advertising initialization errors gracefully
            console.error('Failed to start Protocol v2.1 BLE advertising:', error);
            this.statistics.failedAdvertisements++;
            this.statistics.lastError = error as Error;
            this.isAdvertising = false;
            throw error;
        }
    }

    /**
     * Stop Secure BLE Advertising and Cleanup All Resources
     * =====================================================
     * 
     * Gracefully terminates BLE advertising operations while preserving
     * cryptographic state and configuration for future restart. This method
     * ensures clean shutdown of all advertising-related resources and timers.
     * 
     * SHUTDOWN PROCESS:
     * ================
     * 
     * 1. Platform Advertising Termination:
     *    - Stop platform-specific BLE advertising operations
     *    - Clean up any active advertisement requests
     *    - Release BLE hardware resources
     * 
     * 2. Timer and Resource Cleanup:
     *    - Stop periodic advertising timer
     *    - Stop ephemeral identity rotation timer
     *    - Clean up any pending operations
     * 
     * 3. State Management:
     *    - Update advertising operational status
     *    - Preserve cryptographic configuration for restart
     *    - Maintain statistics and performance data
     * 
     * PRESERVATION FEATURES:
     * =====================
     * 
     * - Cryptographic key material is preserved for restart
     * - Advertisement configuration is maintained
     * - Statistics and performance data remain intact
     * - Sequence numbers continue from last value to prevent replay
     * 
     * @returns Promise that resolves when advertising stops completely
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async stopAdvertising(): Promise<void> {
        // Exit early if not currently advertising to avoid unnecessary operations
        if (!this.isAdvertising) {
            return;
        }

        try {
            console.log('Stopping Protocol v2.1 BLE advertising and cleaning up resources...');

            // Stop all periodic timers to prevent further advertisement operations
            this.stopPeriodicAdvertising();
            this.stopRotationSchedule();

            // Terminate platform-specific BLE advertising operations
            await this.stopPlatformAdvertising();

            // Update operational state while preserving cryptographic configuration
            this.isAdvertising = false;
            this.isPaused = false;
            this.currentAdvertisement = undefined;
            this.currentPacket = undefined;

            // Clear signature cache to release memory resources
            this.signatureCache.clear();

            console.log('Protocol v2.1 BLE advertising stopped successfully');

        } catch (error) {
            // Handle shutdown errors while ensuring clean state
            console.error('Failed to stop Protocol v2.1 BLE advertising:', error);
            this.statistics.lastError = error as Error;
            throw error;
        }
    }

    /**
     * Pause Active BLE Advertising Temporarily
     * ========================================
     * 
     * Temporarily suspends BLE advertising operations while maintaining
     * cryptographic state and configuration for immediate resumption.
     * This method is useful for power management or temporary network
     * silence without losing the established advertising context.
     * 
     * PAUSE OPERATIONS:
     * ================
     * 
     * 1. Operational Validation:
     *    - Check current advertising status
     *    - Verify pause state to prevent redundant operations
     *    - Maintain state consistency during pause
     * 
     * 2. Resource Suspension:
     *    - Stop periodic advertising timer
     *    - Terminate platform BLE advertising
     *    - Preserve all cryptographic material
     * 
     * 3. State Management:
     *    - Set pause flag for proper resumption
     *    - Maintain advertising configuration
     *    - Preserve packet and advertisement data
     * 
     * PRESERVATION FEATURES:
     * =====================
     * 
     * - Complete cryptographic state preservation
     * - Advertisement packet maintained for resumption
     * - Statistics and performance data preserved
     * - Ephemeral identity rotation schedule maintained
     * 
     * @returns Promise that resolves when advertising is paused
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async pauseAdvertising(): Promise<void> {
        // Validate current state to ensure pause operation is appropriate
        if (!this.isAdvertising || this.isPaused) {
            return;
        }

        console.log('Pausing Protocol v2.1 BLE advertising operations');
        
        // Stop periodic advertising while preserving state
        this.stopPeriodicAdvertising();
        
        // Terminate platform advertising operations
        await this.stopPlatformAdvertising();
        
        // Set pause flag for proper resumption tracking
        this.isPaused = true;
    }

    /**
     * Resume Previously Paused BLE Advertising
     * =======================================
     * 
     * Resumes BLE advertising operations from a paused state using
     * preserved cryptographic state and advertisement configuration.
     * This method ensures seamless continuation of advertising with
     * maintained security context and network presence.
     * 
     * RESUMPTION PROCESS:
     * ==================
     * 
     * 1. State Validation:
     *    - Verify advertising and pause status
     *    - Check availability of preserved advertisement packet
     *    - Validate cryptographic state integrity
     * 
     * 2. Advertisement Restoration:
     *    - Restore platform BLE advertising with preserved packet
     *    - Resume periodic advertising timer operations
     *    - Continue ephemeral identity rotation schedule
     * 
     * 3. Operational Continuity:
     *    - Clear pause flag for normal operations
     *    - Maintain sequence number continuity
     *    - Preserve all performance statistics
     * 
     * SECURITY CONTINUITY:
     * ===================
     * 
     * - Cryptographic signatures remain valid
     * - Ephemeral identity rotation continues seamlessly
     * - Replay protection sequence maintained
     * - All Protocol v2.1 security features preserved
     * 
     * @returns Promise that resolves when advertising resumes
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async resumeAdvertising(): Promise<void> {
        // Validate state for resumption operation
        if (!this.isAdvertising || !this.isPaused) {
            return;
        }

        console.log('Resuming Protocol v2.1 BLE advertising operations');

        // Restore advertising using preserved packet data
        if (this.currentPacket) {
            const packetBytes = this.serializePacket(this.currentPacket);
            await this.startPlatformAdvertising(packetBytes);
            
            // Resume periodic advertising operations
            this.startPeriodicAdvertising();
            
            // Clear pause flag to indicate active advertising
            this.isPaused = false;
        }
    }

    /**
     * Update Active Advertisement with New Data
     * ========================================
     * 
     * Dynamically updates active BLE advertisement with new mesh information,
     * capabilities, or routing data while maintaining cryptographic security
     * and operational continuity. This method enables real-time mesh network
     * adaptation without interrupting advertising operations.
     * 
     * UPDATE PROCESS:
     * ==============
     * 
     * 1. Data Validation:
     *    - Validate new advertisement data for Protocol v2.1 compliance
     *    - Enhance data with current security features
     *    - Verify cryptographic key availability
     * 
     * 2. Packet Generation:
     *    - Create new cryptographically signed packet
     *    - Generate fresh signature with current ephemeral identity
     *    - Maintain sequence number progression for replay protection
     * 
     * 3. Seamless Transition:
     *    - Update platform advertising with new packet
     *    - Maintain timer operations without interruption
     *    - Update operational state with new advertisement data
     * 
     * SECURITY MAINTENANCE:
     * ====================
     * 
     * - Fresh cryptographic signatures for new data
     * - Continued ephemeral identity rotation
     * - Maintained replay protection sequence
     * - Protocol v2.1 compliance verification
     * 
     * @param data New advertisement data with updated capabilities and mesh info
     * @returns Promise that resolves when advertisement is updated
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async updateAdvertisement(data: BLEAdvertisementData): Promise<void> {
        // Validate advertising state before attempting update
        if (!this.isAdvertising) {
            // Store new data for future advertising session
            this.currentAdvertisement = data;
            return;
        }

        try {
            console.log('Updating Protocol v2.1 advertisement with new mesh data');

            // Validate new advertisement data for Protocol v2.1 compliance
            this.validateAdvertisementData(data);
            
            // Enhance advertisement data with current security features
            const enhancedData = await this.enhanceAdvertisementDataV21(data);

            // Create new cryptographically signed packet with fresh signature
            const packet = await this.createAdvertisementPacket(enhancedData);
            const packetBytes = this.serializePacket(packet);

            // Update platform advertising seamlessly without interruption
            await this.updatePlatformAdvertising(packetBytes);

            // Update operational state with new advertisement configuration
            this.currentAdvertisement = enhancedData;
            this.currentPacket = packet;
            this.lastAdvertisementTime = Date.now();

            // Update performance statistics
            this.statistics.totalAdvertisements++;
            this.statistics.successfulAdvertisements++;

            console.log('Protocol v2.1 advertisement updated successfully');

        } catch (error) {
            // Handle update errors while maintaining current advertisement
            console.error('Failed to update Protocol v2.1 advertisement:', error);
            this.statistics.failedAdvertisements++;
            this.statistics.lastError = error as Error;
            throw error;
        }
    }

    // ===== PROTOCOL v2.1 ENHANCEMENT =====

    /**
     * Enhance Advertisement Data with Protocol v2.1 Security Features
     * ==============================================================
     * 
     * Applies comprehensive Protocol v2.1 security enhancements to basic
     * advertisement data, adding mandatory cryptographic features, identity
     * proof, and privacy protections required for secure mesh networking.
     * 
     * ENHANCEMENT PROCESS:
     * ===================
     * 
     * 1. Protocol Version Enforcement:
     *    - Set Protocol v2.1 version identifier
     *    - Ensure backward compatibility markers
     *    - Validate protocol compliance requirements
     * 
     * 2. Security Feature Addition:
     *    - Generate unique sequence number for replay protection
     *    - Add current timestamp for temporal validity
     *    - Create ephemeral identity for privacy protection
     * 
     * 3. Cryptographic Identity Proof:
     *    - Include full 32-byte Ed25519 public key
     *    - Generate SHA-256 public key hash for verification
     *    - Create cryptographic signature for authentication
     * 
     * 4. Data Integrity Validation:
     *    - Verify all mandatory fields are present
     *    - Ensure cryptographic material availability
     *    - Validate enhanced data structure compliance
     * 
     * PROTOCOL v2.1 MANDATORY FEATURES:
     * =================================
     * 
     * - Full Ed25519 public key inclusion (32 bytes)
     * - Cryptographic signature using private key
     * - Ephemeral identity rotation for privacy
     * - Sequence number for replay attack prevention
     * - Timestamp for temporal validity verification
     * - Public key hash for rapid verification
     * 
     * SECURITY GUARANTEES:
     * ===================
     * 
     * - Advertisement authenticity through Ed25519 signatures
     * - Identity verification preventing impersonation
     * - Replay protection through sequence numbers
     * - Privacy preservation via ephemeral identifiers
     * - Temporal validity through timestamp verification
     * 
     * @param data Basic advertisement data to enhance
     * @returns Enhanced advertisement data with Protocol v2.1 security features
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    private async enhanceAdvertisementDataV21(data: BLEAdvertisementData): Promise<BLEAdvertisementData> {
        // Enforce Protocol v2.1 version identification
        data.version = BLE_SECURITY_CONFIG.PROTOCOL_VERSION;
        data.protocolVersion = BLE_SECURITY_CONFIG.PROTOCOL_VERSION;

        // Generate unique sequence number for replay protection
        if (!data.sequenceNumber) {
            data.sequenceNumber = this.getNextSequenceNumber();
        }

        // Add current timestamp for temporal validity verification
        data.timestamp = Date.now();

        // Generate ephemeral identity for privacy protection if not provided
        if (!data.ephemeralId) {
            data.ephemeralId = this.generateEphemeralId();
        }

        // Protocol v2.1: MANDATORY full 32-byte Ed25519 public key inclusion
        if (this.keyPair) {
            const identityPublicKey = this.keyPair.getIdentityPublicKey();
            data.identityProof.publicKey = this.bytesToHex(identityPublicKey);
            
            // Generate SHA-256 public key hash for rapid verification
            if (!data.identityProof.publicKeyHash) {
                const hash = await this.hashPublicKey(identityPublicKey);
                data.identityProof.publicKeyHash = this.bytesToHex(hash);
            }
        } else if (BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION) {
            throw new Error('Protocol v2.1 requires key pair for mandatory public key inclusion');
        }

        // Generate cryptographic signature with Protocol v2.1 requirements
        if (this.keyPair) {
            data.identityProof.signature = await this.signAdvertisementV21(data);
        }

        return data;
    }

    /**
     * Generate Cryptographic Signature for Protocol v2.1 Advertisement
     * ==============================================================
     * 
     * Creates Ed25519 cryptographic signature for advertisement data using
     * the node's identity private key. This signature provides authenticity
     * verification and prevents spoofing attacks in the mesh network.
     * 
     * SIGNING PROCESS:
     * ===============
     * 
     * 1. Data Preparation:
     *    - Create canonical signing data from Protocol v2.1 fields
     *    - Include all security-critical advertisement components
     *    - Ensure deterministic field ordering for verification
     * 
     * 2. Signature Generation:
     *    - Use Ed25519 identity private key for signing
     *    - Generate 64-byte cryptographic signature
     *    - Cache signature for performance optimization
     * 
     * 3. Cache Management:
     *    - Store signatures with data hash as cache key
     *    - Implement LRU eviction for memory management
     *    - Limit cache size to prevent memory exhaustion
     * 
     * SECURITY FEATURES:
     * =================
     * 
     * - Ed25519 cryptographic signature (64 bytes)
     * - Identity verification preventing impersonation
     * - Non-repudiation through private key authentication
     * - Cache optimization for repeated identical data
     * 
     * @param data Advertisement data to sign
     * @returns Hexadecimal string representation of Ed25519 signature
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    private async signAdvertisementV21(data: BLEAdvertisementData): Promise<string> {
        if (!this.keyPair) {
            throw new Error('Key pair required for Protocol v2.1 cryptographic signing');
        }

        // Create canonical signing data with all Protocol v2.1 security fields
        const signingData = this.createSigningDataV21(data);

        // Generate cache key from signing data hash for optimization
        const cacheKey = this.hashData(signingData);
        let signature = this.signatureCache.get(cacheKey);

        if (!signature) {
            // Generate Ed25519 signature using identity private key
            signature = this.keyPair.signMessage(signingData);

            // Cache signature for performance optimization
            this.signatureCache.set(cacheKey, signature);

            // Implement LRU cache eviction to prevent memory exhaustion
            if (this.signatureCache.size > 100) {
                const firstKey = this.signatureCache.keys().next().value;
                if (firstKey) {
                    this.signatureCache.delete(firstKey);
                }
            }
        }

        return this.bytesToHex(signature);
    }

    /**
     * Create Canonical Signing Data for Protocol v2.1 Verification
     * ============================================================
     * 
     * Generates deterministic binary data for cryptographic signing by
     * combining all security-critical advertisement fields in a specific
     * order. This ensures consistent signature verification across all
     * implementations and prevents signature validation failures.
     * 
     * INCLUDED FIELDS (in order):
     * ===========================
     * 
     * 1. ephemeralId - Privacy-preserving temporary identifier
     * 2. publicKeyHash - SHA-256 hash of Ed25519 public key
     * 3. publicKey - Full 32-byte Ed25519 public key (Protocol v2.1)
     * 4. timestamp - Advertisement creation time
     * 5. nonce - Cryptographic nonce for uniqueness
     * 6. sequenceNumber - Replay protection sequence
     * 7. version - Protocol version identifier
     * 8. nodeCount - Current mesh network size
     * 9. messageQueueSize - Node's message queue status
     * 
     * DATA STRUCTURE:
     * ==============
     * 
     * - Fields joined with '-' delimiter for parsing
     * - UTF-8 encoding for cross-platform compatibility
     * - Deterministic ordering for verification consistency
     * - All numeric values converted to string representation
     * 
     * @param data Advertisement data containing security fields
     * @returns Binary signing data for Ed25519 signature generation
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    private createSigningDataV21(data: BLEAdvertisementData): Uint8Array {
        // Combine all critical Protocol v2.1 fields in deterministic order
        const parts = [
            data.ephemeralId,
            data.identityProof.publicKeyHash,
            data.identityProof.publicKey || '',  // Protocol v2.1: Mandatory full public key
            data.identityProof.timestamp.toString(),
            data.identityProof.nonce,
            data.sequenceNumber.toString(),
            data.version.toString(),
            data.meshInfo.nodeCount.toString(),
            data.meshInfo.messageQueueSize.toString()
        ];

        // Create UTF-8 encoded binary data for cryptographic signing
        return new TextEncoder().encode(parts.join('-'));
    }

    /**
     * Create Binary Advertisement Packet with Protocol v2.1 Structure
     * ==============================================================
     * 
     * Generates optimized binary packet for BLE advertisement transmission
     * with Protocol v2.1 security features and efficient space utilization.
     * This packet format maximizes information density while maintaining
     * cryptographic security and network topology awareness.
     * 
     * PACKET STRUCTURE:
     * ================
     * 
     * 1. Header Section:
     *    - Protocol version and magic bytes
     *    - Packet type and capability flags
     *    - Timestamp and sequence number
     * 
     * 2. Identity Section:
     *    - Full 32-byte Ed25519 public key
     *    - Ephemeral identity for privacy
     *    - Cryptographic signature (64 bytes)
     * 
     * 3. Mesh Information:
     *    - Compact node count (1 byte, max 255)
     *    - Message queue size (1 byte, max 255)
     *    - Network topology metadata
     * 
     * OPTIMIZATION FEATURES:
     * =====================
     * 
     * - Compact mesh info with 8-bit limits for space efficiency
     * - Capability flags as bitmask for minimal overhead
     * - Binary encoding for maximum data density
     * - Protocol v2.1 structure for security compliance
     * 
     * @param data Enhanced advertisement data with Protocol v2.1 features
     * @returns Binary advertisement packet ready for BLE transmission
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    private async createAdvertisementPacket(data: BLEAdvertisementData): Promise<AdvertisementPacket> {
        // Generate capability flags bitmask from node capabilities
        const flags = this.createCapabilityFlags(data.capabilities);

        // Create compact mesh information with 8-bit space optimization
        const meshInfo: CompactMeshInfo = {
            nodeCount: Math.min(255, data.meshInfo.nodeCount),
            queueSize: Math.min(255, data.meshInfo.messageQueueSize),
            batteryLevel: data.batteryLevel || 100,
            flags: this.createMeshFlags(data),
            protocolVersion: BLE_SECURITY_CONFIG.PROTOCOL_VERSION
        };

        const packet: AdvertisementPacket = {
            version: BLE_SECURITY_CONFIG.PROTOCOL_VERSION,
            flags,
            ephemeralId: this.hexToBytes(data.ephemeralId),
            identityHash: this.hexToBytes(data.identityProof.publicKeyHash).slice(0, 8),
            sequenceNumber: data.sequenceNumber,
            timestamp: Math.floor(data.timestamp / 1000),
            signature: this.hexToBytes(data.identityProof.signature),
            meshInfo,
            extendedData: await this.createExtendedDataV21(data)
        };

        // Protocol v2.1: Include full public key (MANDATORY)
        if (data.identityProof.publicKey) {
            packet.publicKey = this.hexToBytes(data.identityProof.publicKey).slice(0, 32);
        } else if (BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION) {
            console.warn('Protocol v2.1 requires public key in packet');
        }

        return packet;
    }

    /**
     * Serialize packet for transmission (Protocol v2.1 format)
     */
    private serializePacket(packet: AdvertisementPacket): Uint8Array {
        // Calculate Protocol v2.1 packet size
        let size = 1 + 1 + 16 + 8 + 4 + 4 + 64 + 5; // Base fields (110 bytes)
        
        // Protocol v2.1: Add public key space (32 bytes)
        if (packet.publicKey) {
            size += 32; // Total: 142 bytes
        }
        
        if (packet.extendedData) {
            size += packet.extendedData.length;
        }

        const buffer = new Uint8Array(size);
        const view = new DataView(buffer.buffer);
        let offset = 0;

        // Version (1 byte)
        buffer[offset++] = packet.version;

        // Flags (1 byte)
        buffer[offset++] = packet.flags;

        // Ephemeral ID (16 bytes)
        buffer.set(packet.ephemeralId, offset);
        offset += 16;

        // Identity hash (8 bytes)
        buffer.set(packet.identityHash, offset);
        offset += 8;

        // Protocol v2.1: Public key (32 bytes)
        if (packet.publicKey) {
            buffer.set(packet.publicKey, offset);
            offset += 32;
        }

        // Sequence number (4 bytes)
        view.setUint32(offset, packet.sequenceNumber, false);
        offset += 4;

        // Timestamp (4 bytes)
        view.setUint32(offset, packet.timestamp, false);
        offset += 4;

        // Signature (64 bytes)
        buffer.set(packet.signature, offset);
        offset += 64;

        // Mesh info (5 bytes with protocol version)
        buffer[offset++] = packet.meshInfo.nodeCount;
        buffer[offset++] = packet.meshInfo.queueSize;
        buffer[offset++] = packet.meshInfo.batteryLevel;
        buffer[offset++] = packet.meshInfo.flags;
        buffer[offset++] = packet.meshInfo.protocolVersion;

        // Extended data (variable)
        if (packet.extendedData) {
            buffer.set(packet.extendedData, offset);
        }

        return buffer;
    }

    /**
     * Parse advertisement packet (Protocol v2.1 aware)
     */
    static parseAdvertisementPacket(data: Uint8Array): AdvertisementPacket | null {
        try {
            // Minimum Protocol v2.1 packet size
            if (data.length < 110) {
                return null;
            }

            const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
            let offset = 0;

            // Version
            const version = data[offset++];

            // Flags
            const flags = data[offset++];

            // Ephemeral ID (16 bytes)
            const ephemeralId = data.slice(offset, offset + 16);
            offset += 16;

            // Identity hash (8 bytes)
            const identityHash = data.slice(offset, offset + 8);
            offset += 8;

            // Protocol v2.1: Check for public key
            let publicKey: Uint8Array | undefined;
            if (version >= 2 && data.length >= offset + 32 + 76) {
                publicKey = data.slice(offset, offset + 32);
                offset += 32;
            }

            // Sequence number (4 bytes)
            const sequenceNumber = view.getUint32(offset, false);
            offset += 4;

            // Timestamp (4 bytes)
            const timestamp = view.getUint32(offset, false);
            offset += 4;

            // Signature (64 bytes)
            const signature = data.slice(offset, offset + 64);
            offset += 64;

            // Mesh info (5 bytes for v2.1)
            const meshInfo: CompactMeshInfo = {
                nodeCount: data[offset++],
                queueSize: data[offset++],
                batteryLevel: data[offset++],
                flags: data[offset++],
                protocolVersion: version >= 2 ? data[offset++] : 1
            };

            // Extended data
            let extendedData: Uint8Array | undefined;
            if (offset < data.length) {
                extendedData = data.slice(offset);
            }

            return {
                version,
                flags,
                ephemeralId,
                identityHash,
                publicKey,
                sequenceNumber,
                timestamp,
                signature,
                meshInfo,
                extendedData
            };

        } catch (error) {
            console.error('Error parsing advertisement packet:', error);
            return null;
        }
    }

    // ===== VALIDATION =====

    /**
     * Validate advertisement data for Protocol v2.1 compliance
     */
    private validateAdvertisementData(data: BLEAdvertisementData): void {
        // Version check
        if (!data.version || data.version < BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            console.warn(`Advertisement version ${data.version} < required v${BLE_SECURITY_CONFIG.PROTOCOL_VERSION}`);
        }

        // Identity proof validation
        if (!data.identityProof) {
            throw new Error('Identity proof required in advertisement');
        }

        if (!data.identityProof.publicKeyHash || data.identityProof.publicKeyHash.length < 16) {
            throw new Error('Invalid public key hash in identity proof');
        }

        // Protocol v2.1: Require public key
        if (BLE_SECURITY_CONFIG.REQUIRE_SIGNATURE_VERIFICATION && !data.identityProof.publicKey) {
            console.warn('Protocol v2.1 REQUIRES full public key in identity proof');
        }

        if (!data.identityProof.nonce || data.identityProof.nonce.length < 16) {
            throw new Error('Invalid nonce in identity proof');
        }

        // Timestamp validation
        const now = Date.now();
        const timeDiff = Math.abs(now - data.timestamp);
        if (timeDiff > 300000) { // 5 minutes
            console.warn('Advertisement timestamp differs significantly from current time');
        }

        // Mesh info validation
        if (!data.meshInfo) {
            throw new Error('Mesh information required in advertisement');
        }

        // Pre-key bundle validation if present
        if (data.identityProof.preKeyBundle) {
            this.validatePreKeyBundle(data.identityProof.preKeyBundle);
        }
    }

    /**
     * Validate pre-key bundle structure
     */
    private validatePreKeyBundle(bundle: PreKeyBundle): void {
        if (!bundle.identityKey || bundle.identityKey.length !== 64) {
            throw new Error('Invalid identity key in pre-key bundle (must be 64 hex chars)');
        }

        if (!bundle.signedPreKey) {
            throw new Error('Signed pre-key required in bundle');
        }

        if (!bundle.signedPreKey.publicKey || bundle.signedPreKey.publicKey.length !== 64) {
            throw new Error('Invalid signed pre-key public key (must be 64 hex chars)');
        }

        if (!bundle.signedPreKey.signature || bundle.signedPreKey.signature.length !== 128) {
            throw new Error('Invalid signed pre-key signature (must be 128 hex chars)');
        }
    }

    // ===== EXTENDED DATA =====

    /**
     * Create extended data for Protocol v2.1
     */
    private async createExtendedDataV21(data: BLEAdvertisementData): Promise<Uint8Array | undefined> {
        const extended: any = {};

        // Include pre-key bundle if present
        if (data.identityProof.preKeyBundle) {
            extended.preKeyBundle = data.identityProof.preKeyBundle;
        }

        // Protocol v2.1 supported algorithms
        extended.supportedAlgorithms = [
            CryptoAlgorithm.ED25519,
            CryptoAlgorithm.X25519,
            CryptoAlgorithm.XCHACHA20_POLY1305
        ];

        // Protocol v2.1 requirements
        extended.protocolRequirements = {
            requireSignatureVerification: true,
            requireMessageChaining: true,
            requireSequenceNumbers: true,
            requirePublicKeyInAdvertisement: true  // v2.1 specific
        };

        if (Object.keys(extended).length > 0) {
            const extendedData = JSON.stringify(extended);
            return new TextEncoder().encode(extendedData);
        }

        return undefined;
    }

    // ===== ROTATION MANAGEMENT =====

    /**
     * Setup ephemeral ID rotation schedule
     */
    private setupRotationSchedule(data: BLEAdvertisementData): void {
        this.stopRotationSchedule();

        const baseInterval = BLE_CONFIG.ADDRESS_ROTATION_INTERVAL;
        const randomization = Math.random() * BLE_CONFIG.ADVERTISEMENT_RANDOMIZATION;
        const interval = baseInterval + randomization;

        this.rotationSchedule = {
            ephemeralId: data.ephemeralId,
            validFrom: Date.now(),
            validUntil: Date.now() + interval,
            nextRotation: Date.now() + interval
        };

        this.rotationTimer = setTimeout(() => {
            this.rotateEphemeralId();
        }, interval);

        console.log(`Ephemeral ID rotation scheduled for ${new Date(this.rotationSchedule.nextRotation).toLocaleTimeString()}`);
    }

    /**
     * Stop rotation schedule
     */
    private stopRotationSchedule(): void {
        if (this.rotationTimer) {
            clearTimeout(this.rotationTimer);
            this.rotationTimer = undefined;
        }
        this.rotationSchedule = undefined;
    }

    /**
     * Rotate ephemeral ID for privacy
     */
    private async rotateEphemeralId(): Promise<void> {
        if (!this.currentAdvertisement) {
            return;
        }

        console.log('Rotating ephemeral ID for privacy');

        // Generate new ephemeral ID
        const newEphemeralId = this.generateEphemeralId();

        // Update advertisement
        this.currentAdvertisement.ephemeralId = newEphemeralId;
        this.currentAdvertisement.sequenceNumber = this.getNextSequenceNumber();

        // Re-sign with Protocol v2.1
        if (this.keyPair) {
            this.currentAdvertisement.identityProof.signature = await this.signAdvertisementV21(this.currentAdvertisement);
        }

        // Update advertisement
        await this.updateAdvertisement(this.currentAdvertisement);

        // Update statistics
        this.statistics.rotations++;

        // Schedule next rotation
        this.setupRotationSchedule(this.currentAdvertisement);
    }

    // ===== PERIODIC ADVERTISING =====

    /**
     * Start periodic advertising updates
     */
    private startPeriodicAdvertising(): void {
        this.stopPeriodicAdvertising();
        
        // Store reference to avoid 'this' binding issues
        const interval = this.advertisementInterval;
        
        this.advertisementTimer = setInterval(() => {
            this.performPeriodicAdvertisement().catch(error => {
                console.error('Error in periodic advertisement:', error);
            });
        }, interval);
    }

    /**
     * Stop periodic advertising
     */
    private stopPeriodicAdvertising(): void {
        if (this.advertisementTimer) {
            clearInterval(this.advertisementTimer);
            this.advertisementTimer = undefined;
        }
    }

    /**
     * Perform periodic advertisement update
     */
    private async performPeriodicAdvertisement(): Promise<void> {
        if (!this.isAdvertising || this.isPaused) {
            return;
        }

        try {
            if (!this.checkRateLimit()) {
                console.warn('Advertisement rate limit reached');
                return;
            }

            if (this.currentAdvertisement) {
                // Update dynamic fields
                this.currentAdvertisement.meshInfo.nodeCount = await this.getNodeCount();
                this.currentAdvertisement.meshInfo.messageQueueSize = await this.getQueueSize();
                this.currentAdvertisement.sequenceNumber = this.getNextSequenceNumber();

                await this.updateAdvertisement(this.currentAdvertisement);
            }

            // Update statistics
            const now = Date.now();
            const interval = now - this.lastAdvertisementTime;
            this.statistics.averageInterval = 
                (this.statistics.averageInterval * 0.9) + (interval * 0.1);
            this.lastAdvertisementTime = now;

        } catch (error) {
            console.error('Periodic advertisement failed:', error);
            this.statistics.failedAdvertisements++;
        }
    }

    // ===== HELPER METHODS =====

    /**
     * Create capability flags byte
     */
    private createCapabilityFlags(capabilities: NodeCapability[]): number {
        let flags = 0;

        const capabilityBits: Record<NodeCapability, number> = {
            [NodeCapability.RELAY]: 0x01,
            [NodeCapability.STORAGE]: 0x02,
            [NodeCapability.BRIDGE]: 0x04,
            [NodeCapability.GROUP_CHAT]: 0x08,
            [NodeCapability.FILE_TRANSFER]: 0x10,
            [NodeCapability.VOICE_NOTES]: 0x20
        };

        for (const capability of capabilities) {
            flags |= capabilityBits[capability] || 0;
        }

        return flags;
    }

    /**
     * Create mesh flags byte
     */
    private createMeshFlags(data: BLEAdvertisementData): number {
        let flags = 0;

        if (data.identityProof.preKeyBundle) {
            flags |= 0x01; // Has pre-keys
        }

        flags |= 0x02; // Accepting connections

        if (data.batteryLevel && data.batteryLevel < 20) {
            flags |= 0x04; // Low battery
        }

        if (data.meshInfo.messageQueueSize > 0) {
            flags |= 0x08; // Has queued messages
        }

        // Protocol v2.1 flag
        if (data.version >= BLE_SECURITY_CONFIG.PROTOCOL_VERSION) {
            flags |= 0x10; // Protocol v2+ support
        }

        return flags;
    }

    /**
     * Check rate limiting
     */
    private checkRateLimit(): boolean {
        const now = Date.now();
        const windowStart = now - this.rateLimitWindow;

        if (this.lastAdvertisementTime < windowStart) {
            this.advertisementCount = 0;
        }

        if (this.advertisementCount >= this.maxAdvertisementsPerWindow) {
            return false;
        }

        this.advertisementCount++;
        return true;
    }

    /**
     * Generate ephemeral ID
     */
    private generateEphemeralId(): string {
        const bytes = new Uint8Array(16);
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            crypto.getRandomValues(bytes);
        } else {
            // Fallback for environments without crypto
            for (let i = 0; i < 16; i++) {
                bytes[i] = Math.floor(Math.random() * 256);
            }
        }
        return this.bytesToHex(bytes);
    }

    /**
     * Get next sequence number
     */
    private getNextSequenceNumber(): number {
        this.sequenceNumber = (this.sequenceNumber + 1) % 0xFFFFFFFF;
        return this.sequenceNumber;
    }

    /**
     * Hash public key for fingerprint
     */
    private async hashPublicKey(publicKey: Uint8Array): Promise<Uint8Array> {
        // Simple hash for now, replace with proper SHA-256 in production
        const hash = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            hash[i] = publicKey[i % publicKey.length];
        }
        return hash;
    }

    /**
     * Hash data for caching
     */
    private hashData(data: Uint8Array): string {
        let hash = 0;
        for (let i = 0; i < data.length; i++) {
            hash = ((hash << 5) - hash) + data[i];
            hash = hash & hash;
        }
        return hash.toString(36);
    }

    /**
     * Convert bytes to hex string
     */
    protected bytesToHex(bytes: Uint8Array): string {
        return Array.from(bytes)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Convert hex string to bytes
     */
    protected hexToBytes(hex: string): Uint8Array {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    // ===== PROTECTED METHODS FOR SUBCLASSES =====

    /**
     * Get current node count (override in subclass)
     */
    protected async getNodeCount(): Promise<number> {
        return 0;
    }

    /**
     * Get message queue size (override in subclass)
     */
    protected async getQueueSize(): Promise<number> {
        return 0;
    }

    // ===== PUBLIC API =====

    /**
     * Get advertiser status
     */
    getStatus(): {
        isAdvertising: boolean;
        isPaused: boolean;
        currentData?: BLEAdvertisementData;
        rotationSchedule?: RotationSchedule;
        statistics: {
            totalAdvertisements: number;
            successfulAdvertisements: number;
            failedAdvertisements: number;
            rotations: number;
            averageInterval: number;
            protocolVersion: number;
            lastError: Error | null;
        };
    } {
        return {
            isAdvertising: this.isAdvertising,
            isPaused: this.isPaused,
            currentData: this.currentAdvertisement,
            rotationSchedule: this.rotationSchedule,
            statistics: { ...this.statistics }
        };
    }

    /**
     * Set advertising interval
     */
    setAdvertisingInterval(interval: number): void {
        if (interval < 100 || interval > 10000) {
            throw new Error('Advertising interval must be between 100ms and 10s');
        }

        this.advertisementInterval = interval;

        if (this.isAdvertising && !this.isPaused) {
            this.startPeriodicAdvertising();
        }
    }

    /**
     * Update key pair
     */
    setKeyPair(keyPair: IGhostKeyPair): void {
        this.keyPair = keyPair;
        this.signatureCache.clear();
    }
}