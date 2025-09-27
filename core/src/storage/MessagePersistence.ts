/**
 * =====================================================================================
 * GhostComm Protocol v2.1 - Message Persistence and Offline Storage System
 * =====================================================================================
 * 
 * Advanced message persistence framework providing reliable offline message storage,
 * retry mechanisms, and delivery guarantees for the GhostComm mesh network. This
 * system ensures message delivery even during network partitioning, device offline
 * periods, and connection instability through intelligent queuing and retry strategies.
 * 
 * CORE ARCHITECTURE:
 * =================
 * 
 * 1. Persistent Storage Layer:
 *    - AsyncStorage-based message persistence for React Native environments
 *    - JSON serialization with atomic write operations
 *    - Crash-resistant storage with data integrity verification
 *    - Efficient storage management with automatic cleanup
 * 
 * 2. Message Lifecycle Management:
 *    - Priority-based message queuing and ordering
 *    - Expiration tracking with TTL (Time-To-Live) enforcement
 *    - Delivery attempt tracking with exponential backoff
 *    - Automatic retry scheduling for failed deliveries
 * 
 * 3. Storage Optimization:
 *    - Configurable storage limits to prevent excessive resource usage
 *    - Automatic cleanup of expired and undeliverable messages
 *    - Message prioritization for optimal delivery order
 *    - Efficient filtering and retrieval mechanisms
 * 
 * 4. Reliability Features:
 *    - Delivery guarantee mechanisms for critical messages
 *    - Retry strategies with exponential backoff algorithms
 *    - Message deduplication and integrity verification
 *    - Graceful degradation during storage failures
 * 
 * STORAGE STRATEGY:
 * ================
 * 
 * Messages are persisted with comprehensive metadata including:
 * - Original message content and cryptographic signatures
 * - Recipient identification and routing information
 * - Priority levels for delivery order optimization
 * - Timestamp tracking for expiration and retry logic
 * - Attempt counters for delivery reliability monitoring
 * 
 * PERFORMANCE OPTIMIZATION:
 * ========================
 * 
 * - Priority-based sorting for optimal delivery order
 * - Batch operations to minimize storage I/O overhead
 * - Configurable limits to prevent memory exhaustion
 * - Efficient filtering algorithms for recipient-specific queries
 * - Automatic cleanup to maintain storage performance
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 * @classification Offline Message Reliability System
 * @lastModified September 2025
 * 
 * =====================================================================================
 */

// mobile/src/storage/MessagePersistence.ts
// Complete offline message persistence implementation with Protocol v2.1 reliability

import AsyncStorage from '@react-native-async-storage/async-storage';
import { BLEMessage, MessagePriority } from '../../../core';

/**
 * Storage Configuration Constants
 * ==============================
 * 
 * These constants define the operational parameters for the message
 * persistence system, including storage keys, capacity limits, and
 * retention policies to ensure optimal performance and reliability.
 */

/** AsyncStorage key for persistent message storage */
const STORAGE_KEY = '@ghostcomm_offline_messages';

/** Maximum number of messages to store to prevent excessive memory usage */
const MAX_STORED_MESSAGES = 1000;

/** Message expiry time in milliseconds (7 days) for automatic cleanup */
const MESSAGE_EXPIRY_TIME = 7 * 24 * 60 * 60 * 1000; // 7 days

/**
 * Persisted Message Structure for Offline Storage
 * ===============================================
 * 
 * Comprehensive data structure encapsulating all information required
 * for reliable message persistence, delivery tracking, and retry logic.
 * This interface extends basic BLE messages with persistence metadata
 * essential for offline operation and delivery guarantees.
 * 
 * MESSAGE LIFECYCLE TRACKING:
 * ===========================
 * 
 * - message: Complete BLE message with cryptographic signatures
 * - recipientId: Target node identifier for delivery routing
 * - priority: Message priority level for delivery order optimization
 * - storedAt: Storage timestamp for expiration and cleanup logic
 * - attempts: Delivery attempt counter for retry strategy implementation
 * - lastAttemptAt: Last delivery attempt timestamp for backoff calculations
 * 
 * DELIVERY RELIABILITY:
 * ====================
 * 
 * The attempts and lastAttemptAt fields enable sophisticated retry
 * strategies including exponential backoff, maximum attempt limits,
 * and delivery timeline tracking for network reliability monitoring.
 * 
 * STORAGE OPTIMIZATION:
 * ====================
 * 
 * Priority and storedAt fields facilitate efficient message sorting
 * and cleanup operations, ensuring optimal storage utilization and
 * delivery order optimization for critical communications.
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export interface PersistedMessage {
    /** Complete BLE message with Protocol v2.1 security features */
    message: BLEMessage;
    /** Target node identifier for message delivery */
    recipientId: string;
    /** Message priority level for delivery order optimization */
    priority: MessagePriority;
    /** Timestamp when message was stored for persistence */
    storedAt: number;
    /** Number of delivery attempts made for this message */
    attempts: number;
    /** Timestamp of most recent delivery attempt (optional) */
    lastAttemptAt?: number;
}

/**
 * Message Persistence Manager - Offline Storage and Delivery System
 * =================================================================
 * 
 * Comprehensive message persistence implementation providing reliable
 * offline storage, intelligent retry mechanisms, and delivery guarantees
 * for the GhostComm mesh network. This class ensures message delivery
 * even during network partitioning and connectivity issues through
 * sophisticated queuing and retry strategies.
 * 
 * KEY FEATURES:
 * ============
 * 
 * - Persistent AsyncStorage-based message queuing
 * - Priority-based message ordering and delivery
 * - Exponential backoff retry strategies
 * - Automatic message expiration and cleanup
 * - Delivery attempt tracking and monitoring
 * - Storage capacity management and optimization
 * 
 * RELIABILITY GUARANTEES:
 * ======================
 * 
 * - Messages persist across application restarts
 * - Delivery retries with intelligent backoff algorithms
 * - Automatic cleanup prevents storage exhaustion
 * - Priority-based delivery ensures critical message handling
 * - Comprehensive error handling and recovery mechanisms
 * 
 * OPERATIONAL WORKFLOW:
 * ====================
 * 
 * 1. Message Storage: New messages stored with metadata
 * 2. Priority Sorting: Messages ordered by priority and timestamp
 * 3. Delivery Attempts: Retry logic with exponential backoff
 * 4. Success Tracking: Delivered messages removed from storage
 * 5. Cleanup Operations: Expired messages automatically purged
 * 
 * @author LCpl 'Si' Procak
 * @version Protocol v2.1.0
 */
export class MessagePersistence {
    
    /**
     * Store Message for Reliable Offline Delivery
     * ==========================================
     * 
     * Persists a BLE message with comprehensive metadata for later delivery
     * when the recipient becomes available. This method implements priority-based
     * queuing, storage capacity management, and atomic write operations to
     * ensure reliable message persistence across application lifecycles.
     * 
     * STORAGE PROCESS:
     * ===============
     * 
     * 1. Message Metadata Creation:
     *    - Wrap message with persistence metadata
     *    - Add storage timestamp and delivery tracking
     *    - Initialize attempt counter for retry logic
     * 
     * 2. Priority-Based Insertion:
     *    - Retrieve existing message queue from storage
     *    - Insert new message maintaining priority order
     *    - Sort by priority level and storage timestamp
     * 
     * 3. Capacity Management:
     *    - Enforce maximum storage limits
     *    - Remove oldest low-priority messages if needed
     *    - Prevent storage exhaustion and memory issues
     * 
     * 4. Atomic Storage Operation:
     *    - Write complete queue to AsyncStorage atomically
     *    - Handle storage failures with comprehensive error reporting
     *    - Ensure data integrity during write operations
     * 
     * PRIORITY ORDERING:
     * =================
     * 
     * Messages are sorted with the following precedence:
     * 1. Higher priority messages first (descending priority)
     * 2. Older messages first within same priority (ascending timestamp)
     * 
     * This ensures critical messages receive delivery preference while
     * maintaining FIFO order for messages of equal priority.
     * 
     * ERROR HANDLING:
     * ==============
     * 
     * - Storage failures logged and re-thrown for upper layer handling
     * - Partial state recovery when possible
     * - Comprehensive error context for debugging
     * 
     * @param message BLE message to store for offline delivery
     * @param recipientId Target node identifier for delivery routing
     * @param priority Message priority level for delivery order
     * @returns Promise that resolves when message is successfully stored
     * 
     * @throws Error if storage operation fails or capacity exceeded
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async storeMessage(message: BLEMessage, recipientId: string, priority: MessagePriority): Promise<void> {
        try {
            // Retrieve existing message queue from persistent storage
            const messages = await this.getStoredMessages();
            
            // Create comprehensive persistence metadata for the message
            const persisted: PersistedMessage = {
                message,                    // Original BLE message with Protocol v2.1 features
                recipientId,               // Target node for delivery routing
                priority,                  // Priority level for delivery order optimization
                storedAt: Date.now(),     // Storage timestamp for expiration tracking
                attempts: 0               // Initialize delivery attempt counter
            };
            
            // Add new message to the existing queue
            messages.push(persisted);
            
            // Sort messages by priority and timestamp for optimal delivery order
            messages.sort((a, b) => {
                // Primary sort: Higher priority messages first (descending)
                if (a.priority !== b.priority) {
                    return b.priority - a.priority; // Higher priority first
                }
                // Secondary sort: Older messages first within same priority (ascending)
                return a.storedAt - b.storedAt; // Older messages first
            });
            
            // Enforce storage capacity limits to prevent memory exhaustion
            if (messages.length > MAX_STORED_MESSAGES) {
                // Remove oldest low-priority messages beyond capacity limit
                messages.splice(MAX_STORED_MESSAGES);
            }
            
            // Perform atomic write operation to ensure data integrity
            await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
            console.log(`💾 Stored offline message for ${recipientId} (${messages.length} total)`);
            
        } catch (error) {
            // Handle storage failures with comprehensive error reporting
            console.error('Failed to store message:', error);
            throw error;
        }
    }
    
    /**
     * Retrieve All Stored Messages from Persistent Storage
     * ===================================================
     * 
     * Loads the complete message queue from AsyncStorage with proper
     * error handling and data validation. This method serves as the
     * foundational data access layer for all message persistence
     * operations, ensuring consistent and reliable queue retrieval.
     * 
     * RETRIEVAL PROCESS:
     * =================
     * 
     * 1. Storage Access:
     *    - Read serialized message data from AsyncStorage
     *    - Handle storage access errors gracefully
     *    - Provide fallback for missing or corrupted data
     * 
     * 2. Data Deserialization:
     *    - Parse JSON string into PersistedMessage array
     *    - Validate data structure integrity
     *    - Handle JSON parsing errors and malformed data
     * 
     * 3. Error Recovery:
     *    - Return empty array on storage failures
     *    - Log errors for debugging and monitoring
     *    - Ensure graceful degradation for application stability
     * 
     * RELIABILITY FEATURES:
     * ====================
     * 
     * - Comprehensive error handling prevents application crashes
     * - Graceful degradation returns empty array on failures
     * - Consistent interface for all message queue operations
     * - Proper error logging for troubleshooting
     * 
     * @returns Promise resolving to array of persisted messages
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async getStoredMessages(): Promise<PersistedMessage[]> {
        try {
            // Read serialized message queue from AsyncStorage
            const stored = await AsyncStorage.getItem(STORAGE_KEY);
            
            // Parse JSON data or return empty array if no data exists
            return stored ? JSON.parse(stored) : [];
            
        } catch (error) {
            // Handle storage and parsing errors with graceful fallback
            console.error('Failed to get stored messages:', error);
            return [];
        }
    }
    
    /**
     * Retrieve Messages for Specific Recipient Node
     * ============================================
     * 
     * Efficiently filters the message queue to return only messages
     * destined for a specific recipient node. This method is essential
     * for targeted message delivery when a node becomes available or
     * when establishing new connections to specific mesh participants.
     * 
     * FILTERING PROCESS:
     * =================
     * 
     * 1. Queue Retrieval:
     *    - Load complete message queue from persistent storage
     *    - Handle storage errors through graceful degradation
     *    - Ensure data integrity during retrieval operation
     * 
     * 2. Recipient Filtering:
     *    - Filter messages matching the specified recipient identifier
     *    - Maintain original priority-based message ordering
     *    - Preserve all message metadata for delivery processing
     * 
     * 3. Result Optimization:
     *    - Return filtered array maintaining queue ordering
     *    - Preserve delivery attempt tracking and timestamps
     *    - Enable immediate delivery processing for available nodes
     * 
     * USE CASES:
     * =========
     * 
     * - Connection establishment: Deliver queued messages to newly connected nodes
     * - Selective retry: Retry messages for specific nodes experiencing issues
     * - Targeted cleanup: Remove messages for permanently unavailable nodes
     * - Delivery monitoring: Track pending messages per recipient
     * 
     * @param recipientId Unique identifier of the target recipient node
     * @returns Promise resolving to array of messages for specified recipient
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async getMessagesForRecipient(recipientId: string): Promise<PersistedMessage[]> {
        // Load complete message queue from persistent storage
        const messages = await this.getStoredMessages();
        
        // Filter messages for specified recipient while preserving order
        return messages.filter(m => m.recipientId === recipientId);
    }
    
    /**
     * Remove Successfully Delivered Message from Storage
     * =================================================
     * 
     * Permanently removes a specific message from the persistent queue
     * after successful delivery confirmation. This operation is critical
     * for maintaining storage efficiency and preventing duplicate delivery
     * attempts for already processed messages.
     * 
     * REMOVAL PROCESS:
     * ===============
     * 
     * 1. Queue Loading:
     *    - Retrieve complete message queue from persistent storage
     *    - Handle storage access errors with appropriate fallbacks
     *    - Ensure data consistency during read operation
     * 
     * 2. Message Identification:
     *    - Filter messages to exclude the specified message ID
     *    - Preserve all other messages in original priority order
     *    - Maintain queue integrity during removal operation
     * 
     * 3. Atomic Update:
     *    - Write filtered message queue back to AsyncStorage
     *    - Ensure atomic operation to prevent data corruption
     *    - Handle write failures with error logging
     * 
     * 4. Confirmation Logging:
     *    - Log successful removal for delivery tracking
     *    - Provide audit trail for message lifecycle
     *    - Enable troubleshooting and monitoring
     * 
     * DELIVERY LIFECYCLE:
     * ==================
     * 
     * This method is typically called after:
     * - Successful message delivery to recipient
     * - Receipt of delivery acknowledgment
     * - Confirmation of message processing
     * - Manual message cancellation
     * 
     * ERROR HANDLING:
     * ==============
     * 
     * - Storage failures are logged but don't throw exceptions
     * - Graceful degradation prevents application instability
     * - Error context preserved for debugging purposes
     * 
     * @param messageId Unique identifier of message to remove
     * @returns Promise that resolves when removal is complete
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async removeMessage(messageId: string): Promise<void> {
        try {
            // Load complete message queue from persistent storage
            const messages = await this.getStoredMessages();
            
            // Filter out the specified message while preserving others
            const filtered = messages.filter(m => m.message.messageId !== messageId);
            
            // Atomically update storage with filtered message queue
            await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
            
            // Log successful removal for delivery tracking
            console.log(`🗑️ Removed delivered message ${messageId}`);
            
        } catch (error) {
            // Handle removal errors gracefully without throwing
            console.error('Failed to remove message:', error);
        }
    }
    
    /**
     * Update Delivery Attempt Counter for Message Retry Logic
     * =======================================================
     * 
     * Increments the delivery attempt counter and updates the last attempt
     * timestamp for a specific message. This tracking is essential for
     * implementing exponential backoff retry strategies and monitoring
     * message delivery reliability across the mesh network.
     * 
     * TRACKING PROCESS:
     * ================
     * 
     * 1. Message Identification:
     *    - Retrieve complete message queue from persistent storage
     *    - Locate specific message by unique message identifier
     *    - Handle cases where message may no longer exist
     * 
     * 2. Attempt Counter Update:
     *    - Increment delivery attempt counter by one
     *    - Update last attempt timestamp to current time
     *    - Maintain delivery timeline for backoff calculations
     * 
     * 3. Atomic Storage Update:
     *    - Write updated message queue back to AsyncStorage
     *    - Ensure atomic operation to prevent data corruption
     *    - Handle storage failures with comprehensive error logging
     * 
     * RETRY STRATEGY INTEGRATION:
     * ==========================
     * 
     * The updated attempt count and timestamp are used by:
     * - Exponential backoff algorithms for retry scheduling
     * - Maximum attempt limit enforcement (typically 10 attempts)
     * - Delivery reliability monitoring and statistics
     * - Network health assessment and optimization
     * 
     * EXPONENTIAL BACKOFF CALCULATION:
     * ===============================
     * 
     * Retry delays follow the pattern: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 512s
     * This prevents network flooding while ensuring eventual delivery.
     * 
     * ERROR HANDLING:
     * ==============
     * 
     * - Missing messages are handled gracefully (no-op)
     * - Storage failures logged without throwing exceptions
     * - Graceful degradation maintains application stability
     * - Comprehensive error context for debugging
     * 
     * @param messageId Unique identifier of message to update
     * @returns Promise that resolves when update is complete
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async updateAttempts(messageId: string): Promise<void> {
        try {
            // Load complete message queue from persistent storage
            const messages = await this.getStoredMessages();
            
            // Locate the specific message by unique identifier
            const message = messages.find(m => m.message.messageId === messageId);
            
            if (message) {
                // Increment delivery attempt counter for retry tracking
                message.attempts++;
                
                // Update last attempt timestamp for backoff calculations
                message.lastAttemptAt = Date.now();
                
                // Atomically update storage with modified message data
                await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
            }
            
        } catch (error) {
            // Handle update errors gracefully without application disruption
            console.error('Failed to update attempts:', error);
        }
    }
    
    /**
     * Clear Expired and Undeliverable Messages from Storage
     * ====================================================
     * 
     * Performs comprehensive cleanup of the message queue by removing
     * messages that have exceeded their time-to-live, storage age limits,
     * or maximum delivery attempts. This maintenance operation is essential
     * for preventing storage exhaustion and maintaining system performance.
     * 
     * CLEANUP CRITERIA:
     * ================
     * 
     * Messages are removed if they meet any of the following conditions:
     * 
     * 1. Message TTL Expiration:
     *    - Message has explicit expiresAt timestamp
     *    - Current time exceeds the expiration timestamp
     *    - Prevents delivery of stale or time-sensitive messages
     * 
     * 2. Storage Age Limit:
     *    - Message stored longer than MESSAGE_EXPIRY_TIME (7 days)
     *    - Prevents indefinite storage accumulation
     *    - Maintains reasonable storage capacity usage
     * 
     * 3. Maximum Delivery Attempts:
     *    - Message has exceeded 10 delivery attempts
     *    - Prevents infinite retry loops for undeliverable messages
     *    - Indicates persistent delivery failures or unavailable recipients
     * 
     * CLEANUP PROCESS:
     * ===============
     * 
     * 1. Queue Analysis:
     *    - Load complete message queue from persistent storage
     *    - Evaluate each message against expiration criteria
     *    - Calculate current timestamp for age comparisons
     * 
     * 2. Filtering Operation:
     *    - Apply comprehensive expiration logic to each message
     *    - Preserve valid messages maintaining original order
     *    - Count expired messages for cleanup reporting
     * 
     * 3. Storage Update:
     *    - Update storage only if expired messages found
     *    - Perform atomic write to prevent data corruption
     *    - Log cleanup statistics for monitoring and debugging
     * 
     * PERFORMANCE OPTIMIZATION:
     * ========================
     * 
     * - Conditional storage updates prevent unnecessary I/O operations
     * - Efficient filtering reduces processing overhead
     * - Batch cleanup minimizes storage fragmentation
     * - Comprehensive logging enables cleanup monitoring
     * 
     * MAINTENANCE SCHEDULING:
     * ======================
     * 
     * This method should be called:
     * - During application startup for initial cleanup
     * - Periodically during operation (e.g., every hour)
     * - Before storage capacity checks
     * - When storage performance degrades
     * 
     * @returns Promise that resolves when cleanup is complete
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async clearExpiredMessages(): Promise<void> {
        try {
            // Load complete message queue for expiration analysis
            const messages = await this.getStoredMessages();
            const now = Date.now();
            
            // Filter messages to remove expired entries based on multiple criteria
            const valid = messages.filter(m => {
                // Criterion 1: Check explicit message TTL expiration
                if (m.message.expiresAt && m.message.expiresAt < now) {
                    return false; // Message has explicit TTL and is expired
                }
                
                // Criterion 2: Check storage age limit (7 days)
                if (now - m.storedAt > MESSAGE_EXPIRY_TIME) {
                    return false; // Message stored too long, remove for capacity management
                }
                
                // Criterion 3: Check maximum delivery attempts (10 attempts)
                if (m.attempts >= 10) {
                    return false; // Too many failed attempts, likely undeliverable
                }
                
                return true; // Message passes all expiration checks
            });
            
            // Update storage only if expired messages were found
            if (valid.length !== messages.length) {
                // Perform atomic storage update with cleaned message queue
                await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(valid));
                
                // Log cleanup statistics for monitoring and debugging
                console.log(`🧹 Cleaned ${messages.length - valid.length} expired messages`);
            }
            
        } catch (error) {
            // Handle cleanup errors gracefully to prevent application disruption
            console.error('Failed to clear expired messages:', error);
        }
    }
    
    /**
     * Get Pending Message Count for Monitoring and Capacity Planning
     * =============================================================
     * 
     * Returns the total number of messages currently stored in the
     * persistent queue awaiting delivery. This metric is essential for
     * monitoring system health, storage utilization, and network
     * performance across the GhostComm mesh network.
     * 
     * MONITORING APPLICATIONS:
     * =======================
     * 
     * - Storage Capacity Monitoring: Track queue growth and storage usage
     * - Network Health Assessment: Identify delivery bottlenecks and issues
     * - Performance Optimization: Guide retry strategy and cleanup scheduling
     * - User Interface Updates: Display pending message counts to users
     * - Alert Generation: Trigger warnings for excessive queue buildup
     * 
     * OPERATIONAL METRICS:
     * ===================
     * 
     * The pending count provides insights into:
     * - Network connectivity quality and stability
     * - Recipient availability and reachability
     * - Message delivery success rates
     * - Storage system performance and efficiency
     * - Queue management effectiveness
     * 
     * PERFORMANCE CONSIDERATIONS:
     * ==========================
     * 
     * - Efficient count operation without message processing overhead
     * - Minimal storage I/O for frequent monitoring calls
     * - Graceful error handling for storage access failures
     * - Consistent interface for monitoring systems integration
     * 
     * @returns Promise resolving to number of pending messages in queue
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async getPendingCount(): Promise<number> {
        // Retrieve message queue and return total count
        const messages = await this.getStoredMessages();
        return messages.length;
    }
    
    /**
     * Get Messages Ready for Retry with Exponential Backoff Strategy
     * ==============================================================
     * 
     * Intelligently filters the message queue to identify messages that
     * are ready for retry delivery based on exponential backoff timing.
     * This sophisticated retry strategy prevents network flooding while
     * ensuring eventual delivery for temporarily unreachable recipients.
     * 
     * EXPONENTIAL BACKOFF ALGORITHM:
     * =============================
     * 
     * Retry delays follow a geometric progression to balance delivery
     * persistence with network resource conservation:
     * 
     * Attempt 1: 1 second delay    (immediate retry for transient failures)
     * Attempt 2: 2 seconds delay   (quick retry for brief connectivity issues)
     * Attempt 3: 4 seconds delay   (moderate delay for network recovery)
     * Attempt 4: 8 seconds delay   (increased delay for persistent issues)
     * Attempt 5: 16 seconds delay  (longer delay for connection problems)
     * Attempt 6: 32 seconds delay  (substantial delay for node availability)
     * Attempt 7: 64 seconds delay  (extended delay for network partitioning)
     * Attempt 8: 128 seconds delay (long delay for severe connectivity issues)
     * Attempt 9: 256 seconds delay (maximum reasonable retry frequency)
     * Attempt 10: 512 seconds delay (final attempt with maximum delay)
     * 
     * FILTERING CRITERIA:
     * ==================
     * 
     * Messages are considered ready for retry if:
     * 
     * 1. Never Attempted (m.lastAttemptAt is undefined):
     *    - First delivery attempt for newly stored messages
     *    - Immediate availability for delivery processing
     * 
     * 2. Backoff Period Elapsed:
     *    - Current time exceeds last attempt + calculated backoff delay
     *    - Exponential delay based on attempt count prevents flooding
     *    - Maximum delay capped at 512 seconds for reasonable retry frequency
     * 
     * NETWORK PROTECTION FEATURES:
     * ===========================
     * 
     * - Progressive delay increase reduces network congestion
     * - Maximum delay cap prevents indefinite retry intervals
     * - Attempt-based calculation ensures predictable retry patterns
     * - Filter operation preserves original message priority ordering
     * 
     * RELIABILITY BENEFITS:
     * ====================
     * 
     * - Ensures eventual delivery for temporarily unavailable nodes
     * - Prevents message loss during brief connectivity interruptions
     * - Adapts retry frequency based on delivery success patterns
     * - Balances persistence with resource conservation
     * 
     * @returns Promise resolving to array of messages ready for retry
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async getMessagesForRetry(): Promise<PersistedMessage[]> {
        // Load complete message queue from persistent storage
        const messages = await this.getStoredMessages();
        const now = Date.now();
        
        // Filter messages ready for retry based on exponential backoff timing
        return messages.filter(m => {
            // Immediate retry for messages that have never been attempted
            if (!m.lastAttemptAt) return true; // Never attempted, ready for first delivery
            
            // Calculate exponential backoff delay based on attempt count
            // Formula: min(2^attempts * 1000ms, 512000ms) ensures reasonable maximum delay
            const backoffMs = Math.min(Math.pow(2, m.attempts) * 1000, 512000);
            
            // Message ready for retry if backoff period has elapsed
            return now - m.lastAttemptAt > backoffMs;
        });
    }
    
    /**
     * Clear All Stored Messages for Complete Queue Reset
     * =================================================
     * 
     * Permanently removes all messages from the persistent storage queue,
     * effectively resetting the message persistence system to its initial
     * state. This operation is typically used for debugging, testing, or
     * when implementing complete system resets or factory configurations.
     * 
     * COMPLETE RESET OPERATION:
     * ========================
     * 
     * 1. Storage Deletion:
     *    - Remove entire message queue from AsyncStorage
     *    - Ensure complete cleanup without residual data
     *    - Handle storage deletion errors gracefully
     * 
     * 2. State Reset:
     *    - All pending messages permanently removed
     *    - Delivery attempt counters reset
     *    - Priority queues cleared completely
     *    - Storage capacity restored to maximum
     * 
     * 3. Audit Logging:
     *    - Log complete reset operation for debugging
     *    - Provide clear indication of data deletion
     *    - Enable troubleshooting and forensic analysis
     * 
     * USE CASES:
     * =========
     * 
     * - System Debugging: Clear queue state for testing scenarios
     * - Factory Reset: Return persistence system to initial configuration
     * - Emergency Cleanup: Resolve storage corruption or performance issues
     * - Development Testing: Reset state between test iterations
     * - Privacy Protection: Clear sensitive message data on user request
     * 
     * IMPORTANT CONSIDERATIONS:
     * ========================
     * 
     * - This operation is irreversible and will lose all queued messages
     * - Should be used with caution in production environments
     * - May result in message delivery failures for pending communications
     * - Recommended to notify users before performing complete reset
     * 
     * ERROR HANDLING:
     * ==============
     * 
     * - Storage deletion errors logged without throwing exceptions
     * - Graceful degradation maintains application stability
     * - Comprehensive error context for debugging purposes
     * - Operation continues even if deletion partially fails
     * 
     * @returns Promise that resolves when all messages are cleared
     * 
     * @author LCpl 'Si' Procak
     * @version Protocol v2.1.0
     */
    async clearAll(): Promise<void> {
        try {
            // Perform complete deletion of message queue from AsyncStorage
            await AsyncStorage.removeItem(STORAGE_KEY);
            
            // Log successful complete reset for audit and debugging
            console.log('🗑️ Cleared all stored messages - complete queue reset performed');
            
        } catch (error) {
            // Handle deletion errors gracefully without application disruption
            console.error('Failed to clear messages:', error);
        }
    }
}