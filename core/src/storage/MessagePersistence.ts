// mobile/src/storage/MessagePersistence.ts
// Complete offline message persistence implementation

import AsyncStorage from '@react-native-async-storage/async-storage';
import { BLEMessage, MessagePriority } from '../../../core';

const STORAGE_KEY = '@ghostcomm_offline_messages';
const MAX_STORED_MESSAGES = 1000;
const MESSAGE_EXPIRY_TIME = 7 * 24 * 60 * 60 * 1000; // 7 days

export interface PersistedMessage {
    message: BLEMessage;
    recipientId: string;
    priority: MessagePriority;
    storedAt: number;
    attempts: number;
    lastAttemptAt?: number;
}

export class MessagePersistence {
    
    /**
     * Store a message for later delivery
     */
    async storeMessage(message: BLEMessage, recipientId: string, priority: MessagePriority): Promise<void> {
        try {
            const messages = await this.getStoredMessages();
            const persisted: PersistedMessage = {
                message,
                recipientId,
                priority,
                storedAt: Date.now(),
                attempts: 0
            };
            
            messages.push(persisted);
            
            // Sort by priority and timestamp
            messages.sort((a, b) => {
                if (a.priority !== b.priority) {
                    return b.priority - a.priority; // Higher priority first
                }
                return a.storedAt - b.storedAt; // Older messages first
            });
            
            // Limit storage size
            if (messages.length > MAX_STORED_MESSAGES) {
                messages.splice(MAX_STORED_MESSAGES);
            }
            
            await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
            console.log(`💾 Stored offline message for ${recipientId} (${messages.length} total)`);
        } catch (error) {
            console.error('Failed to store message:', error);
            throw error;
        }
    }
    
    /**
     * Get all stored messages
     */
    async getStoredMessages(): Promise<PersistedMessage[]> {
        try {
            const stored = await AsyncStorage.getItem(STORAGE_KEY);
            return stored ? JSON.parse(stored) : [];
        } catch (error) {
            console.error('Failed to get stored messages:', error);
            return [];
        }
    }
    
    /**
     * Get messages for a specific recipient
     */
    async getMessagesForRecipient(recipientId: string): Promise<PersistedMessage[]> {
        const messages = await this.getStoredMessages();
        return messages.filter(m => m.recipientId === recipientId);
    }
    
    /**
     * Remove a specific message
     */
    async removeMessage(messageId: string): Promise<void> {
        try {
            const messages = await this.getStoredMessages();
            const filtered = messages.filter(m => m.message.messageId !== messageId);
            await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(filtered));
            console.log(`🗑️ Removed delivered message ${messageId}`);
        } catch (error) {
            console.error('Failed to remove message:', error);
        }
    }
    
    /**
     * Update attempt count for a message
     */
    async updateAttempts(messageId: string): Promise<void> {
        try {
            const messages = await this.getStoredMessages();
            const message = messages.find(m => m.message.messageId === messageId);
            if (message) {
                message.attempts++;
                message.lastAttemptAt = Date.now();
                await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(messages));
            }
        } catch (error) {
            console.error('Failed to update attempts:', error);
        }
    }
    
    /**
     * Clear expired messages
     */
    async clearExpiredMessages(): Promise<void> {
        try {
            const messages = await this.getStoredMessages();
            const now = Date.now();
            
            // Remove messages that have expired or are too old
            const valid = messages.filter(m => {
                // Check message TTL
                if (m.message.expiresAt && m.message.expiresAt < now) {
                    return false;
                }
                // Check storage age
                if (now - m.storedAt > MESSAGE_EXPIRY_TIME) {
                    return false;
                }
                // Check max attempts (10 attempts)
                if (m.attempts >= 10) {
                    return false;
                }
                return true;
            });
            
            if (valid.length !== messages.length) {
                await AsyncStorage.setItem(STORAGE_KEY, JSON.stringify(valid));
                console.log(`🧹 Cleaned ${messages.length - valid.length} expired messages`);
            }
        } catch (error) {
            console.error('Failed to clear expired messages:', error);
        }
    }
    
    /**
     * Get pending message count
     */
    async getPendingCount(): Promise<number> {
        const messages = await this.getStoredMessages();
        return messages.length;
    }
    
    /**
     * Get messages ready for retry (with exponential backoff)
     */
    async getMessagesForRetry(): Promise<PersistedMessage[]> {
        const messages = await this.getStoredMessages();
        const now = Date.now();
        
        return messages.filter(m => {
            if (!m.lastAttemptAt) return true; // Never attempted
            
            // Exponential backoff: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 512s
            const backoffMs = Math.min(Math.pow(2, m.attempts) * 1000, 512000);
            return now - m.lastAttemptAt > backoffMs;
        });
    }
    
    /**
     * Clear all stored messages
     */
    async clearAll(): Promise<void> {
        try {
            await AsyncStorage.removeItem(STORAGE_KEY);
            console.log('🗑️ Cleared all stored messages');
        } catch (error) {
            console.error('Failed to clear messages:', error);
        }
    }
}