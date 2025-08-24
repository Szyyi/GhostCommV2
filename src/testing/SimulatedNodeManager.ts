// mobile/src/testing/SimulatedNodeManager.ts
import { 
    BLENode, 
    NodeCapability, 
    DeviceType, 
    VerificationStatus,
    MessageType 
} from '../../core';

export interface SimulationProfile {
    type: 'patrol' | 'base' | 'recon' | 'convoy' | 'emergency' | 'relay';
    movement: 'static' | 'mobile' | 'orbital' | 'random';
    responsePattern: 'echo' | 'tactical' | 'emergency' | 'silent';
    batteryDrain: number; // percentage per minute
}

export class SimulatedNodeManager {
    private simulatedNodes: Map<string, BLENode> = new Map();
    private messageHandlers: Map<string, (msg: string) => string> = new Map();
    private nodeProfiles: Map<string, SimulationProfile> = new Map();
    private activeIntervals: Map<string, NodeJS.Timeout> = new Map();
    private messageQueues: Map<string, string[]> = new Map();
    private nodeRelationships: Map<string, Set<string>> = new Map();

    // Military-style callsign generation
    private generateCallsign(type: string = 'standard'): string {
        const prefixes = {
            standard: ['ALPHA', 'BRAVO', 'CHARLIE', 'DELTA', 'ECHO', 'FOXTROT', 'GOLF', 'HOTEL'],
            recon: ['SCOUT', 'EAGLE', 'HAWK', 'RAVEN', 'FALCON'],
            base: ['BASE', 'OUTPOST', 'FORTRESS', 'STRONGHOLD'],
            emergency: ['MAYDAY', 'SOS', 'MEDIC', 'EVAC'],
            convoy: ['CONVOY', 'TRANSPORT', 'SUPPLY', 'LOGISTICS']
        };
        
        const selectedPrefixes = prefixes[type as keyof typeof prefixes] || prefixes.standard;
        const prefix = selectedPrefixes[Math.floor(Math.random() * selectedPrefixes.length)];
        const suffix = Math.floor(100 + Math.random() * 900);
        
        return `${prefix}-${suffix}`;
    }

    createSimulatedNode(options: {
        name?: string;
        rssi?: number;
        capabilities?: NodeCapability[];
        autoRespond?: boolean;
        profile?: SimulationProfile;
        position?: { lat: number; lon: number };
    }): BLENode {
        const id = `SIM_${Date.now().toString(36)}_${Math.random().toString(36).substr(2, 4)}`;
        const profile = options.profile || {
            type: 'patrol',
            movement: 'static',
            responsePattern: 'tactical',
            batteryDrain: 0.1
        };
        
        const node: BLENode = {
            id,
            name: options.name || this.generateCallsign(profile.type),
            identityKey: new Uint8Array(32).fill(Math.random() * 255),
            encryptionKey: new Uint8Array(32).fill(Math.random() * 255),
            isConnected: false,
            lastSeen: Date.now(),
            firstSeen: Date.now(),
            rssi: options.rssi || -65,
            verificationStatus: VerificationStatus.UNVERIFIED,
            trustScore: 50 + Math.random() * 30,
            protocolVersion: 2,
            capabilities: options.capabilities || this.getCapabilitiesForProfile(profile),
            deviceType: this.getDeviceTypeForProfile(profile),
            supportedAlgorithms: [],
            isRelay: profile.type === 'relay' || profile.type === 'base',
            bluetoothAddress: `${profile.type.toUpperCase()}:${id}`,
            batteryLevel: 70 + Math.random() * 30,
            lastRSSI: options.rssi || -65,
            canSee: undefined
        };

        this.simulatedNodes.set(id, node);
        this.nodeProfiles.set(id, profile);
        this.messageQueues.set(id, []);
        this.nodeRelationships.set(id, new Set());

        // Set up message handler based on profile
        if (options.autoRespond) {
            this.setupMessageHandler(id, node, profile);
        }

        // Start behavior simulation based on profile
        this.startNodeBehavior(id, node, profile);

        return node;
    }

    private getCapabilitiesForProfile(profile: SimulationProfile): NodeCapability[] {
        switch (profile.type) {
            case 'base':
                return [NodeCapability.RELAY, NodeCapability.STORAGE, NodeCapability.BRIDGE];
            case 'relay':
                return [NodeCapability.RELAY, NodeCapability.STORAGE];
            case 'emergency':
                return [NodeCapability.RELAY];
            default:
                return [NodeCapability.RELAY];
        }
    }

    private getDeviceTypeForProfile(profile: SimulationProfile): DeviceType {
        switch (profile.type) {
            case 'base':
            case 'relay':
                return DeviceType.DEDICATED_RELAY;
            case 'convoy':
                return DeviceType.LAPTOP;
            default:
                return DeviceType.PHONE;
        }
    }

    private setupMessageHandler(nodeId: string, node: BLENode, profile: SimulationProfile): void {
        const handlers: Record<string, (msg: string, node: BLENode) => string> = {
            echo: (msg) => `[ECHO] ${msg}`,
            
            tactical: (msg, node) => {
                const responses = [
                    `${node.name}: Roger, "${msg}"`,
                    `${node.name}: Copy that, proceeding with ${msg}`,
                    `${node.name}: Acknowledged - ${msg}`,
                    `${node.name}: 10-4, message received`,
                    `${node.name}: Wilco - ${msg}`
                ];
                return responses[Math.floor(Math.random() * responses.length)];
            },
            
            emergency: (msg, node) => {
                return `[URGENT] ${node.name}: EMERGENCY RESPONSE REQUIRED - Re: ${msg}`;
            },
            
            silent: () => ''
        };

        const handler = handlers[profile.responsePattern] || handlers.tactical;
        this.messageHandlers.set(nodeId, (msg) => handler(msg, node));
    }

    private startNodeBehavior(nodeId: string, node: BLENode, profile: SimulationProfile): void {
        // Clear any existing interval
        const existingInterval = this.activeIntervals.get(nodeId);
        if (existingInterval) {
            clearInterval(existingInterval);
        }

        const interval = setInterval(() => {
            // Update based on movement pattern
            this.updateNodePosition(node, profile);
            
            // Drain battery
            node.batteryLevel = Math.max(0, node.batteryLevel! - profile.batteryDrain);
            
            // Update last seen
            node.lastSeen = Date.now();
            
            // Check if node should go offline (battery dead or random disconnect)
            if (node.batteryLevel! <= 0 || Math.random() < 0.001) {
                node.isConnected = false;
            }
        }, 1000);

        this.activeIntervals.set(nodeId, interval);
    }

    private updateNodePosition(node: BLENode, profile: SimulationProfile): void {
        switch (profile.movement) {
            case 'mobile':
                // Simulate movement with changing RSSI
                const change = (Math.random() - 0.5) * 15;
                node.rssi = Math.max(-100, Math.min(-30, node.rssi + change));
                break;
                
            case 'orbital':
                // Simulate circular movement pattern
                const time = Date.now() / 1000;
                const baseRSSI = -65;
                const amplitude = 20;
                node.rssi = baseRSSI + amplitude * Math.sin(time * 0.1);
                break;
                
            case 'random':
                // Random walk
                if (Math.random() < 0.1) {
                    node.rssi = -40 - Math.random() * 60;
                }
                break;
                
            case 'static':
            default:
                // Minor fluctuations only
                node.rssi += (Math.random() - 0.5) * 2;
                node.rssi = Math.max(-100, Math.min(-30, node.rssi));
        }
        
        node.lastRSSI = node.rssi;
    }

    // Create a tactical squad with relationships
    createTacticalSquad(size: number = 5): BLENode[] {
        const squadNodes: BLENode[] = [];
        const squadLeader = this.createSimulatedNode({
            name: `ALPHA-LEAD`,
            rssi: -55,
            profile: {
                type: 'patrol',
                movement: 'mobile',
                responsePattern: 'tactical',
                batteryDrain: 0.05
            },
            autoRespond: true
        });
        squadNodes.push(squadLeader);

        for (let i = 1; i < size; i++) {
            const member = this.createSimulatedNode({
                name: `ALPHA-${100 + i}`,
                rssi: -60 - Math.random() * 20,
                profile: {
                    type: 'patrol',
                    movement: 'orbital',
                    responsePattern: 'tactical',
                    batteryDrain: 0.08
                },
                autoRespond: true
            });
            
            // Create relationships within squad
            this.nodeRelationships.get(squadLeader.id)?.add(member.id);
            this.nodeRelationships.get(member.id)?.add(squadLeader.id);
            
            squadNodes.push(member);
        }

        return squadNodes;
    }

    // Create a base station network
    createBaseNetwork(): BLENode[] {
        const baseNodes: BLENode[] = [];
        
        // Main base
        const mainBase = this.createSimulatedNode({
            name: 'BASE-ALPHA',
            rssi: -45,
            profile: {
                type: 'base',
                movement: 'static',
                responsePattern: 'tactical',
                batteryDrain: 0.01
            },
            autoRespond: true
        });
        baseNodes.push(mainBase);

        // Relay stations
        for (let i = 0; i < 3; i++) {
            const relay = this.createSimulatedNode({
                name: `RELAY-${200 + i}`,
                rssi: -55 - i * 10,
                profile: {
                    type: 'relay',
                    movement: 'static',
                    responsePattern: 'echo',
                    batteryDrain: 0.02
                },
                autoRespond: true
            });
            baseNodes.push(relay);
        }

        return baseNodes;
    }

    // Simulate emergency beacon
    createEmergencyBeacon(distress: boolean = true): BLENode {
        const beacon = this.createSimulatedNode({
            name: distress ? 'SOS-BEACON' : 'EVAC-READY',
            rssi: -85,
            profile: {
                type: 'emergency',
                movement: 'static',
                responsePattern: 'emergency',
                batteryDrain: 0.5 // High drain in emergency mode
            },
            autoRespond: true
        });

        beacon.batteryLevel = 25; // Low battery in emergency
        beacon.verificationStatus = VerificationStatus.TRUSTED;
        
        return beacon;
    }

    // Simulate convoy movement
    simulateConvoyMovement(convoyId: string, speed: number = 1): void {
        const convoyNodes = Array.from(this.simulatedNodes.values())
            .filter(node => node.bluetoothAddress.includes('CONVOY'));

        let position = 0;
        const interval = setInterval(() => {
            position += speed;
            
            convoyNodes.forEach((node, index) => {
                // Convoy members maintain relative positions
                const offset = index * 10;
                node.rssi = -50 - Math.abs(Math.sin((position + offset) * 0.01)) * 30;
                node.lastRSSI = node.rssi;
                
                // Lead vehicle has best signal
                if (index === 0) {
                    node.rssi = Math.max(node.rssi, -60);
                }
            });

            if (position > 1000) {
                clearInterval(interval);
            }
        }, 100);
    }

    // Queue messages for delayed delivery
    queueMessage(nodeId: string, message: string, delay: number = 0): void {
        setTimeout(() => {
            const queue = this.messageQueues.get(nodeId) || [];
            queue.push(message);
            this.messageQueues.set(nodeId, queue);
        }, delay);
    }

    // Process queued messages
    processMessageQueues(): Map<string, string[]> {
        const processedMessages = new Map<string, string[]>();
        
        this.messageQueues.forEach((queue, nodeId) => {
            if (queue.length > 0) {
                processedMessages.set(nodeId, [...queue]);
                this.messageQueues.set(nodeId, []);
            }
        });
        
        return processedMessages;
    }

    // Simulate network fragmentation
    simulateNetworkSplit(groupA: string[], groupB: string[]): void {
        groupA.forEach(nodeIdA => {
            const nodeA = this.simulatedNodes.get(nodeIdA);
            if (nodeA) {
                groupB.forEach(nodeIdB => {
                    // Make nodes in different groups unreachable
                    const nodeB = this.simulatedNodes.get(nodeIdB);
                    if (nodeB) {
                        // Simulate being out of range
                        const relationships = this.nodeRelationships.get(nodeIdA);
                        relationships?.delete(nodeIdB);
                    }
                });
            }
        });
    }

    // Get network statistics
    getNetworkStatistics(): {
        totalNodes: number;
        connectedNodes: number;
        averageRSSI: number;
        averageBattery: number;
        nodesByType: Map<string, number>;
    } {
        const nodes = Array.from(this.simulatedNodes.values());
        const connectedNodes = nodes.filter(n => n.isConnected);
        
        const nodesByType = new Map<string, number>();
        nodes.forEach(node => {
            const profile = this.nodeProfiles.get(node.id);
            const type = profile?.type || 'unknown';
            nodesByType.set(type, (nodesByType.get(type) || 0) + 1);
        });

        return {
            totalNodes: nodes.length,
            connectedNodes: connectedNodes.length,
            averageRSSI: nodes.reduce((sum, n) => sum + n.rssi, 0) / nodes.length,
            averageBattery: nodes.reduce((sum, n) => sum + (n.batteryLevel || 0), 0) / nodes.length,
            nodesByType
        };
    }

    // Cleanup
    cleanup(): void {
        this.activeIntervals.forEach(interval => clearInterval(interval));
        this.activeIntervals.clear();
        this.simulatedNodes.clear();
        this.messageHandlers.clear();
        this.nodeProfiles.clear();
        this.messageQueues.clear();
        this.nodeRelationships.clear();
    }

    // Getters
    getSimulatedNodes(): BLENode[] {
        return Array.from(this.simulatedNodes.values());
    }

    getNodeById(nodeId: string): BLENode | undefined {
        return this.simulatedNodes.get(nodeId);
    }

    handleMessage(nodeId: string, message: string): string | null {
        const handler = this.messageHandlers.get(nodeId);
        return handler ? handler(message) : null;
    }
}

export const simulationManager = new SimulatedNodeManager();