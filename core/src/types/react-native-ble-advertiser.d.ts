// mobile/src/types/react-native-ble-advertiser.d.ts
declare module 'react-native-ble-advertiser' {
    const BLEAdvertiser: {
        setServiceUUID(uuid: string): void;
        broadcast(uuid: string, data?: string | null, options?: any): Promise<void>;
        stopBroadcast(): Promise<void>;
        requestBTPermissions(): Promise<boolean>;
        checkBTPermissions(): Promise<boolean>;
        enableAdapter(): Promise<void>;
        disableAdapter(): Promise<void>;
        getAdapterState(): Promise<string>;
        isActive(): Promise<boolean>;
    };
    
    export default BLEAdvertiser;
}