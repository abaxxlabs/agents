import type { IDAgent } from '../agent/index.js';
export declare class Queue {
    private agent;
    private connectedDid;
    private _star;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
    });
    createPeer(): Promise<any>;
    send(node: any, topic: any, message: any): Promise<{
        ok: boolean;
        timestsamp: number;
    }>;
    publish(topic: any, message: any, relayers?: any[]): Promise<string>;
    subscribe(topic: any, cb: any): Promise<any>;
    unsubscribe(topic: any): Promise<void>;
}
//# sourceMappingURL=queue.d.ts.map