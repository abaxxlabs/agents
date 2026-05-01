import type { IDAgent } from '../agent/index.js';
export declare class Services {
    private agent;
    private connectedDid;
    constructor(options: {
        agent: IDAgent;
        connectedDid: string;
    });
    get(payload: any): Promise<any>;
    post(payload: any): Promise<any>;
    put(payload: any): Promise<any>;
    proxy(payload: any): Promise<any>;
}
//# sourceMappingURL=services.d.ts.map