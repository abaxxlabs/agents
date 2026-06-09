import { AgentScopeError } from './base.js';

export class DidResolutionFailedError extends AgentScopeError {
  constructor(did: string, reason: string) {
    super('DID_RESOLUTION_FAILED', `Could not resolve ${did} — ${reason}`, { did });
    this.name = 'DidResolutionFailedError';
  }
}
