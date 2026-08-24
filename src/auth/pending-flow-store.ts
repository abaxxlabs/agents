// Copyright 2026 Abaxx Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * In-process PKCE state store for OAuth 2.0 flows.
 * Uses state as the key and stores codeVerifier plus expiresAt; no OIDC nonce is stored.
 * Prevents CSRF (unknown state rejected), replay (single-use), and stale flows (10-minute default TTL).
 * This implementation is process-local; multi-instance deployments require sticky callback routing.
 */

// ─── Types ────────────────────────────────────────────────────────────────────

interface PendingFlow {
  /** The PKCE code verifier stored for this flow. Validated in consume(). */
  codeVerifier: string;
  /** Unix milliseconds when this flow expires. */
  expiresAt: number;
}

/** Default flow TTL: 10 minutes. Long enough for a human to complete the redirect. */
const DEFAULT_FLOW_TTL_MS = 10 * 60 * 1000;

// ─── PendingFlowStore ─────────────────────────────────────────────────────────

/** Tracks in-flight OAuth flows as state -> { codeVerifier, expiresAt }. One instance per provider. */
export class PendingFlowStore {
  private flows = new Map<string, PendingFlow>();
  private ttlMs: number;

  constructor(ttlMs = DEFAULT_FLOW_TTL_MS) {
    this.ttlMs = ttlMs;
  }

  /** Register a new flow. Opportunistically purges expired flows on each call. */
  register(state: string, codeVerifier: string): void {
    this.purgeExpired();
    this.flows.set(state, {
      codeVerifier,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /** Validate and consume a flow (single-use). Throws PendingFlowError on failure. */
  consume(state: string, codeVerifier: string): void {
    const flow = this.flows.get(state);
    if (!flow) {
      throw new PendingFlowError(
        'Unknown or already-used OAuth state parameter — possible CSRF attempt or expired flow. ' +
          'Restart the authorization flow.',
      );
    }

    if (Date.now() > flow.expiresAt) {
      this.flows.delete(state);
      throw new PendingFlowError(
        'OAuth authorization flow has expired. Restart the authorization flow.',
      );
    }

    if (codeVerifier !== flow.codeVerifier) {
      // Do not delete — probing attack. Let the flow expire naturally.
      throw new PendingFlowError(
        'PKCE code verifier mismatch. ' +
          'The codeVerifier passed to exchangeCode() must match the value from buildAuthorizationUrl().',
      );
    }

    this.flows.delete(state);
  }

  /** Remove all expired flows. */
  private purgeExpired(): void {
    const now = Date.now();
    for (const [state, flow] of this.flows) {
      if (now > flow.expiresAt) this.flows.delete(state);
    }
  }
}

// ─── Error Type ───────────────────────────────────────────────────────────────

/** Thrown by PendingFlowStore.consume() on validation failure. */
export class PendingFlowError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PendingFlowError';
  }
}
