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
 * Shared fixed-window rate limiter for sensitive operations.
 * Keyed by the human DID so counters are shared across REST and MCP
 * transports and cannot be reset by opening another session.
 */

import { createHash } from 'node:crypto';
import { RateLimitExceededError } from './errors.js';

export const SIGN_RATE_LIMIT = 100;
export const SIGN_RATE_WINDOW_MS = 60_000;
export const CHALLENGE_RATE_LIMIT = 30;
export const CHALLENGE_RATE_WINDOW_MS = 60_000;
export const CREDENTIAL_MINT_RATE_LIMIT = 100;
export const CREDENTIAL_MINT_RATE_WINDOW_MS = 60_000;

/** Issuance and delegation draw on one quota so neither can be used to bypass the other. */
export const CREDENTIAL_MINT_OPERATION = 'credential-mint';

export interface RateLimitCheck {
  principal: string;
  operation: string;
  limit: number;
  windowMs: number;
}

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfterSeconds?: number;
  resetAt: number;
}

export interface RateLimiter {
  check(input: RateLimitCheck): RateLimitDecision;
  sweep(maxAgeMs: number): void;
}

/** Observer for rate-limit decisions. Receives a hashed principal, never the raw value. */
export interface RateLimitTelemetrySink {
  rateLimitChecked(event: {
    operation: string;
    principalHash: string;
    allowed: boolean;
    limit: number;
    remaining: number;
    windowMs: number;
    retryAfterSeconds?: number;
    resetAt: number;
  }): void;
}

interface RateWindow {
  start: number;
  count: number;
}

export class FixedWindowRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, RateWindow>();
  #telemetry?: RateLimitTelemetrySink;

  /** Observe every decision. Emission is best-effort and never alters the outcome. */
  setTelemetrySink(sink: RateLimitTelemetrySink | undefined): void {
    this.#telemetry = sink;
  }

  protected emitTelemetry(input: RateLimitCheck, decision: RateLimitDecision): void {
    if (!this.#telemetry) return;
    try {
      this.#telemetry.rateLimitChecked({
        operation: input.operation,
        principalHash: createHash('sha256').update(input.principal).digest('hex'),
        allowed: decision.allowed,
        limit: decision.limit,
        remaining: decision.remaining,
        windowMs: input.windowMs,
        retryAfterSeconds: decision.retryAfterSeconds,
        resetAt: decision.resetAt,
      });
    } catch {
      // Operational telemetry is best-effort and must not alter rate limits.
    }
  }

  check(input: RateLimitCheck): RateLimitDecision {
    const now = Date.now();
    const key = rateLimitBucketKey(input.principal, input.operation);
    let bucket = this.buckets.get(key);
    if (!bucket || now - bucket.start > input.windowMs) {
      bucket = { start: now, count: 0 };
      this.buckets.set(key, bucket);
    }

    bucket.count++;
    const resetAt = bucket.start + input.windowMs;
    const remaining = Math.max(0, input.limit - bucket.count);
    const decision: RateLimitDecision =
      bucket.count > input.limit
        ? {
            allowed: false,
            limit: input.limit,
            remaining: 0,
            retryAfterSeconds: Math.max(1, Math.ceil((resetAt - now) / 1000)),
            resetAt,
          }
        : { allowed: true, limit: input.limit, remaining, resetAt };

    this.emitTelemetry(input, decision);
    return decision;
  }

  sweep(maxAgeMs: number): void {
    const now = Date.now();
    for (const [key, bucket] of this.buckets) {
      if (now - bucket.start > maxAgeMs) this.buckets.delete(key);
    }
  }

  size(): number {
    return this.buckets.size;
  }
}

export const defaultIdentityRateLimiter = new FixedWindowRateLimiter();

export function assertWithinRateLimit(
  limiter: RateLimiter,
  input: RateLimitCheck,
): RateLimitDecision {
  const decision = limiter.check(input);
  if (!decision.allowed) {
    throw new RateLimitExceededError(
      input.operation,
      input.limit,
      input.windowMs,
      decision.retryAfterSeconds ?? Math.ceil(input.windowMs / 1000),
    );
  }
  return decision;
}

export function rateLimitBucketKey(principal: string, operation: string): string {
  return `${principal}:${operation}`;
}
