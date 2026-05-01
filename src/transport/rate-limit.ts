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
 * Shared fixed-window rate limiter for sign and challenge operations.
 * Keyed by a stable principal (e.g. session token) so counters are shared
 * across REST and MCP transports within the same session.
 */

import { RateLimitExceededError } from './errors.js';

export const SIGN_RATE_LIMIT = 100;
export const SIGN_RATE_WINDOW_MS = 60_000;
export const CHALLENGE_RATE_LIMIT = 30;
export const CHALLENGE_RATE_WINDOW_MS = 60_000;

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

interface RateWindow {
  start: number;
  count: number;
}

export class FixedWindowRateLimiter implements RateLimiter {
  private readonly buckets = new Map<string, RateWindow>();

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
    if (bucket.count > input.limit) {
      return {
        allowed: false,
        limit: input.limit,
        remaining: 0,
        retryAfterSeconds: Math.max(1, Math.ceil((resetAt - now) / 1000)),
        resetAt,
      };
    }

    return {
      allowed: true,
      limit: input.limit,
      remaining,
      resetAt,
    };
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
