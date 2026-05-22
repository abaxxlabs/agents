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
 * Agents++ — Configuration loader and validator
 */

import { readFileSync } from 'node:fs';
import type { AgentScopeConfig } from './types/config.js';
import { TtlExceededError } from './errors/index.js';

export type { ScopeMode, AgentScopeConfig } from './types/config.js';

const DEFAULTS: Partial<AgentScopeConfig> = {
  encryption: {
    algorithm: 'aes-256-gcm',
    columns: [],
  },
  audit: {
    enabled: true,
  },
  credential: {
    maxTtl: '24h',
    clockSkew: '5s',
  },
  did: {
    resolverCacheTtl: '5m',
  },
  log: {
    level: 'info',
  },
};

export function loadConfig(pathOrConfig: string | AgentScopeConfig): AgentScopeConfig {
  let raw: AgentScopeConfig;

  if (typeof pathOrConfig === 'string') {
    const content = readFileSync(pathOrConfig, 'utf-8');
    raw = JSON.parse(content) as AgentScopeConfig;
  } else {
    raw = pathOrConfig;
  }

  // Validate at load time so config errors surface on startup, not at first login.
  // devMode comes from config, not process.env — consumers bridge at their boundary.
  const isDevMode = raw.devMode === true;
  if (!raw.abaxxOne && !raw.oidc && !isDevMode) {
    throw new Error(
      'AgentScopeConfig requires either abaxxOne or oidc configuration. ' +
        'For local development without a real provider, pass `devMode: true` ' +
        'in the config (consumers can bridge from env at their boundary, e.g. ' +
        '`devMode: process.env.AGENTS_DEV_MODE === "true"`).',
    );
  }
  if (raw.abaxxOne && raw.oidc) {
    throw new Error('AgentScopeConfig cannot have both abaxxOne and oidc set. Choose one.');
  }

  const config: AgentScopeConfig = {
    database: {
      connectionString: raw.database.connectionString,
      poolSize: raw.database.poolSize ?? 10,
    },
    // abaxxOne is now optional — only include if present in raw config
    ...(raw.abaxxOne && {
      abaxxOne: {
        tenantUrl: raw.abaxxOne.tenantUrl,
        clientId: raw.abaxxOne.clientId,
        clientSecret: raw.abaxxOne.clientSecret,
      },
    }),
    ...(raw.oidc && {
      oidc: {
        issuerUrl: raw.oidc.issuerUrl,
        clientId: raw.oidc.clientId,
        clientSecret: raw.oidc.clientSecret,
        redirectUri: raw.oidc.redirectUri,
        scopes: raw.oidc.scopes,
      },
    }),
    encryption: {
      algorithm: raw.encryption?.algorithm ?? DEFAULTS.encryption!.algorithm,
      // masterKey is NOT on the config blob — it is passed via injections to AgentScope.create().
      // Accepting it here would re-introduce the log-leak surface (config blobs can be logged or
      // transmitted) and defeats the BYOK boundary.
      columns: raw.encryption?.columns ?? DEFAULTS.encryption!.columns,
    },
    audit: {
      enabled: raw.audit?.enabled ?? DEFAULTS.audit!.enabled,
    },
    credential: {
      maxTtl: raw.credential?.maxTtl ?? DEFAULTS.credential!.maxTtl,
      clockSkew: raw.credential?.clockSkew ?? DEFAULTS.credential!.clockSkew,
    },
    did: {
      resolverCacheTtl: raw.did?.resolverCacheTtl ?? DEFAULTS.did!.resolverCacheTtl,
    },
    log: {
      level: raw.log?.level ?? DEFAULTS.log!.level,
    },
    // Always boolean — strict `=== true` rejects truthy non-boolean inputs ('true', 1).
    devMode: raw.devMode === true,
    // Strict `path !== undefined` gate — `{ keystore: {} }` must NOT round-trip
    // as a present-but-empty object (avoids a third absent/empty/set state).
    ...(raw.keystore?.path !== undefined && {
      keystore: {
        path: raw.keystore.path,
      },
    }),
    // Filter non-string entries so downstream engines don't defend against malformed arrays.
    ...(raw.orgBoundary?.extraConsumerDomains !== undefined && {
      orgBoundary: {
        extraConsumerDomains: raw.orgBoundary.extraConsumerDomains.filter(
          (d): d is string => typeof d === 'string',
        ),
      },
    }),
    ...(raw.scopeMode !== undefined && { scopeMode: raw.scopeMode }),
  };

  return config;
}

/**
 * Parse a duration string like '30s', '5m', '24h', '1d' into milliseconds.
 */
// Bounded quantifiers ({1,20}) prevent polynomial backtracking on untrusted input (CodeQL js/polynomial-redos).
const DURATION_TOKEN_RE = /(\d{1,20}(?:\.\d{1,20})?)(ms|s|m|h|d)/g;
const MAX_DURATION_INPUT_LEN = 64;
const DURATION_UNIT_MS: Record<string, number> = {
  ms: 1,
  s: 1_000,
  m: 60_000,
  h: 3_600_000,
  d: 86_400_000,
};

// Cap at ~100 years: without it, huge inputs return Infinity or overflow Number.MAX_SAFE_INTEGER,
// silently corrupting clockSkew (unbounded skew → expired creds accepted) and setTimeout
// (clamped to 1ms at 32-bit overflow per the HTML spec). Any input above this is operator error.
const MAX_DURATION_MS = 100 * 365 * 86_400_000;

/**
 * Parse a duration string to milliseconds.
 *
 * Accepts:
 *   - Simple:    '30s', '5m', '2h', '1d'
 *   - Milliseconds: '500ms'
 *   - Fractional:  '1.5s', '0.5m'
 *   - Compound:   '1m30s', '2h15m'
 *
 * Rejects: missing unit ('90'), unknown units, duplicate units ('1m1m'),
 * negative values, durations above ~100 years, non-finite results, and any
 * string that does not fully parse.
 */
export function parseDuration(duration: string): number {
  if (duration.length > MAX_DURATION_INPUT_LEN) {
    throw new Error(
      `Duration string too long (${duration.length} chars, max ${MAX_DURATION_INPUT_LEN}).`,
    );
  }
  const matches = [...duration.matchAll(DURATION_TOKEN_RE)];

  // Must fully reconstruct the input — catches trailing garbage ('30sx') or bare numbers ('90').
  const reconstructed = matches.map((m) => m[0]).join('');
  if (matches.length === 0 || reconstructed !== duration.trim()) {
    throw new Error(
      `Invalid duration format: '${duration}'. ` +
        `Expected NN<unit> or compound (e.g. '30s', '5m', '1m30s', '500ms', '1.5s').`,
    );
  }

  const seen = new Set<string>();
  for (const [, , unit] of matches) {
    if (seen.has(unit)) {
      throw new Error(`Duplicate unit '${unit}' in duration '${duration}'.`);
    }
    seen.add(unit);
  }

  const ms = matches.reduce((acc, m) => acc + parseFloat(m[1]) * DURATION_UNIT_MS[m[2]], 0);

  if (!Number.isFinite(ms) || ms > MAX_DURATION_MS || ms < 0) {
    throw new Error(
      `Duration '${duration}' is out of range. ` +
        `Maximum is ~100 years (${MAX_DURATION_MS}ms); got ${ms}ms.`,
    );
  }

  return Math.round(ms);
}

/**
 * Convert an `expiresIn` value (string duration or integer seconds) to milliseconds.
 *
 * @param expiresIn - Duration string ('4h', '30m') or positive integer seconds.
 * @returns Milliseconds.
 * @throws {Error} if the value is not a positive integer (when numeric) or a valid duration string.
 */
export function expiresInToMs(expiresIn: string | number): number {
  if (typeof expiresIn === 'number') {
    if (!Number.isFinite(expiresIn) || expiresIn <= 0 || !Number.isInteger(expiresIn)) {
      throw new Error(`Invalid expiresIn: ${expiresIn}. Must be a positive integer (seconds).`);
    }
    return expiresIn * 1_000;
  }
  const ms = parseDuration(expiresIn);
  if (ms <= 0) {
    throw new Error(`Invalid expiresIn: ${expiresIn}. Duration must be positive.`);
  }
  return ms;
}

/**
 * Reject expiresIn values that exceed a configured maximum TTL.
 *
 * @throws {TtlExceededError} when the resolved duration exceeds maxTtlMs
 */
export function assertExpiresInBound(
  expiresIn: string | number,
  maxTtlMs: number,
): void {
  if (expiresInToMs(expiresIn) > maxTtlMs) {
    throw new TtlExceededError(maxTtlMs);
  }
}
