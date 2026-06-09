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
 * Session-level authorization bound for credential issuance.
 * Checked at issuance time, not query time -- once a credential exists it can be replayed.
 * Trust boundary: oidcIdentity.groups MUST come from a cryptographically verified id_token.
 * RoleScopeConfig is trusted startup-loaded config, NOT runtime-user-controllable.
 */

// ─── Types ─────────────────────────────────────────────────────────

/** Authorization ceiling for an authenticated session. `['*']` = unrestricted (test only). `[]` = no access. */
export interface ScopeCeiling {
  /** Columns the session may issue credentials for. `['*']` = unrestricted. */
  columns: string[];
  /** Actions the session may issue credentials for. `['*']` = unrestricted. */
  actions: string[];
  /** How the ceiling was resolved -- drives audit trail. */
  source:
    | 'oidc-claims'
    | 'oidc-groups'
    | 'oidc-google-directory'
    | 'oidc-microsoft-roles'
    | 'oidc-abaxxone'
    | 'mock-unrestricted';
  /** Group names or identifiers that produced this ceiling. Empty for mock sessions. */
  resolvedFrom: string[];
  /** Policy rules evaluated at issuance time. Co-located with the ceiling so callers can't bypass them. */
  rules?: IssuanceRule[];
  /** Max credential TTL in milliseconds. Enforced at issuance time across all paths. */
  credentialMaxTtlMs?: number;
}

/** Maps role/group names to granted scope. Multiple groups produce a UNION ceiling. */
export type RoleScopeConfig = Record<
  string,
  {
    columns: string[];
    actions: string[];
  }
>;

/** Scope request submitted by a caller wanting to issue a credential. */
export interface RequestedScope {
  columns: string[];
  actions: string[];
}

// ─── Issuance Policy ───────────────────────────────────────────────

/** Thrown by an IssuanceRule. Distinct from ScopeExceedsCeilingError -- scope is valid but policy rejects. */
export class PolicyViolationError extends Error {
  readonly code = 'POLICY_VIOLATION' as const;

  constructor(message: string) {
    super(message);
    this.name = 'PolicyViolationError';
  }
}

/**
 * Thrown when a caller-supplied timezone is not a recognized IANA timezone.
 * Unrecognized timezones cause implementation-defined behavior that could shift the policy window.
 */
export class InvalidTimezoneError extends Error {
  readonly code = 'INVALID_TIMEZONE' as const;

  constructor(message: string) {
    super(message);
    this.name = 'InvalidTimezoneError';
  }
}

/** Context passed to IssuanceRule.check() at issuance time. */
export interface IssuanceContext {
  humanDid: string;
  requestedAt: Date;
  timezone?: string;
}

/** Policy rule evaluated before credential signing. Throw PolicyViolationError to block issuance. */
export interface IssuanceRule {
  type: string;
  check(context: IssuanceContext): void;
}

function resolveHourFromDate(date: Date, timezone?: string): number {
  if (!timezone) return date.getHours();
  const raw = parseInt(
    new Intl.DateTimeFormat('en-US', {
      hour: 'numeric',
      hour12: false,
      timeZone: timezone,
    }).format(date),
    10,
  );
  return raw === 24 ? 0 : raw;
}

/** Validate a caller-supplied timezone. Defers to runtime ICU -- no hardcoded allowlist. */
function assertValidTimezone(tz: string | undefined): void {
  if (!tz) return;
  try {
    // Discard the instance — we only care that construction doesn't throw.
    void new Intl.DateTimeFormat(undefined, { timeZone: tz });
  } catch {
    throw new InvalidTimezoneError(`Unsupported IANA timezone: ${tz}`);
  }
}

/**
 * Block credential issuance at and after `blockFromHour` (0-23, inclusive).
 * @param blockFromHour Hour at which issuance is blocked.
 * @param timezone IANA timezone name. Defaults to process locale.
 */
export function timeOfDayRule(
  blockFromHour: number,
  timezone?: string,
  _clock?: () => number,
): IssuanceRule {
  return {
    type: 'time-of-day',
    check({ requestedAt, timezone: ctxTz }) {
      assertValidTimezone(ctxTz); // only caller-supplied tz is validated (code-level tz is deployer-controlled)

      // Ceiling's configured timezone takes priority — callers cannot shift the policy window.
      const tz = timezone ?? ctxTz;
      const hour = _clock ? _clock() : resolveHourFromDate(requestedAt, tz);
      if (hour >= blockFromHour) {
        throw new PolicyViolationError(
          `Credential issuance not permitted at or after ${blockFromHour}:00` +
            (tz ? ` (${tz})` : ''),
        );
      }
    },
  };
}

// ─── Errors ────────────────────────────────────────────────────────

/** Thrown when requested scope exceeds the session ceiling. Maps to 403 in the REST server. */
export class ScopeExceedsCeilingError extends Error {
  readonly code = 'SCOPE_EXCEEDS_CEILING' as const;
  readonly ceiling: ScopeCeiling;
  readonly requested: RequestedScope;
  readonly excess: { columns: string[]; actions: string[] };

  constructor(
    ceiling: ScopeCeiling,
    requested: RequestedScope,
    excess: { columns: string[]; actions: string[] },
  ) {
    const parts: string[] = [];
    if (excess.columns.length > 0) {
      parts.push(`columns [${excess.columns.join(', ')}]`);
    }
    if (excess.actions.length > 0) {
      parts.push(`actions [${excess.actions.join(', ')}]`);
    }
    const groupsNote =
      ceiling.resolvedFrom.length > 0
        ? ` (session authenticated with groups: ${ceiling.resolvedFrom.join(', ')})`
        : '';
    super(
      `Requested scope exceeds session ceiling: ${parts.join(' and ')}${groupsNote}. ` +
        `Ceiling columns: [${ceiling.columns.join(', ')}], actions: [${ceiling.actions.join(', ')}].`,
    );
    this.name = 'ScopeExceedsCeilingError';
    this.ceiling = ceiling;
    this.requested = requested;
    this.excess = excess;
  }
}

// ─── Resolution ────────────────────────────────────────────────────

/** Extract `groups` claim as string[]. Non-array/non-string shapes return [] (fail-closed). */
function extractGroups(claims: Record<string, unknown>): string[] {
  const raw = claims['groups'];
  if (Array.isArray(raw)) {
    return raw.filter((g): g is string => typeof g === 'string');
  }
  if (typeof raw === 'string' && raw.length > 0) {
    return [raw];
  }
  return [];
}

/**
 * Resolve a ScopeCeiling from OIDC groups via a role map.
 * Unmatched groups are dropped. Zero matches produce an empty ceiling (fail-closed).
 */
export function resolveScopeCeiling(
  oidcIdentity: { claims: Record<string, unknown> },
  config: RoleScopeConfig,
): ScopeCeiling {
  const groups = extractGroups(oidcIdentity.claims);

  const columns = new Set<string>();
  const actions = new Set<string>();
  const resolvedFrom: string[] = [];

  for (const group of groups) {
    const entry = config[group];
    if (!entry) continue;
    resolvedFrom.push(group);
    // Strip literal wildcard — a config '*' must not silently produce an unrestricted ceiling.
    for (const col of entry.columns) {
      if (col !== '*') columns.add(col);
    }
    for (const act of entry.actions) {
      if (act !== '*') actions.add(act);
    }
  }

  return {
    columns: Array.from(columns),
    actions: Array.from(actions),
    source: 'oidc-groups',
    resolvedFrom,
  };
}

/**
 * Resolve a ScopeCeiling from OIDC token claims. Routes to the correct provider-specific
 * resolver based on issuer hostname. Missing or malformed claims produce an empty ceiling.
 */
export function resolveScopeCeilingFromClaims(identity: {
  claims: Record<string, unknown>;
}): ScopeCeiling {
  const iss = identity.claims['iss'] as string | undefined;

  // Exact hostname match -- substring matching allows evil.com/accounts.google.com/ to impersonate Google.
  if (iss) {
    try {
      const issuerHostname = new URL(iss).hostname;
      if (issuerHostname === 'accounts.google.com') {
        return resolveGoogleCeiling(identity.claims);
      }
      if (issuerHostname === 'login.microsoftonline.com' || issuerHostname === 'sts.windows.net') {
        return resolveMicrosoftCeiling(identity.claims);
      }
      if (issuerHostname.endsWith('.abaxx.tech') || issuerHostname === 'abaxxone.com') {
        return resolveAbaxxOneCeiling(identity.claims);
      }
    } catch {
      // Invalid URL in iss — fall through to Keycloak default (fail-closed).
    }
  }

  return resolveKeycloakCeiling(identity.claims);
}

/** Keycloak -- reads scope_columns/scope_actions from custom protocol mapper claims. */
function resolveKeycloakCeiling(claims: Record<string, unknown>): ScopeCeiling {
  const rawCols = claims['scope_columns'];
  const rawActs = claims['scope_actions'];

  const columns = Array.isArray(rawCols)
    ? rawCols.filter((c): c is string => typeof c === 'string' && c !== '*')
    : [];
  const actions = Array.isArray(rawActs)
    ? rawActs.filter((a): a is string => typeof a === 'string' && a !== '*')
    : [];

  const resolvedFrom: string[] = [];
  if ('scope_columns' in claims) resolvedFrom.push('scope_columns');
  if ('scope_actions' in claims) resolvedFrom.push('scope_actions');

  return { columns, actions, source: 'oidc-claims', resolvedFrom };
}

/** Google Workspace -- checks custom schema attributes first, falls back to scope_columns. */
function resolveGoogleCeiling(claims: Record<string, unknown>): ScopeCeiling {
  // Check for Google Workspace custom schema attributes (merged from userinfo)
  const customSchemas = claims['customSchemas'] as
    | Record<string, Record<string, unknown>>
    | undefined;
  const agentIdSchema = customSchemas?.['agent_id'] ?? customSchemas?.['agentId'];
  if (agentIdSchema) {
    const columns = extractStringArray(agentIdSchema['scope_columns']);
    const actions = extractStringArray(agentIdSchema['scope_actions']);
    return {
      columns: columns.filter((c) => c !== '*'),
      actions: actions.filter((a) => a !== '*'),
      source: 'oidc-google-directory',
      resolvedFrom: ['customSchemas.agent_id'],
    };
  }

  const ceiling = resolveKeycloakCeiling(claims);
  if (ceiling.columns.length > 0 || ceiling.actions.length > 0) {
    return {
      ...ceiling,
      source: 'oidc-google-directory',
      resolvedFrom: [...ceiling.resolvedFrom, 'google-fallback'],
    };
  }

  return { columns: [], actions: [], source: 'oidc-google-directory', resolvedFrom: [] };
}

/** Microsoft Entra ID -- checks optional scope claims first, falls back to `roles`. */
function resolveMicrosoftCeiling(claims: Record<string, unknown>): ScopeCeiling {
  const ceiling = resolveKeycloakCeiling(claims);
  if (ceiling.columns.length > 0 || ceiling.actions.length > 0) {
    return {
      ...ceiling,
      source: 'oidc-microsoft-roles',
      resolvedFrom: [...ceiling.resolvedFrom, 'optional-claims'],
    };
  }

  // Entra app roles — `roles` claim contains role value strings from the app manifest.
  const roles = extractStringArray(claims['roles']);
  if (roles.length > 0) {
    return {
      columns: [],
      actions: [],
      source: 'oidc-microsoft-roles',
      resolvedFrom: roles.map((r) => `role:${r}`),
    };
  }

  return { columns: [], actions: [], source: 'oidc-microsoft-roles', resolvedFrom: [] };
}

/** AbaxxOne -- checks `abaxx:scope` object first, falls back to scope_columns. */
function resolveAbaxxOneCeiling(claims: Record<string, unknown>): ScopeCeiling {
  const abaxxScope = claims['abaxx:scope'] as { columns?: unknown; actions?: unknown } | undefined;
  if (abaxxScope) {
    const columns = extractStringArray(abaxxScope.columns).filter((c) => c !== '*');
    const actions = extractStringArray(abaxxScope.actions).filter((a) => a !== '*');
    return {
      columns,
      actions,
      source: 'oidc-abaxxone',
      resolvedFrom: ['abaxx:scope'],
    };
  }

  const ceiling = resolveKeycloakCeiling(claims);
  if (ceiling.columns.length > 0 || ceiling.actions.length > 0) {
    return { ...ceiling, source: 'oidc-abaxxone' };
  }

  return { columns: [], actions: [], source: 'oidc-abaxxone', resolvedFrom: [] };
}

/** Safely extract a string[] from an unknown value. */
function extractStringArray(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === 'string');
  if (typeof raw === 'string' && raw.length > 0) return [raw];
  return [];
}

/** Unrestricted ceiling for test/mock sessions. Not used by production OIDC paths. */
export function unrestrictedCeiling(): ScopeCeiling {
  return {
    columns: ['*'],
    actions: ['*'],
    source: 'mock-unrestricted',
    resolvedFrom: [],
  };
}

// ─── Enforcement ───────────────────────────────────────────────────

/** Check whether a requested scope fits inside a ceiling. Returns the exact excess on failure. */
export function scopeFitsInCeiling(
  requested: RequestedScope,
  ceiling: ScopeCeiling,
): { ok: true } | { ok: false; excess: { columns: string[]; actions: string[] } } {
  const colCeiling = new Set(ceiling.columns);
  const actCeiling = new Set(ceiling.actions);
  const colWild = colCeiling.has('*');
  const actWild = actCeiling.has('*');

  const excessCols: string[] = [];
  for (const col of new Set(requested.columns)) {
    if (!colWild && !colCeiling.has(col)) excessCols.push(col);
  }

  const excessActs: string[] = [];
  for (const act of new Set(requested.actions)) {
    if (!actWild && !actCeiling.has(act)) excessActs.push(act);
  }

  if (excessCols.length === 0 && excessActs.length === 0) {
    return { ok: true };
  }
  return {
    ok: false,
    excess: { columns: excessCols, actions: excessActs },
  };
}

/**
 * Assert scope fits ceiling or throw. When `context` is provided, also evaluates ceiling.rules.
 */
export function assertScopeFitsInCeiling(
  requested: RequestedScope,
  ceiling: ScopeCeiling,
  context?: IssuanceContext,
): void {
  const result = scopeFitsInCeiling(requested, ceiling);
  if (!result.ok) {
    throw new ScopeExceedsCeilingError(ceiling, requested, result.excess);
  }
  if (context && ceiling.rules && ceiling.rules.length > 0) {
    for (const rule of ceiling.rules) {
      rule.check(context);
    }
  }
}
