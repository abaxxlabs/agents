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
 * Scope Ceiling — session-level authorization bound for credential issuance.
 *
 * Computed once at authenticate() time from OIDC claims via RoleScopeConfig.
 * Every issueCredential() call must fit inside the ceiling or throws
 * ScopeExceedsCeilingError (REST server maps this to 403 + rejection audit record).
 *
 * Trust boundaries:
 *   - `oidcIdentity.groups` MUST come from a cryptographically verified id_token or userinfo
 *     response. The SDK does not re-verify here — that's the caller's responsibility (jwks-verify.ts).
 *   - `RoleScopeConfig` is trusted code-level configuration (loaded at server startup).
 *     It is NOT user-controllable at runtime.
 *
 * Putting the check at issuance time (not query time) matters: at query time the credential
 * already exists and can be replayed to other servers. Refusing to issue is the correct boundary.
 */

// ─── Types ─────────────────────────────────────────────────────────

/**
 * The authorization ceiling for an authenticated session.
 *
 * Semantics:
 *   - `columns: ['*']` or `actions: ['*']` means "unrestricted for that axis."
 *     Use sparingly — primarily for `mock-unrestricted` sessions in tests.
 *     Never set `['*']` for a real OIDC session without an explicit group mapping.
 *   - Empty arrays (`[]`) mean "no access granted." Requests will always fail.
 *   - Otherwise the arrays are literal allow-lists.
 *
 * The ceiling carries `source` and `resolvedFrom` so audit records can answer
 * "why was this session allowed to issue that credential?" after the fact.
 */
export interface ScopeCeiling {
  /** Columns the session may issue credentials for. `['*']` = unrestricted. */
  columns: string[];
  /** Actions the session may issue credentials for. `['*']` = unrestricted. */
  actions: string[];
  /**
   * Where the ceiling came from.
   * - `oidc-claims` — read directly from `scope_columns` / `scope_actions`
   *   OIDC token claims (the Keycloak-native path, primary for the demo)
   * - `oidc-groups` — derived from the `groups` claim via a RoleScopeConfig
   *   mapping table (fallback for IdPs that emit groups but not scope arrays)
   * - `mock-unrestricted` — test/mock sessions, wildcard `['*']` on both axes
   */
  source:
    | 'oidc-claims'
    | 'oidc-groups'
    | 'oidc-google-directory'
    | 'oidc-microsoft-roles'
    | 'oidc-abaxxone'
    | 'mock-unrestricted';
  /**
   * The specific group names (or equivalent identifiers) that resolved to
   * this ceiling. Empty for `mock-unrestricted`. Used for audit and for
   * explaining denials to the caller ("you are in groups X, Y; requested
   * action requires membership in Z").
   */
  resolvedFrom: string[];
  /**
   * Optional policy rules evaluated inside issueCredential() after scope checks pass.
   * Any rule that throws PolicyViolationError blocks issuance.
   *
   * Without this field, temporal and contextual rules would have to be enforced
   * via external wrappers that can be bypassed by holders of the original
   * session reference. Co-locating rules with the ceiling means there is no
   * unwrapped session that callers can hold onto.
   */
  rules?: IssuanceRule[];
}

/**
 * Maps role/group names to their granted scope. Multiple groups produce a UNION ceiling —
 * friendlier for admins who accumulate roles rather than replace them.
 */
export type RoleScopeConfig = Record<
  string,
  {
    columns: string[];
    actions: string[];
  }
>;

/**
 * A scope request, as submitted by a caller wanting to issue a credential.
 * Shape matches the `columns` + `actions` subset of `IssueCredentialOptions`
 * (see types.ts) so callers can pass the options directly.
 */
export interface RequestedScope {
  columns: string[];
  actions: string[];
}

// ─── Issuance Policy ───────────────────────────────────────────────

/**
 * Thrown by an IssuanceRule when it blocks issuance.
 * Distinct from ScopeExceedsCeilingError — the scope is valid but a policy rule rejects it.
 */
export class PolicyViolationError extends Error {
  readonly code = 'POLICY_VIOLATION' as const;

  constructor(message: string) {
    super(message);
    this.name = 'PolicyViolationError';
  }
}

/**
 * Thrown by `timeOfDayRule` when a caller-supplied timezone string is not a
 * recognised IANA timezone.
 *
 * Security rationale: passing an unrecognised timezone to `Intl.DateTimeFormat`
 * produces implementation-defined behaviour (Node/V8 may silently fall back to
 * UTC, throw a RangeError, or return NaN). In all cases the policy window is
 * evaluated under the wrong timezone, potentially opening an issuance window
 * that the ceiling owner did not intend. Validation before use closes the gap.
 *
 * This is a caller error, not a configuration error — the ceiling's built-in
 * `timezone` param is code-level and under the deployer's control. This error
 * fires only for the `context.timezone` path (caller-supplied at request time).
 */
export class InvalidTimezoneError extends Error {
  readonly code = 'INVALID_TIMEZONE' as const;

  constructor(message: string) {
    super(message);
    this.name = 'InvalidTimezoneError';
  }
}

/**
 * Context passed to IssuanceRule.check() at issuance time.
 * Rules may inspect who is issuing (`humanDid`) and when (`requestedAt`).
 */
export interface IssuanceContext {
  humanDid: string;
  requestedAt: Date;
  timezone?: string;
}

/**
 * A single policy rule evaluated inside issueCredential() before the
 * credential is signed. Throw PolicyViolationError to block issuance.
 */
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

/**
 * Validate a caller-supplied IANA timezone before use.
 * An unrecognized timezone causes Intl.DateTimeFormat to behave unexpectedly,
 * potentially shifting the policy window. Defers to the runtime's ICU database —
 * a hard-coded allowlist rots across Node/ICU versions.
 */
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
 * Built-in rule: block credential issuance at and after `blockFromHour` (0–23, inclusive).
 *
 * Example — block at and after 18:00 Toronto time:
 *   rules: [timeOfDayRule(18, 'America/Toronto')]
 *
 * @param blockFromHour  Hour at which issuance is blocked (18 → blocks 18:00 and later).
 * @param timezone       IANA timezone name. Defaults to the Node process locale.
 * @param _clock         Override the clock for testing only — returns current hour (0–23).
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

/**
 * Thrown when a caller requests scope beyond their session ceiling.
 * The REST server maps this to 403 SCOPE_EXCEEDS_CEILING.
 * Callers should produce an audit record on each throw.
 */
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

/**
 * Extract the `groups` claim. Accepts string[] or single string.
 * Any other shape returns [] — zero authority on ambiguous claims.
 */
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
 * Resolve an OIDC identity into a ScopeCeiling using the role map.
 * Unmatched groups are silently dropped. Zero matched groups → empty ceiling (fail-closed).
 *
 * @param oidcIdentity Must carry a `claims` record from a verified token.
 * @param config       Role-to-scope mapping loaded at server startup.
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
 * Resolve a ScopeCeiling from `scope_columns` / `scope_actions` OIDC token claims.
 * Primary Keycloak-native resolver — no config table needed; the IdP is authoritative.
 * Missing or malformed claims produce an empty ceiling (fail-closed).
 */
export function resolveScopeCeilingFromClaims(identity: {
  claims: Record<string, unknown>;
}): ScopeCeiling {
  const iss = identity.claims['iss'] as string | undefined;

  // Match on exact issuer hostname — substring matching would allow provider confusion attacks.
  // An attacker-controlled issuer like "https://evil.com/accounts.google.com/" would otherwise
  // match the Google resolver. Parse as URL and match on exact hostname instead.
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

/**
 * Keycloak — reads `scope_columns` and `scope_actions` directly from
 * custom claims projected via protocol mappers.
 */
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

/**
 * Google — STUB. Google id_tokens don't carry custom attributes natively.
 * Checks for Workspace custom schema attributes (merged from userinfo) first,
 * then falls back to scope_columns/scope_actions if present.
 * For group-based scope, use resolveScopeCeiling() with an hd/group mapping.
 */
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

/**
 * Microsoft Entra ID (Azure AD) — STUB. Checks optional claims (scope_columns/scope_actions)
 * first, then falls back to `roles` claim. For group-based scope, use resolveScopeCeiling().
 */
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

/**
 * AbaxxOne — STUB. Checks for `abaxx:scope` object first, then falls back
 * to scope_columns/scope_actions. DID format handled by the provider layer.
 */
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

/**
 * Unrestricted ceiling for test/mock sessions. NOT used by production OIDC paths.
 * The `source: 'mock-unrestricted'` field prevents confusion with a legitimately broad ceiling.
 */
export function unrestrictedCeiling(): ScopeCeiling {
  return {
    columns: ['*'],
    actions: ['*'],
    source: 'mock-unrestricted',
    resolvedFrom: [],
  };
}

// ─── Enforcement ───────────────────────────────────────────────────

/**
 * Check whether a requested scope fits inside a ceiling.
 * `['*']` ceiling accepts any request on that axis (test-only escape hatch).
 * Returns a tagged union so callers can produce a rejection audit record with the exact excess.
 */
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
 * Assert a requested scope fits a ceiling or throw `ScopeExceedsCeilingError`.
 * When `context` is provided, also evaluates any `ceiling.rules` — throwing
 * `PolicyViolationError` if a rule blocks issuance.
 *
 * Callers that don't pass `context` get unchanged behavior (rules are skipped).
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
