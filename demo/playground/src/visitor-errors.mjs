import { ScopeExceedsCeilingError } from '@abaxxlabs/agents';
import { AgentScopeError } from '@abaxxlabs/agents/sql';

const DOMAIN_ERROR_CODES = new Set([
  'CREDENTIAL_INVALID',
  'CREDENTIAL_EXPIRED',
  'CREDENTIAL_REVOKED',
  'CREDENTIAL_MALFORMED',
  'CREDENTIAL_REPLAYED',
  'UNKNOWN_ISSUER',
  'QUERY_REJECTED',
  'SCOPE_VIOLATION',
  'TTL_EXCEEDED',
  'UNTRUSTED_ISSUER',
  'WRONG_ORG',
  'UNAUTHORIZED',
  'PARENT_SCOPE_EXCEEDED',
]);

export function errorPayload(err) {
  return { error: err.constructor?.name ?? 'Error', message: err.message };
}

/** The shared session plane could not serve the request. */
export class SessionPlaneUnavailableError extends Error {
  constructor(message, { cause } = {}) {
    super(message);
    this.cause = cause;
  }
}

/** The request carried more than one visitor session cookie. */
export class DuplicateVisitorSessionCookieError extends Error {}

function isDomainRejection(err) {
  return (err instanceof AgentScopeError && DOMAIN_ERROR_CODES.has(err.code)) ||
    err instanceof ScopeExceedsCeilingError ||
    (err instanceof Error && err.message.startsWith('Delegation error:'));
}

export function isDelegationRejection(err) {
  return err instanceof Error && /^(Delegation error:|Agent .* not found\.|Source credential)/.test(err.message);
}

export function rejected(err, extra = {}) {
  if (!isDomainRejection(err)) throw err;
  return [403, { ...extra, ...errorPayload(err) }];
}
