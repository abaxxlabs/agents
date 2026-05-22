export { AgentScopeError } from './base.js';

export {
  CredentialInvalidError,
  CredentialExpiredError,
  CredentialRevokedError,
  CredentialMalformedError,
  UnknownIssuerError,
  CredentialReplayedError,
} from './credential.js';

export { DidResolutionFailedError } from './did.js';

export { AuthUnavailableError, DiscoveryEndpointBlockedError } from './auth.js';

export { SqliteRuntimeUnavailableError, DbConnectionFailedError } from './db.js';

export { AuditWriteFailedError } from './audit.js';

export { QueryRejectedError, ScopeViolationError, ScopeWarning } from './query.js';

export {
  type KeyRotationPhase,
  KeyRotationFailedError,
  DecryptionFailedError,
  MasterKeyMissingError,
  MasterKeyMismatchError,
} from './crypto.js';

export {
  ParentCredentialRequestFailedError,
  TtlExceededError,
  PrecisionLossError,
  CapabilityRequiresPaidTierError,
} from './business.js';
