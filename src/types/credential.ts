export interface IssueCredentialOptions {
  agent: string;
  columns: string[];
  actions: 'read'[];
  expiresIn: string | number;
  metadata?: Record<string, unknown>;
  /** When true, the credential MUST be issued by the parent instance. */
  requireParent?: boolean;
  /**
   * Maximum delegation chain depth; embedded in the JWT and inherited downstream.
   * Must be a positive integer (>= 1). Defaults to 2 when omitted.
   * `issueCredential()` throws `maxDepth must be a positive integer` if a value
   * of 0, a negative number, or a non-integer (e.g. 1.5) is supplied.
   */
  maxDepth?: number;
}

export interface CredentialScope {
  database?: string;
  columns: string[];
  actions: string[];
}

export interface DelegateCredentialOptions {
  targetAgent: string;
  columns: string[];
  actions: 'read'[];
  expiresIn: string | number;
  metadata?: Record<string, unknown>;
}
