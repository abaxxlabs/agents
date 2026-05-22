export interface IssueCredentialOptions {
  agent: string;
  columns: string[];
  actions: 'read'[];
  expiresIn: string | number;
  metadata?: Record<string, unknown>;
  /** When true, the credential MUST be issued by the parent instance. */
  requireParent?: boolean;
  /** Maximum delegation chain depth; embedded in the JWT and inherited downstream. Default: 2. */
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
