/** Controls how aggressively the projection boundary enforces column access. */
export type ScopeMode = 'projection';

export interface AgentScopeConfig {
  database: {
    connectionString: string;
    poolSize?: number;
  };
  abaxxOne?: {
    tenantUrl: string;
    clientId: string;
    clientSecret?: string;
  };
  oidc?: {
    issuerUrl: string;
    clientId: string;
    clientSecret?: string;
    redirectUri?: string;
    scopes?: string[];
  };
  encryption?: {
    algorithm?: 'aes-256-gcm';
    columns?: string[];
  };
  audit?: {
    enabled?: boolean;
  };
  credential?: {
    maxTtl?: string;
    clockSkew?: string;
  };
  did?: {
    resolverCacheTtl?: string;
  };
  log?: {
    level?: 'debug' | 'info' | 'warn' | 'error';
  };
  scopeMode?: ScopeMode;
  orgBoundary?: {
    extraConsumerDomains?: readonly string[];
  };
  keystore?: {
    path?: string;
  };
  devMode?: boolean;
}
