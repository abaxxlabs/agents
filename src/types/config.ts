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
