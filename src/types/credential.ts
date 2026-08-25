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
   * Current behavior: because re-delegation is intentionally blocked by design,
   * values above 2 are currently equivalent to 2 in practice — they still
   * allow only one delegation hop. This is forward-compatible infrastructure
   * and will matter if multi-hop delegation is enabled later.
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
