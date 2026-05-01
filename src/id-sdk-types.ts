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
 * Canonical type definitions for the platform identity SDK shape.
 *
 * Both `auth/agent.ts` and `vc-verifier.ts` depend on these interfaces.
 * The contract is structural: any implementation that satisfies this shape
 * (MCP adapter, direct id-sdk, consumer-owned stub) is accepted.
 */

/** Platform VC API surface — superset of all methods used across the library. */
export interface IdSdkVcApi {
  createCredential(issuer: string, subject: string, data: unknown, type?: string): Promise<unknown>;
  signCredential(vc: unknown, options: unknown): Promise<string>;
  getSignerOptions(did: string): Promise<{
    kid: string;
    issuerDid: string;
    subjectDid: string;
    signer: (data: Uint8Array) => Promise<Uint8Array>;
  }>;
  verifyJWT(jwt: string): Promise<boolean>;
  decodeJWT(jwt: string): Promise<{
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
  }>;
  parseJWT(jwt: string): Promise<unknown>;
  createRevocableCredential(options: unknown): Promise<unknown>;
  revokeCredential(options: unknown): Promise<unknown>;
  checkCredentialStatus(options: unknown): Promise<{ revoked: boolean; suspended: boolean }>;
  EdDsaSigner(privateKey: Uint8Array): (data: Uint8Array) => Promise<Uint8Array>;
}

/** Platform DID API surface. */
export interface IdSdkDidApi {
  resolve(didUrl: string): Promise<{ didDocument: unknown; didResolutionMetadata: unknown }>;
  create(options?: unknown): Promise<unknown>;
}

/** Structural contract for the platform identity SDK instance. */
export interface IdSdkInstance {
  vc: IdSdkVcApi;
  did: IdSdkDidApi;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- agent is the loosest part of the SDK shape; any here lets MCP adapter and direct id-sdk both satisfy it
  agent: any;
  connectedDid: string;
}
