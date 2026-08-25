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

import { decodeJwt } from '#crypto/jwt.js';
import { createPresentation, VcVerifier } from '#identity/index.js';
import type { DidAliasRegistry } from '#did/alias.js';
import type { AgentStore } from '#storage/types.js';
import type { RegisteredAgent } from '#types/auth.js';
import {
  CredentialInvalidError,
  CredentialExpiredError,
  CredentialRevokedError,
  CredentialMalformedError,
  UnknownIssuerError,
  CredentialReplayedError,
} from '#errors/index.js';

export interface QueryAuthorizerOptions {
  verifier: VcVerifier;
  agents: Map<string, RegisteredAgent>;
  verifierDid: string;
  didAliases?: DidAliasRegistry;
  agentStore: AgentStore;
}

export interface AuthorizationInput {
  agent: string;
  credential: string;
  credentials?: string[];
  requirePresentation?: boolean;
}

export interface AuthorizationResult {
  ownerDid: string;
  readColumns: Set<string>;
  /** Qualified column name to the actions the presented credentials grant on it. */
  columnActions: Map<string, Set<string>>;
  scopeColumns: string[];
  allJwts: string[];
}

/**
 * Single authorization boundary for scoped queries. Verifies every presented
 * credential (VP-wrapped), binds it to the requesting agent, validates owner
 * and delegation chains, enforces issuer consistency across the union, and
 * accumulates the column/action scope.
 */
export class QueryAuthorizer {
  private verifier: VcVerifier;
  private agents: Map<string, RegisteredAgent>;
  private verifierDid: string;
  private didAliases?: DidAliasRegistry;
  private agentStore: AgentStore;

  constructor(options: QueryAuthorizerOptions) {
    this.verifier = options.verifier;
    this.agents = options.agents;
    this.verifierDid = options.verifierDid;
    this.didAliases = options.didAliases;
    this.agentStore = options.agentStore;
  }

  /**
   * Alias-aware DID comparison. Falls back to strict === when no alias
   * registry is configured.
   */
  private didsMatch(a: string, b: string): boolean {
    if (a === b) return true;
    return this.didAliases?.didsMatch(a, b) ?? false;
  }

  async authorize(input: AuthorizationInput): Promise<AuthorizationResult> {
    const { agent, credential, credentials, requirePresentation } = input;

    if (!credential) {
      throw new CredentialMalformedError('No credential provided');
    }

    const allJwts = [credential, ...(credentials ?? [])];

    // W3C VP wrapping: raw VCs are wrapped in a Verifiable Presentation
    // before verification. This ensures replay protection applies to the
    // VP nonce (per-query, ephemeral) rather than the VC JTI (per-credential,
    // long-lived). The VC remains reusable across queries — each query
    // creates a fresh VP wrapping the same VC.
    //
    // The agent's signer is looked up from the agents map. If the agent
    // isn't registered (shouldn't happen — createAgent precedes query),
    // the raw VC is passed through for backward compatibility.
    const agentRec = this.agents.get(agent);
    const columnActions: Map<string, Set<string>> = new Map();
    let ownerDid = '';

    for (const jwt of allJwts) {
      let jwtToVerify = jwt;

      const decoded = decodeJwt(jwt);
      const vpClaim = decoded.payload.vp as { type?: string[] } | undefined;
      const isAlreadyVP = vpClaim?.type?.includes?.('VerifiablePresentation');
      if (!isAlreadyVP && requirePresentation) {
        throw new CredentialInvalidError(
          agent,
          'Remote query paths require a Verifiable Presentation signed by the agent; raw credentials are bearer tokens.',
        );
      }
      if (!isAlreadyVP && agentRec?.signer) {
        jwtToVerify = await createPresentation(jwt, agent, agentRec.signer, {
          audience: this.verifierDid,
        });
      }

      const result = await this.verifier.verify(jwtToVerify, {
        expectedAudience: this.verifierDid,
      });

      if (!result.valid) {
        switch (result.status) {
          case 'INVALID_SIGNATURE':
            throw new CredentialInvalidError(agent, result.error);
          case 'EXPIRED':
            throw new CredentialExpiredError(agent, result.credential?.expiresAt ?? new Date());
          case 'REVOKED':
          case 'SUSPENDED':
            throw new CredentialRevokedError(
              'unknown',
              result.credential?.issuer ?? 'unknown',
              result.status === 'SUSPENDED',
            );
          case 'UNKNOWN_ISSUER':
            throw new UnknownIssuerError(result.credential?.issuer ?? 'unknown', result.error);
          case 'REPLAYED': {
            const decoded = decodeJwt(jwt);
            throw new CredentialReplayedError(agent, decoded.payload.jti ?? 'unknown');
          }
          case 'WRONG_SUBJECT':
            // Credential is cryptographically valid but was issued for a different agent.
            // Distinct from INVALID_SIGNATURE — the key is correct, the binding is wrong.
            // Use CredentialInvalidError (not CredentialMalformedError) so callers debug
            // authorization, not key rotation.
            throw new CredentialInvalidError(
              agent,
              result.error ?? 'Credential issued for wrong agent',
            );
          case 'WRONG_AUDIENCE':
            throw new CredentialInvalidError(
              agent,
              result.error ?? 'VP audience does not match this server',
            );
          case 'POLICY_VIOLATION':
            throw new CredentialInvalidError(
              agent,
              result.error ?? 'Delegation chain exceeds maximum depth',
            );
          case 'MALFORMED':
          default:
            throw new CredentialMalformedError(result.error ?? 'Unknown error');
        }
      }

      // Verify the credential is for this agent. Uses didsMatch() because
      // during the migration grace period, agent credentials issued under
      // the old DID must still be accepted when the agent presents with its
      // new DID.
      if (!this.didsMatch(result.credential!.subject!, agent)) {
        throw new CredentialInvalidError(
          agent,
          `Credential subject ${result.credential!.subject} does not match agent ${agent}`,
        );
      }

      // Verify the credential issuer is the agent's registered owner.
      // The in-memory agents Map may not have the agent (e.g., after restart),
      // so fall back to the database. The guard must NOT silently pass on
      // cache miss — without the DB fallback, the owner check would skip
      // entirely whenever `agents.get()` returns undefined.
      let ownerAgent = this.agents.get(agent);
      if (!ownerAgent) {
        // Cache miss — load from storage layer to ensure owner binding survives restarts.
        // Uses AgentStore.findByDid() instead of direct pool.query to keep ScopeEngine
        // decoupled from SQL for metadata reads (pool is used solely for data-plane queries).
        try {
          const record = await this.agentStore.findByDid(agent);
          if (record) {
            ownerAgent = {
              did: record.did,
              name: record.name,
              ownerDid: record.ownerDid,
            } as RegisteredAgent;
          }
        } catch (dbErr) {
          // Fail closed. A storage error silently skipping the owner check is a
          // security downgrade — propagate so the query is rejected.
          throw new CredentialInvalidError(
            agent,
            `Agent owner lookup failed — ${dbErr instanceof Error ? dbErr.message : 'database error'}. Cannot verify credential issuer.`,
          );
        }
      }
      if (!ownerAgent) {
        throw new CredentialInvalidError(
          agent,
          `Agent ${agent} is not registered. Cannot verify credential issuer without a known owner binding.`,
        );
      }
      const isThisDelegated =
        result.credential!.vcTypes?.includes('DelegatedAgentScopeCredential') ?? false;

      if (!this.didsMatch(result.credential!.issuer, ownerAgent.ownerDid)) {
        // If this is a delegated credential, walk the delegation chain instead
        // of rejecting outright. A delegated credential has iss = delegator
        // agent DID (not the human owner). The chain must prove:
        // human owner → delegator agent → this credential.
        const chain = result.credential!.delegationChain;
        if (!isThisDelegated || !chain || chain.length === 0) {
          throw new CredentialInvalidError(
            agent,
            `Credential issuer ${result.credential!.issuer} is not the registered owner of agent ${agent}`,
          );
        }

        // Verify the source credential in the chain. One level only — nested
        // delegation is not supported. The source VC must be:
        //   1. Cryptographically valid (signature, expiry, revocation)
        //   2. Issued by the human owner (source.issuer === ownerAgent.ownerDid)
        //   3. Issued TO the delegator (source.subject === delegated.issuer)
        const sourceJwt = chain[0];
        const sourceResult = await this.verifier.verify(sourceJwt, {
          expectedSubject: result.credential!.issuer,
        });
        if (!sourceResult.valid) {
          throw new CredentialInvalidError(
            agent,
            `Delegation chain invalid: source credential verification failed — ` +
              `${sourceResult.status}: ${sourceResult.error ?? 'unknown'}`,
          );
        }
        if (!this.didsMatch(sourceResult.credential!.issuer, ownerAgent.ownerDid)) {
          throw new CredentialInvalidError(
            agent,
            `Delegation chain invalid: source credential issuer ` +
              `${sourceResult.credential!.issuer} is not the registered owner ` +
              `(${ownerAgent.ownerDid}) of the delegating agent`,
          );
        }
      }

      // Delegated credentials cannot be unioned — combining narrow delegations
      // reconstructs wider access than any single delegation authorized.
      if (isThisDelegated && allJwts.length > 1) {
        throw new CredentialInvalidError(
          agent,
          `Delegated credentials cannot be combined in a scope union. ` +
            `A worker must hold a single credential listing all authorized columns; ` +
            `it cannot recombine narrow delegations to construct wider access.`,
        );
      }

      // Issuer consistency check — all credentials in a multi-VC query must
      // come from the same issuer to prevent scope union across different issuers.
      const thisIssuer = result.credential!.issuer;
      if (!ownerDid) {
        ownerDid = thisIssuer;
      } else if (!this.didsMatch(thisIssuer, ownerDid)) {
        throw new CredentialInvalidError(
          agent,
          `Credential issuer ${thisIssuer} does not match first credential's issuer ${ownerDid}. ` +
            `All credentials in a scope union must come from the same issuer.`,
        );
      }

      // scope is Optional on DecodedCredential (IdentityBindingCredentials carry no scope).
      // The verify() call above with no skipScopeCheck means MALFORMED is returned for
      // capability credentials missing scope — but guard defensively at the access site.
      if (!result.credential!.scope?.columns) {
        throw new CredentialMalformedError(
          'Credential missing scope.columns — cannot compute query scope',
        );
      }
      // Actions can be missing (legacy/bug); must default to []
      const actions: string[] = result.credential!.scope?.actions || [];
      for (const col of result.credential!.scope.columns) {
        if (!columnActions.has(col)) columnActions.set(col, new Set());
        for (const act of actions) columnActions.get(col)!.add(act);
      }
    }

    const readColumns = new Set<string>(
      Array.from(columnActions)
        .filter(([, acts]) => acts.has('read'))
        .map(([col]) => col),
    );

    return {
      ownerDid,
      readColumns,
      columnActions,
      scopeColumns: Array.from(readColumns),
      allJwts,
    };
  }
}
