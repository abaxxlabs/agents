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
 * DidDhtPublisher — interface stub for did:dht external publishing.
 *
 * The current build ships did:key only. This interface ships so a future implementation
 * can slot in without changing calling code (AgentVerifier, ServerIdentity, MCP tools
 * already reference DidDhtMethod and compile cleanly against this stub).
 */

// ─── DidDhtMethod ─────────────────────────────────────────────────────────────

/**
 * The DID method currently in use by this server.
 * Currently always 'did:key'. Returned by MCP `whoami`/`discover` tools.
 */
export type DidDhtMethod = 'did:dht' | 'did:key';

// ─── DidDhtPublisher ─────────────────────────────────────────────────────────

/**
 * DidDhtPublisher — contract for did:dht external publishing.
 *
 * A future concrete DidDhtPublisher class will implement this interface.
 * Callers that want to conditionally use DHT can accept DidDhtPublisher as an
 * optional dependency and check currentMethod at runtime.
 */
export interface DidDhtPublisher {
  /**
   * Publish the server's DID document to the DHT network.
   *
   * Returns success=false (not throw) on soft failures (gateway unreachable,
   * timeout) so callers can decide whether to retry or fall back to did:key.
   * Throws only on programming errors (invalid DID document, misconfiguration).
   */
  publish(): Promise<{ success: boolean; method: DidDhtMethod; reason?: string }>;

  /**
   * Start the automatic re-publish timer.
   *
   * DHT records have a TTL. This starts a background interval that calls
   * publish() on a configurable schedule (default: every 2 hours) to keep
   * the server's DID document alive in the network.
   *
   * Idempotent — calling twice has no effect (timer runs once).
   */
  startAutoPublish(): void;

  /**
   * Stop the automatic re-publish timer and clean up resources.
   * Call during graceful shutdown.
   */
  stop(): void;

  /**
   * The DID method currently active. 'did:dht' when publishing is live;
   * 'did:key' when DHT is unavailable or not yet started.
   *
   * Read by MCP `whoami` and `discover` tools to report identity topology.
   */
  readonly currentMethod: DidDhtMethod;
}
