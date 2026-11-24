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

/** Optional parts of the MCP host: the persistent server identity, extensions and shutdown. */

import { createInstanceIdentity, type InstanceIdentity } from '#identity/instance-identity.js';
import type { Logger } from '#observability/logger.js';
import type { McpHostAttachment, McpHostExtension, McpHostExtensionContext } from './extension.js';

export interface HostIdentityOptions {
  keystorePath?: string;
  trustedServers?: readonly string[];
  /** True when a host extension needs the persistent identity. */
  required?: boolean;
  devMode: boolean;
  logger: Logger;
}

/** A keystore path, trusted servers or an extension each need the persistent server identity. */
export function needsHostIdentity(
  options: Pick<HostIdentityOptions, 'keystorePath' | 'trustedServers' | 'required'>,
): boolean {
  return (
    options.keystorePath !== undefined ||
    (options.trustedServers?.length ?? 0) > 0 ||
    options.required === true
  );
}

/**
 * The persistent server identity and its trust anchors, or null when the host needs neither,
 * which keeps the per-process verifier DID.
 */
export async function loadHostIdentity(
  options: HostIdentityOptions,
): Promise<InstanceIdentity | null> {
  if (!needsHostIdentity(options)) return null;
  return createInstanceIdentity({
    keystorePath: options.keystorePath,
    devMode: options.devMode,
    trustedServers: options.trustedServers,
    logger: options.logger,
  });
}

export interface AttachedExtension {
  name: string;
  attachment: McpHostAttachment;
}

/**
 * Attaches every extension in order. An extension that returns null stays off. `onAttached`
 * runs as soon as an extension is on, so what it opened is released if a later one fails.
 */
export async function attachHostExtensions(
  extensions: readonly McpHostExtension[],
  context: McpHostExtensionContext,
  onAttached: (extension: AttachedExtension) => void = () => {},
): Promise<AttachedExtension[]> {
  const attached: AttachedExtension[] = [];
  for (const extension of extensions) {
    const attachment = await extension.attach(context);
    if (!attachment) continue;
    const entry = { name: extension.name, attachment };
    attached.push(entry);
    onAttached(entry);
  }
  return attached;
}

/** Stops an extension at most once. Failures are logged, never thrown. */
export function extensionStopper(
  extension: AttachedExtension,
  logger: Logger,
): () => Promise<void> {
  let stopping: Promise<void> | undefined;
  return () => {
    stopping ??= Promise.resolve()
      .then(() => extension.attachment.stop?.())
      .catch((err: unknown) => {
        logger.warn(`[agents] extension ${extension.name} stop failed`, {
          error: errorMessage(err),
        });
      });
    return stopping;
  };
}

export type HostExtensionStart = { ok: true } | { ok: false; error: string };

/** Starts an extension. A failed start is stopped again so nothing it launched outlives it. */
export async function startHostExtension(
  extension: AttachedExtension,
  stop: () => Promise<void>,
): Promise<HostExtensionStart> {
  try {
    await extension.attachment.start?.();
    return { ok: true };
  } catch (err) {
    await stop();
    return { ok: false, error: errorMessage(err) };
  }
}

export interface HostShutdown {
  /** Registers a cleanup step. Steps run in reverse order of registration. */
  defer(step: () => unknown): void;
  /** Runs every step once, logging failures instead of throwing, then exits with the highest `code` asked for. */
  run(code?: number): Promise<void>;
  /** True once `run` has been called. */
  readonly underWay: boolean;
}

export function createHostShutdown(options: {
  log: (message: string) => void;
  exit: (code: number) => void;
}): HostShutdown {
  const steps: Array<() => unknown> = [];
  let running: Promise<void> | undefined;
  let exitCode = 0;
  return {
    defer(step) {
      steps.push(step);
    },
    get underWay() {
      return running !== undefined;
    },
    run(code = 0) {
      // A failure reported while a shutdown is already under way still decides the exit code.
      exitCode = Math.max(exitCode, code);
      running ??= (async () => {
        options.log('Shutting down...');
        for (const step of [...steps].reverse()) {
          try {
            await step();
          } catch (err) {
            options.log(`Shutdown step failed: ${errorMessage(err)}`);
          }
        }
        options.exit(exitCode);
      })();
      return running;
    },
  };
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
