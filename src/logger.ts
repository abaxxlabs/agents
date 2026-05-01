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
 * Pluggable logger interface for library diagnostics.
 *
 * @example
 * ```typescript
 * import { AgentIdentity, type Logger } from '@abaxxlabs/agents';
 *
 * const siemLogger: Logger = {
 *   warn(msg, fields) { siem.send({ level: 'warn', msg, ...fields }); },
 *   error(msg, fields) { siem.send({ level: 'error', msg, ...fields }); },
 * };
 *
 * const identity = await AgentIdentity.create(config, {
 *   masterKey, storage, logger: siemLogger,
 * });
 * ```
 */
export interface Logger {
  warn(message: string, fields?: Record<string, unknown>): void;
  error(message: string, fields?: Record<string, unknown>): void;
}

/** Writes to stderr in the same format the library used before the Logger interface existed. */
export const defaultLogger: Logger = {
  warn(message: string) {
    console.warn(message);
  },
  error(message: string) {
    console.error(message);
  },
};
