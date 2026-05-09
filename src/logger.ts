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

export function getLogger(injected?: Logger): Logger {
  return injected ?? defaultLogger;
}
