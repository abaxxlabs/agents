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

import type { Logger } from '#observability/logger.js';
import { getLogger } from '#observability/logger.js';
import { normalizeDomainError, toMcpErrorBody } from '#transport/index.js';

export function mapAgentScopeError(
  err: unknown,
  injectedLogger?: Logger,
): {
  content: Array<{ type: 'text'; text: string }>;
  isError: true;
} {
  const logger = getLogger(injectedLogger);
  const normalized = normalizeDomainError(err);
  if (normalized.code === 'INTERNAL_ERROR' && err instanceof Error) {
    logger.error('[agents] Internal error in MCP tool handler: ' + err.message, {
      handler: 'tool',
      error: err.message,
    });
  }
  return {
    content: [{ type: 'text', text: JSON.stringify(toMcpErrorBody(normalized)) }],
    isError: true,
  };
}
