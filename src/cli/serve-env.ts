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

export interface ServeChildEnvOptions {
  db: string;
  port: string;
  columns?: string;
}

/**
 * Builds the REST server child-process environment from CLI options.
 */
export function buildServeChildEnv(
  options: ServeChildEnvOptions,
  baseEnv: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const env: Record<string, string> = {};

  for (const [key, value] of Object.entries(baseEnv)) {
    if (value !== undefined) env[key] = value;
  }

  env.DATABASE_URL = options.db;
  env.PORT = options.port;
  if (options.columns) env.ENCRYPTED_COLUMNS = options.columns;

  return env;
}
