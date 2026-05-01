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

/** Opt-in gates for tests requiring local services (Keychain, loopback, Abaxx One). */
export const KEYCHAIN_TESTS_ENV = 'AGENTS_RUN_KEYCHAIN_TESTS';
export const LOOPBACK_TESTS_ENV = 'AGENTS_RUN_LOOPBACK_TESTS';
export const ABAXX_ONE_OIDC_TESTS_ENV = 'AGENTS_RUN_ABAXX_ONE_OIDC_TESTS';

function envFlag(name: string): boolean {
  return process.env[name] === 'true';
}

export const isCi = process.env.CI === 'true';

export const shouldRunMacOsKeychainTests =
  process.platform === 'darwin' && !isCi && envFlag(KEYCHAIN_TESTS_ENV);

export const shouldRunLoopbackHttpTests = envFlag(LOOPBACK_TESTS_ENV);

export const shouldRunAbaxxOneOidcTests = envFlag(ABAXX_ONE_OIDC_TESTS_ENV);

export const keychainSkipReason = `skipped: run npm run test:e2e with ${KEYCHAIN_TESTS_ENV}=true on macOS with CI!=true and an interactive local Keychain.`;

export const loopbackSkipReason = `skipped: moved out of default npm test; run npm run test:e2e with ${LOOPBACK_TESTS_ENV}=true on a machine that permits loopback listeners.`;

export const abaxxOneOidcSkipReason = `skipped: moved out of default npm test; run npm run test:e2e with ${ABAXX_ONE_OIDC_TESTS_ENV}=true and Abaxx One listening on localhost:3001.`;
