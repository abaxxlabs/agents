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

/** Runtime readers for OIDC JSON payloads. Narrows `unknown` values from provider-controlled data. */

import type { OidcTokenResponse } from './provider.js';

export type JsonObject = Record<string, unknown>;

export function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function readOptionalString(payload: JsonObject, field: string): string | undefined {
  const value = payload[field];
  return typeof value === 'string' ? value : undefined;
}

export function readOptionalNumber(payload: JsonObject, field: string): number | undefined {
  const value = payload[field];
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

export function readOptionalStringArray(payload: JsonObject, field: string): string[] | undefined {
  const value = payload[field];
  if (!Array.isArray(value) || !value.every(item => typeof item === 'string')) {
    return undefined;
  }
  return value;
}

/** Narrow token endpoint JSON into OidcTokenResponse. Does not throw; providers decide what's required. */
export function parseOidcTokenResponse(payload: unknown): OidcTokenResponse {
  if (!isJsonObject(payload)) {
    return { access_token: '', token_type: '' };
  }

  return {
    access_token: readOptionalString(payload, 'access_token') ?? '',
    token_type: readOptionalString(payload, 'token_type') ?? '',
    id_token: readOptionalString(payload, 'id_token'),
    refresh_token: readOptionalString(payload, 'refresh_token'),
    expires_in: readOptionalNumber(payload, 'expires_in'),
    scope: readOptionalString(payload, 'scope'),
  };
}

/** Decode JWT payload claims without verification. Malformed input returns {}. */
export function parseJwtPayloadClaims(idToken: string): JsonObject {
  try {
    const parts = idToken.split('.');
    if (parts.length !== 3) {
      return {};
    }

    const payload: unknown = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return isJsonObject(payload) ? payload : {};
  } catch {
    return {};
  }
}
