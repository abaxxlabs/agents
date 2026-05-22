type Brand<T, B extends string> = T & { readonly __brand: B };

/** A W3C Decentralized Identifier (e.g. `did:dht:abc123`). */
export type Did = Brand<string, 'Did'>;

/** A SQL column name. */
export type ColumnName = Brand<string, 'ColumnName'>;

/** A SQL table name (optionally schema-qualified). */
export type TableName = Brand<string, 'TableName'>;

/** A JWT `jti` (unique token identifier). */
export type Jti = Brand<string, 'Jti'>;

/** An HTTPS issuer URL (e.g. OIDC issuer endpoint). */
export type IssuerUrl = Brand<string, 'IssuerUrl'>;

/**
 * Validate and brand a string as a {@link Did}.
 * @param value - must start with `did:`
 * @throws Error if the value is empty or not a valid DID prefix
 */
export function asDid(value: string): Did {
  if (!value || !value.startsWith('did:')) {
    throw new Error(`Invalid DID: expected "did:" prefix, got "${value}"`);
  }
  return value as Did;
}

/**
 * Validate and brand a string as a {@link ColumnName}.
 * @param value - must be a non-empty string
 * @throws Error if the value is empty
 */
export function asColumnName(value: string): ColumnName {
  if (!value) {
    throw new Error('Invalid column name: must be non-empty');
  }
  return value as ColumnName;
}

/**
 * Validate and brand a string as a {@link TableName}.
 * @param value - must be a non-empty string
 * @throws Error if the value is empty
 */
export function asTableName(value: string): TableName {
  if (!value) {
    throw new Error('Invalid table name: must be non-empty');
  }
  return value as TableName;
}

/**
 * Validate and brand a string as a {@link Jti}.
 * @param value - must be a non-empty string
 * @throws Error if the value is empty
 */
export function asJti(value: string): Jti {
  if (!value) {
    throw new Error('Invalid JTI: must be non-empty');
  }
  return value as Jti;
}

/**
 * Validate and brand a string as an {@link IssuerUrl}.
 * @param value - must start with `https://`
 * @throws Error if the value is empty or not an HTTPS URL
 */
export function asIssuerUrl(value: string): IssuerUrl {
  if (!value || !value.startsWith('https://')) {
    throw new Error(`Invalid issuer URL: expected "https://" prefix, got "${value}"`);
  }
  return value as IssuerUrl;
}
