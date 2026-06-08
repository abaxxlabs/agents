export interface IdSdkVcApi {
  createCredential(issuer: string, subject: string, data: unknown, type?: string): Promise<unknown>;
  signCredential(vc: unknown, options: unknown): Promise<string>;
  getSignerOptions(did: string, subjectDid: string): Promise<{
    kid: string;
    issuerDid: string;
    subjectDid: string;
    signer: (data: Uint8Array) => Promise<Uint8Array>;
  }>;
  verifyJWT(jwt: string): Promise<boolean>;
  decodeJWT(jwt: string): Promise<{
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
  }>;
  parseJWT(jwt: string): Promise<unknown>;
  createRevocableCredential(options: unknown): Promise<unknown>;
  revokeCredential(options: unknown): Promise<unknown>;
  checkCredentialStatus(options: unknown): Promise<{ revoked: boolean; suspended: boolean }>;
  EdDsaSigner(privateKey: Uint8Array): (data: Uint8Array) => Promise<Uint8Array>;
}

/** Platform DID API surface. */
export interface IdSdkDidApi {
  resolve(didUrl: string): Promise<{ didDocument: unknown; didResolutionMetadata: unknown }>;
  create(options?: unknown): Promise<unknown>;
}

/** Structural contract for the platform identity SDK instance. */
export interface IdSdkInstance {
  vc: IdSdkVcApi;
  did: IdSdkDidApi;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- agent is the loosest part of the SDK shape; any here lets MCP adapter and direct id-sdk both satisfy it
  agent: any;
  connectedDid: string;
}
