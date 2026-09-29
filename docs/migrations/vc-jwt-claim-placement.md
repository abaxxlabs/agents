# Migration: delegation claims moved inside the credential

**Audience:** anyone decoding an issued credential and reading its claims directly. If you only call `issueCredential`, `issueDelegatedCredential` or the verifier, nothing changes for you.

The delegation ceiling and the ancestor chain used to sit at the JWT top level, beside `iss`, `sub` and `exp`. In VC-JWT the verifiable credential is the object under `vc`; anything outside it is a statement about the token, not about the credential. Both claims now live inside `vc`, so a verifier reading the credential finds them where the specification says to look.

---

## TL;DR

One thing can break you: reading `payload.maxDepth` or `payload.delegationChain` off a decoded credential. Both now return `undefined` on newly issued credentials.

Everything else is unchanged. The options you pass at issuance are the same, and credentials issued before this release keep verifying.

---

## 1. Where the claims live now

```jsonc
// before
{
  "iss": "did:key:…",
  "sub": "did:key:…",
  "maxDepth": 2,
  "delegationChain": ["eyJhbGciOi…"],
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "DelegatedAgentScopeCredential"],
    "credentialSubject": {
      "id": "did:key:…",
      "scope": { "columns": ["…"], "actions": ["read"] },
      "owner": "did:key:…",
      "delegated": false
    }
  }
}

// after
{
  "iss": "did:key:…",
  "sub": "did:key:…",
  "vc": {
    "@context": ["https://www.w3.org/2018/credentials/v1"],
    "type": ["VerifiableCredential", "DelegatedAgentScopeCredential"],
    "credentialSubject": {
      "id": "did:key:…",
      "scope": { "columns": ["…"], "actions": ["read"] }
    },
    "termsOfUse": [{ "type": "DelegationPolicy", "maxDepth": 2 }],
    "evidence": [{ "type": "DelegationChain", "credentials": ["eyJhbGciOi…"] }]
  }
}
```

`termsOfUse` and `evidence` are both defined by the W3C credentials context. `termsOfUse` carries constraints the issuer places on use, which is what a delegation ceiling is; `evidence` carries provenance, which is what an ancestor chain is.

## 2. Two fields are gone

`credentialSubject.owner` duplicated `iss` in every path that issued it, and nothing read it — ownership is checked by comparing the credential's issuer against the agent's registered owner.

`credentialSubject.delegated` was always `false`, including on delegated credentials, where it contradicted the `type` array declaring `DelegatedAgentScopeCredential`. Nothing read it either.

## 3. If you read the claims yourself

```ts
// before
const { payload } = decodeJwt(credential);
const ceiling = payload.maxDepth;
const chain = payload.delegationChain;

// after
const { payload } = decodeJwt(credential);
const ceiling = payload.vc?.termsOfUse?.find((t) => t.type === 'DelegationPolicy')?.maxDepth;
const chain = payload.vc?.evidence?.find((e) => e.type === 'DelegationChain')?.credentials;
```

Both `type` values may be a string or an array of strings, as VC sub-objects are allowed to carry several types. If you write your own reader, accept both.

## 4. Compatibility

Credentials issued before this release keep verifying. The verifier reads the current location first and falls back to the legacy top-level claim, so a mixed population of credentials works without any action on your part.

The fallback is transitional. It will be removed once no unexpired credential can still carry the legacy shape, which is bounded by the longest credential lifetime you issue. If you decode credentials yourself, move to the reader above before then.

## 5. No change at issuance

```ts
// unchanged
await scope.issueCredential({
  agent: agentDid,
  columns: ['patients.name'],
  actions: ['read'],
  expiresIn: '4h',
  maxDepth: 2,
});
```

The option name, its meaning and its default are unchanged. Only where the value lands inside the issued JWT changed.
