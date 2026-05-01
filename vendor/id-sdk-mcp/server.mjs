/**
 * Vendored id-sdk MCP server for Agents++.
 *
 * Source: /Users/john/Projects/dwn/platform/packages/id-sdk-mcp
 *
 * Product decision: Agents++ integrates with the platform identity stack via a
 * local MCP process rather than importing the full id-sdk into the core package.
 * This keeps the package install self-contained while still letting deployments
 * enable did:dht resolution, hosted VC status lists, and DWN
 * operations through an explicit process boundary.
 *
 * Maintenance note: this file intentionally extends the upstream MCP server
 * with the VC tools used by Agents++ (`verifyJWT`, `decodeJWT`, status checks,
 * and revocation). Re-sync from upstream carefully and preserve those tools
 * unless the upstream server has grown equivalent coverage.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod/v4";
import { IDDwn } from "./sdk/esm/index.js";
import { VerifiableCredential } from "./sdk/esm/credentials/credential.js";

let session = null;

const server = new McpServer({
  name: "id-sdk-mcp",
  version: "0.1.0",
});

const safeReplacer = (_key, value) => {
  if (typeof value === "bigint") {
    return value.toString();
  }

  if (value instanceof Uint8Array) {
    return Array.from(value);
  }

  if (value instanceof Error) {
    return {
      name: value.name,
      message: value.message,
      stack: value.stack,
    };
  }

  return value;
};

const asTextResult = (payload) => ({
  content: [
    {
      type: "text",
      text: JSON.stringify(payload, safeReplacer, 2),
    },
  ],
});

const requireSession = () => {
  if (!session) {
    throw new Error(
      "No active SDK session. Call connect first to initialize IDDwn."
    );
  }

  return session;
};

const anyObjectSchema = z.object({}).passthrough();

server.registerTool(
  "connect",
  {
    description: "Initialize an IDDwn session using the dist build.",
    inputSchema: z.object({
      connectedDid: z.string().optional(),
      didMethod: z.enum(["ion", "dht", "key"]).optional(),
      sync: z.string().optional(),
      queueWhenOffline: z.boolean().optional(),
      flushWhenOnline: z.boolean().optional(),
      passphrase: z.string().optional(),
      dwnEndpoints: z.array(z.string()).optional(),
      dhtRelayUrl: z.string().optional(),
    }),
  },
  async (args) => {
    const serviceOptions = {};

    if (args.dwnEndpoints) {
      serviceOptions.dwnEndpoints = args.dwnEndpoints;
    }

    if (args.dhtRelayUrl) {
      serviceOptions.dhtRelayUrl = args.dhtRelayUrl;
    }

    const options = {
      connectedDid: args.connectedDid,
      didMethod: args.didMethod,
      sync: args.sync,
      queueWhenOffline: args.queueWhenOffline,
      flushWhenOnline: args.flushWhenOnline,
      passphrase: args.passphrase,
      ...(Object.keys(serviceOptions).length > 0 ? { serviceOptions } : {}),
    };

    const { iddwn, did } = await IDDwn.connect(options);
    session = { iddwn, did };

    return asTextResult({
      connected: true,
      did,
      didMethod: args.didMethod ?? "ion",
      sync: args.sync ?? "30s",
    });
  }
);

server.registerTool(
  "session_status",
  {
    description: "Get currently connected DID and session status.",
    inputSchema: z.object({}),
  },
  async () => {
    if (!session) {
      return asTextResult({ connected: false });
    }

    return asTextResult({
      connected: true,
      did: session.did,
    });
  }
);

server.registerTool(
  "did_create",
  {
    description: "Create a new DID with optional service endpoint overrides.",
    inputSchema: z.object({
      dwnEndpoints: z.array(z.string()).optional(),
    }),
  },
  async (args) => {
    const { iddwn } = requireSession();
    const result = await iddwn.did.create({
      ...(args.dwnEndpoints ? { serviceOptions: { dwnEndpoints: args.dwnEndpoints } } : {}),
    });

    return asTextResult(result);
  }
);

server.registerTool(
  "did_resolve",
  {
    description: "Resolve a DID or DID URL.",
    inputSchema: z.object({
      didUrl: z.string(),
    }),
  },
  async ({ didUrl }) => {
    const { iddwn } = requireSession();
    const resolution = await iddwn.did.resolve(didUrl);
    return asTextResult(resolution);
  }
);

server.registerTool(
  "vc_create_credential",
  {
    description:
      "Create a Verifiable Credential payload (unsigned credential object).",
    inputSchema: z.object({
      issuer: z.string(),
      subject: z.string(),
      data: anyObjectSchema,
      type: z.string().optional(),
    }),
  },
  async ({ issuer, subject, data, type }) => {
    const { iddwn } = requireSession();
    const credential = await iddwn.vc.createCredential(
      issuer,
      subject,
      data,
      type
    );

    return asTextResult(credential);
  }
);

server.registerTool(
  "vc_sign_credential",
  {
    description:
      "Sign a Verifiable Credential JSON object and return the signed JWT.",
    inputSchema: z.object({
      vc: anyObjectSchema,
      signOptions: anyObjectSchema.optional(),
    }),
  },
  async ({ vc, signOptions = {} }) => {
    const { iddwn } = requireSession();
    const credential =
      vc instanceof VerifiableCredential
        ? vc
        : new VerifiableCredential(vc.vcDataModel ?? vc);

    const signingOptions =
      typeof signOptions.signer === "function"
        ? signOptions
        : await iddwn.vc.getSignerOptions(
            signOptions.issuerDid ?? credential.issuer,
            signOptions.subjectDid ?? credential.subject
          );

    const signed = await iddwn.vc.signCredential(credential, {
      ...signingOptions,
      ...signOptions,
      signer: signingOptions.signer,
    });
    return asTextResult(signed);
  }
);

server.registerTool(
  "vc_get_signer_options",
  {
    description:
      "Return serializable signer metadata for an issuer/subject pair. The signer function itself stays server-side.",
    inputSchema: z.object({
      issuerDid: z.string(),
      subjectDid: z.string().optional(),
    }),
  },
  async ({ issuerDid, subjectDid }) => {
    const { iddwn } = requireSession();
    const signerOptions = await iddwn.vc.getSignerOptions(
      issuerDid,
      subjectDid ?? issuerDid
    );

    const { signer: _signer, ...serializableOptions } = signerOptions;
    return asTextResult(serializableOptions);
  }
);

server.registerTool(
  "vc_verify_jwt",
  {
    description: "Verify a VC JWT using the connected IDDwn VC API.",
    inputSchema: z.object({
      jwt: z.string(),
    }),
  },
  async ({ jwt }) => {
    const { iddwn } = requireSession();
    const verified = await iddwn.vc.verifyJWT(jwt);
    return asTextResult(verified);
  }
);

server.registerTool(
  "vc_decode_jwt",
  {
    description: "Decode a VC JWT into header, payload, and signature parts.",
    inputSchema: z.object({
      jwt: z.string(),
    }),
  },
  async ({ jwt }) => {
    const { iddwn } = requireSession();
    const decoded = await iddwn.vc.decodeJWT(jwt);
    return asTextResult(decoded);
  }
);

server.registerTool(
  "vc_parse_jwt",
  {
    description: "Parse a VC JWT into an SDK VerifiableCredential object.",
    inputSchema: z.object({
      jwt: z.string(),
    }),
  },
  async ({ jwt }) => {
    const { iddwn } = requireSession();
    const credential = await iddwn.vc.parseJWT(jwt);
    return asTextResult(credential);
  }
);

server.registerTool(
  "vc_create_revocable_credential",
  {
    description:
      "Create and sign a revocable credential with status-list metadata.",
    inputSchema: z.object({
      options: anyObjectSchema,
    }),
  },
  async ({ options }) => {
    const { iddwn } = requireSession();
    const createOptions = { ...options };

    if (!createOptions.signOptions || typeof createOptions.signOptions.signer !== "function") {
      const signingOptions = await iddwn.vc.getSignerOptions(
        createOptions.signOptions?.issuerDid ?? createOptions.issuer,
        createOptions.signOptions?.subjectDid ?? createOptions.subject
      );
      createOptions.signOptions = {
        ...signingOptions,
        ...createOptions.signOptions,
        signer: signingOptions.signer,
      };
    }

    const result = await iddwn.vc.createRevocableCredential(createOptions);
    return asTextResult(result);
  }
);

server.registerTool(
  "vc_revoke_credential",
  {
    description: "Revoke a credential through the connected IDDwn VC API.",
    inputSchema: z.object({
      options: anyObjectSchema,
    }),
  },
  async ({ options }) => {
    const { iddwn } = requireSession();
    const revokeOptions = { ...options };

    if (revokeOptions.signOptions && typeof revokeOptions.signOptions.signer !== "function") {
      const signingOptions = await iddwn.vc.getSignerOptions(
        revokeOptions.signOptions.issuerDid ?? session.did,
        revokeOptions.signOptions.subjectDid ?? session.did
      );
      revokeOptions.signOptions = {
        ...signingOptions,
        ...revokeOptions.signOptions,
        signer: signingOptions.signer,
      };
    }

    const result = await iddwn.vc.revokeCredential(revokeOptions);
    return asTextResult(result);
  }
);

server.registerTool(
  "vc_check_credential_status",
  {
    description: "Check whether a credential has been revoked or suspended.",
    inputSchema: z.object({
      options: anyObjectSchema,
    }),
  },
  async ({ options }) => {
    const { iddwn } = requireSession();
    const status = await iddwn.vc.checkCredentialStatus(options);
    return asTextResult(status);
  }
);

server.registerTool(
  "vp_create_presentation",
  {
    description:
      "Create a Verifiable Presentation result from VC JWTs and a presentation definition.",
    inputSchema: z.object({
      vcJwts: z.array(z.string()),
      presentationDefinition: anyObjectSchema,
    }),
  },
  async ({ vcJwts, presentationDefinition }) => {
    const { iddwn } = requireSession();
    const presentation = await iddwn.vc.createPresentation(
      vcJwts,
      presentationDefinition
    );
    return asTextResult(presentation);
  }
);

server.registerTool(
  "vp_decode_presentation",
  {
    description: "Decode a VP JWT into its payload structure.",
    inputSchema: z.object({
      jwt: z.string(),
    }),
  },
  async ({ jwt }) => {
    const { iddwn } = requireSession();
    const decoded = await iddwn.vc.decodePresentation(jwt);
    return asTextResult(decoded);
  }
);

server.registerTool(
  "dwn_records_write",
  {
    description: "Write a record to DWN. Pass the full SDK request object.",
    inputSchema: z.object({
      request: anyObjectSchema,
    }),
  },
  async ({ request }) => {
    const { iddwn } = requireSession();
    const result = await iddwn.dwn.records.write(request);
    return asTextResult(result);
  }
);

server.registerTool(
  "dwn_records_query",
  {
    description: "Query records from DWN. Pass the full SDK request object.",
    inputSchema: z.object({
      request: anyObjectSchema,
    }),
  },
  async ({ request }) => {
    const { iddwn } = requireSession();
    const result = await iddwn.dwn.records.query(request);
    return asTextResult(result);
  }
);

server.registerTool(
  "dwn_records_read",
  {
    description: "Read a single record from DWN. Pass the full SDK request object.",
    inputSchema: z.object({
      request: anyObjectSchema,
    }),
  },
  async ({ request }) => {
    const { iddwn } = requireSession();
    const result = await iddwn.dwn.records.read(request);
    return asTextResult(result);
  }
);

server.registerTool(
  "dwn_records_delete",
  {
    description: "Delete a record from DWN. Pass the full SDK request object.",
    inputSchema: z.object({
      request: anyObjectSchema,
    }),
  },
  async ({ request }) => {
    const { iddwn } = requireSession();
    const result = await iddwn.dwn.records.delete(request);
    return asTextResult(result);
  }
);

server.registerTool(
  "flush_outbox_and_sync",
  {
    description: "Flush outbox and run one sync cycle immediately.",
    inputSchema: z.object({}),
  },
  async () => {
    const { iddwn } = requireSession();
    await iddwn.flushOutboxAndSync();
    return asTextResult({ ok: true });
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
