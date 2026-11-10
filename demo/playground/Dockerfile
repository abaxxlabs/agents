FROM oven/bun:1.3.14 AS runtime-deps

USER root
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --production --frozen-lockfile --ignore-scripts --backend=copyfile

FROM runtime-deps AS builder

COPY . .

# Build the canonical repository package before installing its local Playground link.
RUN bun install --frozen-lockfile --ignore-scripts --backend=copyfile \
  && bun run build:esm \
  && bun run build:cjs \
  && bun run build:cjs-shim

FROM node:22-bookworm-slim AS playground-deps

WORKDIR /app/demo/playground
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
RUN apt-get update \
  && apt-get install --yes --no-install-recommends git python3 make g++ \
  && rm -rf /var/lib/apt/lists/*
COPY . /app
COPY --from=builder /app/dist /app/dist
RUN git init --quiet /app \
  && npm ci --ignore-scripts --no-audit --no-fund \
  && npm rebuild better-sqlite3 --ignore-scripts=false --no-audit --no-fund \
  && npm run build:css \
  && npm prune --omit=dev --ignore-scripts --no-audit --no-fund \
  && npm run check:linked-agents

FROM node:22-bookworm-slim AS runtime

WORKDIR /app
ENV NODE_ENV=development \
  NPM_CONFIG_UPDATE_NOTIFIER=false

COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/migrations ./migrations
COPY --from=builder /app/vendor ./vendor
COPY --from=runtime-deps /app/node_modules ./node_modules
COPY --from=playground-deps /app/demo/playground/node_modules/better-sqlite3 ./node_modules/better-sqlite3
COPY --from=builder /app/demo/playground/package.json ./demo/playground/package.json
COPY --from=builder /app/demo/playground/package-lock.json ./demo/playground/package-lock.json
COPY --from=playground-deps /app/demo/playground/node_modules ./demo/playground/node_modules
COPY --from=playground-deps /app/demo/playground/public ./demo/playground/public
COPY --from=builder /app/demo/playground/scripts ./demo/playground/scripts
COPY --from=builder /app/demo/playground/src ./demo/playground/src
COPY --from=builder /app/demo/playground/reports ./demo/playground/reports

RUN ln -s ../demo/playground/node_modules/pg /app/node_modules/pg \
  && ln -s ../demo/playground/node_modules/libpg-query /app/node_modules/libpg-query \
  && mkdir -p /var/lib/playground \
  && chown node:node /var/lib/playground

WORKDIR /app/demo/playground
USER node

RUN node --input-type=module -e ' \
  import assert from "node:assert/strict"; \
  import { createStorageBackend } from "@abaxxlabs/agents"; \
  const storage = await createStorageBackend({ type: "sqlite", path: ":memory:", sessionMacKey: Buffer.alloc(32) }); \
  try { \
    await storage.initialize(); \
    assert.equal(await storage.agents.count(), 0); \
  } finally { \
    await storage.close(); \
  }'

EXPOSE 3100
CMD ["node", "src/server.mjs"]
