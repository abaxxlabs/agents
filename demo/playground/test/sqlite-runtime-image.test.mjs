import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const playground = new URL('../', import.meta.url);
const readJson = (url) => JSON.parse(readFileSync(url, 'utf8'));
const manifest = readJson(new URL('package.json', playground));
const lock = readJson(new URL('package-lock.json', playground));
const rootManifest = readJson(new URL('../../package.json', playground));
const dockerfile = readFileSync(new URL('Dockerfile', playground), 'utf8');
const stages = new Map([...dockerfile.matchAll(/^FROM (\S+) AS (\S+)\n([\s\S]*?)(?=^FROM |$(?![\s\S]))/gm)]
  .map(([, image, name, source]) => [name, { image, source: source.replace(/\\\n\s*/g, ' ') }]));

test('SQLite is a pinned production dependency with its native-install closure locked', () => {
  const sqlitePeer = rootManifest.peerDependencies['better-sqlite3'];
  assert.match(sqlitePeer, /^\d+\.\d+\.\d+$/, 'the SDK SQLite peer must be an exact version pin');
  assert.equal(manifest.dependencies['better-sqlite3'], sqlitePeer);
  assert.deepEqual(lock.packages[''].dependencies, manifest.dependencies);
  const pending = ['better-sqlite3'];
  const seen = new Set();
  while (pending.length > 0) {
    const name = pending.pop();
    if (seen.has(name)) continue;
    seen.add(name);
    const entry = lock.packages[`node_modules/${name}`];
    assert.ok(entry, `missing production lock entry for ${name}`);
    assert.ok(!entry.dev && !entry.optional, `${name} must survive production pruning`);
    assert.ok(entry.integrity, `${name} must have registry integrity metadata`);
    for (const dependency of Object.keys(entry.dependencies ?? {})) {
      const nested = lock.packages[`node_modules/${name}/node_modules/${dependency}`];
      if (nested) {
        assert.ok(!nested.dev && !nested.optional);
        assert.ok(nested.integrity);
      } else {
        pending.push(dependency);
      }
    }
  }
  assert.equal(lock.packages['node_modules/better-sqlite3'].version, sqlitePeer);
  assert.equal(manifest.scripts['proof:sqlite-runtime'], 'node scripts/sqlite-runtime-proof.mjs');
});

test('the assembled image opens SQLite through the public SDK as the runtime user during build', () => {
  const runtime = stages.get('runtime').source;
  const smoke = runtime.match(/^RUN node --input-type=module -e '([^']+)'$/m);
  assert.ok(smoke, 'the final image must execute a SQLite smoke, not just import its driver');
  const usersBeforeSmoke = [...runtime.slice(0, smoke.index).matchAll(/^USER (\S+)$/gm)];
  assert.equal(usersBeforeSmoke.at(-1)?.[1], 'node',
    'the smoke must run as the final non-root user');
  assert.match(smoke[1], /import \{ createStorageBackend \} from "@abaxxlabs\/agents"/);
  assert.match(smoke[1], /await createStorageBackend\(\{ type: "sqlite", path: ":memory:", sessionMacKey: Buffer\.alloc\(32\) \}\)/);
  assert.match(smoke[1], /try \{\s*await storage\.initialize\(\);\s*assert\.equal\(await storage\.agents\.count\(\), 0\);\s*\} finally \{\s*await storage\.close\(\);\s*\}/);
});
