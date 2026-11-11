import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { posix } from 'node:path';
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

test('the local SDK lock metadata tracks the current repository manifest', () => {
  assert.deepEqual(lock.packages['node_modules/@abaxxlabs/agents'], {
    resolved: '../..', link: true,
  });
  for (const field of [
    'name', 'version', 'license', 'engines', 'dependencies', 'devDependencies',
    'optionalDependencies', 'peerDependencies', 'peerDependenciesMeta',
  ]) {
    assert.deepEqual(lock.packages['../..'][field], rootManifest[field], `stale SDK ${field}`);
  }
  const normalizeBins = (bins) => Object.fromEntries(Object.entries(bins)
    .map(([name, path]) => [name, posix.normalize(path)]));
  assert.deepEqual(normalizeBins(lock.packages['../..'].bin), normalizeBins(rootManifest.bin));
});

test('native installation is scoped to SQLite under the final runtime Node version', () => {
  const deps = stages.get('playground-deps');
  const runtime = stages.get('runtime');
  assert.equal(deps.image, 'node:22-bookworm-slim');
  assert.equal(runtime.image, deps.image);
  assert.match(deps.source, /apt-get install[^\n]*\bpython3\b/);
  assert.match(deps.source, /apt-get install[^\n]*\bmake\b/);
  assert.match(deps.source, /apt-get install[^\n]*\bg\+\+/);

  const commands = [...dockerfile.replace(/\\\n\s*/g, ' ').matchAll(/\b(?:bun|npm) (?:install|ci|prune|rebuild)\b[^\n&]*/g)]
    .map(([command]) => command.trim());
  const rebuilds = commands.filter((command) => command.startsWith('npm rebuild'));
  assert.equal(rebuilds.length, 1, 'only the named native addon may run install scripts');
  assert.match(rebuilds[0], /^npm rebuild better-sqlite3 --ignore-scripts=false(?:\s|$)/);
  for (const command of commands.filter((command) => !rebuilds.includes(command))) {
    assert.match(command, /--ignore-scripts(?:\s|$)/);
  }
  assert.match(deps.source, /npm ci[^\n]*&& npm rebuild better-sqlite3[^\n]*&& npm run build:css[^\n]*&& npm prune --omit=dev/);
  assert.doesNotMatch(runtime.source, /apt-get|npm (?:ci|install|rebuild)|\b(?:make|g\+\+|python3)\b/);
});

test('the final image overlays the root peer with the Node-built addon and stays non-root', () => {
  const runtime = stages.get('runtime').source;
  assert.match(runtime, /COPY --from=playground-deps \/app\/demo\/playground\/node_modules \.\/demo\/playground\/node_modules/);
  const rootDependencies = runtime.indexOf('COPY --from=runtime-deps /app/node_modules ./node_modules');
  const nativeCopy = runtime.indexOf('COPY --from=playground-deps /app/demo/playground/node_modules/better-sqlite3 ./node_modules/better-sqlite3');
  assert.ok(rootDependencies >= 0 && nativeCopy > rootDependencies,
    'the Node-built addon must overwrite the existing script-disabled root peer');
  assert.doesNotMatch(runtime, /\bln -s [^\n&]*better-sqlite3/);
  for (const peer of ['pg', 'libpg-query']) {
    assert.ok(runtime.includes(`ln -s ../demo/playground/node_modules/${peer} /app/node_modules/${peer}`));
  }
  assert.match(runtime, /WORKDIR \/app\/demo\/playground\nUSER node\n/);
  assert.match(runtime, /CMD \["node", "src\/server\.mjs"\]\s*$/);
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
