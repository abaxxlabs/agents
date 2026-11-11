#!/usr/bin/env node
/** Selects the Playground smoke target: the local Compose stack or a deployed origin. */
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const LOCAL_SCRIPT = 'compose-smoke.mjs';
const REMOTE_SCRIPT = 'remote-smoke.mjs';
const TARGET_ERROR =
  'PLAYGROUND_SMOKE_BASE_URL must be a bare HTTPS origin without a path, query, or credentials';

export function resolveSmokeTarget(env = {}) {
  const raw = env.PLAYGROUND_SMOKE_BASE_URL;
  if (raw === undefined) return { mode: 'local', script: LOCAL_SCRIPT };
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(TARGET_ERROR);
  }
  if (url.protocol !== 'https:' || url.username || url.password ||
    url.pathname !== '/' || url.search || url.hash) {
    throw new Error(TARGET_ERROR);
  }
  return { mode: 'remote', script: REMOTE_SCRIPT, baseUrl: url.origin };
}

function main() {
  let target;
  try {
    target = resolveSmokeTarget(process.env);
  } catch (err) {
    console.error(`smoke selector: ${err.message}`);
    process.exit(1);
  }
  const child = spawn(process.execPath, [join(__dirname, target.script)], { stdio: 'inherit' });
  child.on('error', (err) => {
    console.error(`smoke selector: cannot start ${target.script}: ${err.message}`);
    process.exit(1);
  });
  child.on('close', (code) => {
    process.exit(code ?? 1);
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
