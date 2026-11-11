import { spawn } from 'node:child_process';

export class CommandFailure extends Error {
  constructor(stage, code) {
    super(stage);
    this.stage = stage;
    this.code = code ?? 'SPAWN_FAILED';
  }
}

export function execute(command, args, { cwd, env = process.env, timeout = 120_000, inherit = false, signal } = {}) {
  return new Promise((resolve) => {
    if (signal?.aborted) { resolve({ code: -1, stdout: '', stderr: '', timedOut: false }); return; }
    const child = spawn(command, args, { cwd, env, stdio: inherit ? 'inherit' : ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const abort = () => child.kill('SIGKILL');
    signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeout);
    const collect = (target) => (chunk) => {
      if (target === 'stdout') stdout += chunk;
      else stderr += chunk;
      if (stdout.length + stderr.length > 8_000_000) { timedOut = true; child.kill('SIGKILL'); }
    };
    child.stdout?.on('data', collect('stdout'));
    child.stderr?.on('data', collect('stderr'));
    const finish = (code) => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      resolve({ code: timedOut || signal?.aborted ? -1 : code, stdout, stderr, timedOut });
    };
    child.on('error', () => finish(-1));
    child.on('close', finish);
  });
}

export async function poll(operation, accept, { timeout = 15_000, interval = 200, signal } = {}) {
  const started = Date.now();
  do {
    if (signal?.aborted) throw new CommandFailure('interrupted');
    const value = await operation();
    if (signal?.aborted) throw new CommandFailure('interrupted');
    if (accept(value)) return { value, elapsedMs: Date.now() - started };
    await new Promise((resolve) => setTimeout(resolve, interval));
  } while (Date.now() - started < timeout);
  throw new CommandFailure('deadline-exceeded');
}
