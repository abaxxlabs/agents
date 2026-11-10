import { resolve } from 'node:path';

export function canonicalMigrationsDir(playgroundRoot) {
  return resolve(playgroundRoot, '..', '..', 'migrations');
}
