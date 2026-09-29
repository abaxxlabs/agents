import { execFileSync } from 'node:child_process';

export function corporateEmployeeNames(rootDir, emailSuffix) {
  if (!emailSuffix) return [];
  const suffix = emailSuffix.toLocaleLowerCase();
  const output = execFileSync('git', ['shortlog', '-sne', 'HEAD'], {
    cwd: rootDir,
    encoding: 'utf8',
  });
  const names = new Set();
  for (const line of output.split('\n')) {
    const match = /^\s*\d+\s+(.+?)\s+<([^>]+)>$/.exec(line);
    if (match?.[1].trim().length >= 3 && match[2].trim().toLocaleLowerCase().endsWith(suffix)) {
      names.add(match[1].trim());
    }
  }
  return [...names];
}

export function normalizePrivateUrlPrefixes(values) {
  const normalized = new Set();
  for (const rawValue of values) {
    const value = String(rawValue ?? '')
      .trim()
      .replace(/^git\+/, '')
      .replace(/\/+$/, '')
      .replace(/\.git$/, '');
    if (!value) continue;
    normalized.add(value);

    const sshMatch = /^git@([^:]+):(.+)$/.exec(value);
    if (sshMatch) {
      normalized.add(`${sshMatch[1]}/${sshMatch[2]}`);
      normalized.add(`${sshMatch[1]}:${sshMatch[2]}`);
      continue;
    }
    try {
      const url = new URL(value);
      const pathname = url.pathname.replace(/^\/|\/$/g, '');
      normalized.add(pathname ? `${url.host}/${pathname}` : url.host);
    } catch {
      // Non-URL prefixes are matched as provided.
    }
  }
  return [...normalized];
}
