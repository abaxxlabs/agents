// Audits publishable files for secrets, oversized text, and release-only terms.
import { existsSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

import {
  DEFAULT_BLOCKED_RELEASE_TERM_ALLOWLIST,
  RELEASE_BLOCKED_TERMS,
} from './release-blocked-term-constants.mjs';

const BLOCKED_RELEASE_TERM_ALLOWLIST = DEFAULT_BLOCKED_RELEASE_TERM_ALLOWLIST.map((entry) => ({
  ...entry,
  linePattern: entry.linePattern ? new RegExp(entry.linePattern) : undefined,
}));

const SECRET_CONTENT_PATTERNS = [
  {
    name: 'private key block',
    pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/,
  },
  {
    name: 'encrypted private key block',
    pattern: new RegExp('-----BEGIN ENCRYPTED ' + 'PRIVATE KEY-----'),
  },
  {
    name: 'PGP private key block',
    pattern: new RegExp('-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----'),
  },
  {
    name: 'SSH2 encrypted private key block',
    pattern: new RegExp('---- BEGIN SSH2 ENCRYPTED ' + 'PRIVATE KEY ----'),
  },
  { name: 'AWS access key id', pattern: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'AWS temporary access key id', pattern: /\bASIA[0-9A-Z]{16}\b/ },
  {
    name: 'GCP service account key metadata',
    pattern: /"private_key_id"\s*:\s*"[A-Za-z0-9_-]{16,}"/,
  },
  {
    name: 'GitHub token',
    pattern: /\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,})\b/,
  },
  { name: 'OpenAI API key', pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { name: 'Anthropic API key', pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/ },
];

// Editorial terms apply only to known text; secret signatures still scan other files.
const RELEASE_TERM_EXTENSIONS = new Set([
  '',
  '.cjs',
  '.css',
  '.env',
  '.html',
  '.js',
  '.json',
  '.lock',
  '.md',
  '.mjs',
  '.sh',
  '.sql',
  '.toml',
  '.ts',
  '.tsx',
  '.txt',
  '.yaml',
  '.yml',
]);
const MARKDOWN_EXTENSIONS = new Set(['.md', '.mdx']);

function maskMarkdownCode(contents) {
  const lines = contents.split(/(?<=\n)/);
  let fence;
  return lines
    .map((line) => {
      const match = /^ {0,3}(`{3,}|~{3,})/.exec(line);
      if (match && (!fence || match[1][0] === fence)) {
        fence = fence ? undefined : match[1][0];
        return line.replace(/[^\n]/g, ' ');
      }
      if (fence) return line.replace(/[^\n]/g, ' ');
      return line.replace(/`+[^`\n]*`+/g, (value) => ' '.repeat(value.length));
    })
    .join('');
}

function markdownLinkDestinations(contents) {
  const masked = maskMarkdownCode(contents);
  const matches = [];
  const patterns = [
    /!?\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^\s)]+))[^\n]*?\)/g,
    /^\s{0,3}\[[^\]\n]+\]:\s*(?:<([^>\n]+)>|([^\s]+))/gm,
    /(?:href|src)\s*=\s*["']([^"']+)["']/gi,
  ];
  for (const pattern of patterns) {
    for (const match of masked.matchAll(pattern)) {
      matches.push({ destination: match[1] ?? match[2], index: match.index });
    }
  }
  return matches;
}

function markdownLineNumber(contents, index) {
  return contents.slice(0, index).split('\n').length;
}

function markdownRelativeTarget(destination, artifactPath) {
  const decoded = decodeURIComponent(destination.replace(/&amp;/g, '&'));
  if (!decoded || decoded.startsWith('#') || decoded.startsWith('//')) return;
  if (/^[A-Za-z][A-Za-z\d+.-]*:/.test(decoded)) return;

  const withoutFragment = decoded.split('#', 1)[0].split('?', 1)[0];
  if (!withoutFragment) return;
  return withoutFragment.startsWith('/')
    ? path.posix.normalize(withoutFragment.slice(1))
    : path.posix.normalize(path.posix.join(path.posix.dirname(artifactPath), withoutFragment));
}

function markdownLinkViolations(contents, artifactPath, rootDir, publishedPaths) {
  if (!MARKDOWN_EXTENSIONS.has(path.extname(artifactPath).toLowerCase())) return [];

  const violations = [];
  for (const { destination, index } of markdownLinkDestinations(contents)) {
    let target;
    let invalidDestination = false;
    try {
      target = markdownRelativeTarget(destination, artifactPath);
    } catch {
      invalidDestination = true;
    }
    if (!target && !invalidDestination) continue;

    const absoluteTarget = path.resolve(rootDir, target ?? '');
    const absoluteRoot = path.resolve(rootDir);
    const withinRoot =
      absoluteTarget === absoluteRoot || absoluteTarget.startsWith(`${absoluteRoot}${path.sep}`);
    const included =
      !publishedPaths ||
      publishedPaths.has(target) ||
      [...publishedPaths].some((publishedPath) => publishedPath.startsWith(`${target}/`));
    const exists = !invalidDestination && withinRoot && included && existsSync(absoluteTarget);
    if (!exists) {
      violations.push({
        path: artifactPath,
        line: markdownLineNumber(contents, index),
        reason: secretContentViolations(destination, artifactPath).length
          ? 'contains broken relative link (sensitive value redacted)'
          : `contains broken relative link "${destination}"`,
      });
    }
  }
  return violations;
}

export function artifactFileStatus(artifactPath, rootDir) {
  const absolutePath = path.resolve(rootDir, artifactPath);
  if (
    !absolutePath.startsWith(path.resolve(rootDir) + path.sep) &&
    absolutePath !== path.resolve(rootDir)
  ) {
    return { withinRoot: false };
  }
  if (!existsSync(absolutePath)) return { withinRoot: true, exists: false };
  const stat = statSync(absolutePath);
  return { withinRoot: true, exists: true, isFile: stat.isFile() };
}

function contentScanStatus(artifactPath, rootDir, fileStatus) {
  fileStatus ??= artifactFileStatus(artifactPath, rootDir);
  if (!fileStatus.withinRoot || !fileStatus.exists || !fileStatus.isFile) {
    return { scan: false };
  }
  return { scan: true };
}

function isBlockedTermAllowlisted(allowlist, artifactPath, line, term) {
  return allowlist.some((entry) => {
    if (entry.path !== artifactPath) return false;
    if (entry.term && entry.term !== term) return false;
    if (entry.linePattern && !entry.linePattern.test(line)) return false;
    return true;
  });
}

function databaseCredentialViolations(contents, artifactPath) {
  const violations = [];
  const urlPattern = /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis):\/\/[^\s"'`<>]+/gi;
  const localHosts = new Set(['localhost', '127.0.0.1', '::1', 'h', 'host', 'example.com']);
  for (const match of contents.matchAll(urlPattern)) {
    try {
      const url = new URL(match[0]);
      if (!url.username || !url.password || localHosts.has(url.hostname.toLowerCase())) continue;
      violations.push({
        path: artifactPath,
        reason: 'contains high-confidence secret pattern: database URL with embedded password',
      });
      break;
    } catch {
      // Malformed example URLs are not high-confidence secrets.
    }
  }
  return violations;
}

function secretContentViolations(contents, artifactPath) {
  const patternViolations = SECRET_CONTENT_PATTERNS.filter(({ pattern }) =>
    pattern.test(contents),
  ).map(({ name }) => ({
    path: artifactPath,
    reason: `contains high-confidence secret pattern: ${name}`,
  }));
  return [...patternViolations, ...databaseCredentialViolations(contents, artifactPath)];
}

function normalizeSensitiveText(value) {
  return value
    .normalize('NFKC')
    .replace(/[\u200B-\u200D\uFEFF*_`~]/g, '')
    .toLocaleLowerCase();
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function releaseBlockedTerms(ticketPrefixes = []) {
  return [
    ...RELEASE_BLOCKED_TERMS,
    ...ticketPrefixes.map((term) => ({
      category: 'ticket/process history',
      term,
      pattern: new RegExp(String.raw`\b${escapeRegExp(term)}(?:-\d+)?\b`, 'i'),
    })),
  ];
}

function blockedReleaseTermViolations(contents, artifactPath, ticketPrefixes) {
  const violations = [];
  contents.split(/\r?\n/).forEach((line, index) => {
    const normalizedLine = normalizeSensitiveText(line);
    for (const term of releaseBlockedTerms(ticketPrefixes)) {
      if (!term.pattern.test(normalizedLine)) continue;
      if (isBlockedTermAllowlisted(BLOCKED_RELEASE_TERM_ALLOWLIST, artifactPath, line, term.term)) {
        continue;
      }
      violations.push({
        path: artifactPath,
        line: index + 1,
        term: term.term,
        reason: `contains blocked release term "${term.term}" (${term.category})`,
      });
    }
  });
  return violations;
}

function blockedLiteralViolations(contents, artifactPath, values, reason) {
  const blockedValues = [
    ...new Set(values.map((value) => normalizeSensitiveText(value.trim())).filter(Boolean)),
  ];
  if (blockedValues.length === 0) return [];

  const violations = [];
  contents.split(/\r?\n/).forEach((line, index) => {
    const normalizedLine = normalizeSensitiveText(line);
    if (blockedValues.some((value) => normalizedLine.includes(value))) {
      violations.push({ path: artifactPath, line: index + 1, reason });
    }
  });
  return violations;
}

function blockedPatternViolations(contents, artifactPath, terms) {
  const violations = [];
  contents.split(/\r?\n/).forEach((line, index) => {
    for (const { term, pattern } of terms) {
      pattern.lastIndex = 0;
      if (!pattern.test(line)) continue;
      violations.push({
        path: artifactPath,
        line: index + 1,
        term,
        reason: `contains blocked content term "${term}"`,
      });
    }
  });
  return violations;
}

function ticketIdViolations(contents, artifactPath, includeTicketIds, ticketPrefixes) {
  const ticketPattern =
    ticketPrefixes.length > 0
      ? new RegExp(`\\b(?:${ticketPrefixes.map(escapeRegExp).join('|')})-\\d+\\b`, 'i')
      : undefined;
  const violations = [];
  contents.split(/\r?\n/).forEach((line, index) => {
    if (includeTicketIds && ticketPattern?.test(line)) {
      violations.push({ path: artifactPath, line: index + 1, reason: 'contains an internal ID' });
    }
  });
  return violations;
}

export function scanReleaseContentForViolations(contents, artifactPath, options = {}) {
  return [
    ...secretContentViolations(contents, artifactPath),
    ...blockedPatternViolations(contents, artifactPath, options.blockedContentTerms ?? []),
    ...blockedReleaseTermViolations(contents, artifactPath, options.ticketPrefixes ?? []),
    ...blockedLiteralViolations(
      contents,
      artifactPath,
      options.privateUrlPrefixes ?? [],
      'contains a private URL',
    ),
    ...blockedLiteralViolations(
      contents,
      artifactPath,
      options.employeeNames ?? [],
      'contains an employee name',
    ),
  ];
}

/** Scans supplied text for secrets and blocked content. */
export function scanArtifactContentForViolations(contents, artifactPath, options = {}) {
  const scanBlockedTerms =
    options.scanBlockedTerms !== false &&
    RELEASE_TERM_EXTENSIONS.has(path.extname(artifactPath).toLowerCase());
  return [
    ...secretContentViolations(contents, artifactPath),
    ...blockedPatternViolations(contents, artifactPath, options.blockedContentTerms ?? []),
    ...(scanBlockedTerms
      ? blockedReleaseTermViolations(contents, artifactPath, options.ticketPrefixes ?? [])
      : []),
    ...ticketIdViolations(contents, artifactPath, !scanBlockedTerms, options.ticketPrefixes ?? []),
    ...blockedLiteralViolations(
      contents,
      artifactPath,
      options.privateUrlPrefixes ?? [],
      'contains a private URL',
    ),
    ...blockedLiteralViolations(
      contents,
      artifactPath,
      options.employeeNames ?? [],
      'contains an employee name',
    ),
  ];
}

export function scanFileForContentViolations(artifactPath, rootDir, options = {}) {
  const status = contentScanStatus(artifactPath, rootDir, options.fileStatus);
  if (!status.scan) return [];

  const contents = readFileSync(path.resolve(rootDir, artifactPath), 'utf8');
  return [
    ...scanArtifactContentForViolations(contents, artifactPath, options),
    ...markdownLinkViolations(contents, artifactPath, rootDir, options.publishedPaths),
  ];
}
