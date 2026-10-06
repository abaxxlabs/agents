export const RELEASE_BLOCKED_TERMS = [
  {
    category: 'ticket/process history',
    term: 'PR #',
    pattern: /\bPR\s+#\d+\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'pre-landing',
    pattern: /\bpre[- ]landing\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'adversarial review',
    pattern: /\badversarial review\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'agent workflow',
    pattern: /\bagent workflow\b/i,
  },
  {
    category: 'ticket/process history',
    term: 'handoff',
    pattern: /\bhandoff\b/i,
  },
  {
    category: 'temporal/internal delivery history',
    term: 'Session',
    pattern: /\b(?:post-)?Sessions?\s*[- ]\s*\d+\b/i,
  },
  {
    category: 'temporal/internal delivery history',
    term: 'Phase',
    pattern: /\bPhase\s*[- ]\s*\d+\b/i,
  },
  {
    category: 'temporal/internal delivery history',
    term: 'hackathon',
    pattern: /\bhackathon\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'commercial',
    pattern: /\bcommercial\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'paid',
    pattern: /\bpaid\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'upgrade path',
    pattern: /\bupgrade path\b/i,
  },
  {
    category: 'strategy/commercial positioning',
    term: 'open-core',
    pattern: /\bopen[- ]core\b/i,
  },
];

export const DEFAULT_BLOCKED_RELEASE_TERM_ALLOWLIST = [
  {
    path: 'scripts/release-blocked-term-constants.mjs',
    linePattern: String.raw`^\s*(?:(?:category|term|pattern|linePattern):)`,
    reason: 'The generic release audit policy must declare the exact editorial terms it enforces.',
  },
  {
    path: 'LICENSE',
    linePattern: String.raw`other commercial damages or losses`,
    reason:
      'Standard Apache License 2.0 section 8 boilerplate ("damages or losses"); not project-authored positioning.',
  },
];
