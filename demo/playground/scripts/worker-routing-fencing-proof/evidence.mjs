// Fail-closed evidence contract for the two-worker routing/fencing proof.
// The host validates the driver result (protocol, status, and that every
// required acceptance check is present and PASS) and each worker result
// (protocol, node-22/linux/uid provenance, clean cleanup, no idle pool errors).
// A missing, failed, or unexpected-protocol record is a hard failure, not a gap.

// Required driver checks, grouped by the acceptance criterion they prove.
// The union is the full driver matrix (S1 routing, S2 drain, S3 dead-owner/
// catalog-down, S4 fencing, S5 forged-hop/privilege/boundary, S6
// prerequisite/combined-gate); every name must PASS and no other check may
// fail. The count is derived from this object at load time -- requiredChecks()
// below -- so it can never drift from the set it documents.
export const REQUIRED = {
  routingMatrix: [
    'matrix-clean-start',
    'matrix-create-owners',
    'matrix-create-persists-did',
    'matrix-duplicate-refused',
    'matrix-ping-body-transport',
    'matrix-reset-restores-seed',
    'matrix-final-quantity-seed-A',
    'matrix-final-quantity-seed-B',
    'matrix-did-stable-A',
    'matrix-did-stable-B',
    'matrix-no-new-identity-on-forward',
    'matrix-one-live-session-per-sandbox',
    'matrix-unknown-cookie-410',
    'matrix-non-owner-forwarded',
    'matrix-cleared',
    ...[
      'status', 'query', 'rawsql', 'agents', 'present', 'delegate',
      'audit', 'renew', 'mutate', 'reset', 'rawbytes', 'ping',
    ].flatMap((op) => [`matrix-${op}-A-owner`, `matrix-${op}-A-nonowner`,
      `matrix-${op}-B-owner`, `matrix-${op}-B-nonowner`]),
    'matrix-static-unrouted-root',
    'matrix-static-unrouted-healthz',
    'matrix-static-unrouted-readyz',
  ],
  drain: [
    'drain-recorded-deadline',
    'drain-session-marked-draining',
    'drain-admission-race-rejected',
    'drain-admission-race-no-row',
    'drain-new-session-refused',
    'drain-readyz-alive-admission-closed',
    'drain-existing-status-alive',
    'drain-existing-query-alive',
    'drain-worker-a-restored-active',
    'retire-control-applied',
    'retired-no-admission',
    'drain-no-state-migration',
    'drain-janitor-reaps-retired-worker-session',
    'drain-reaped-session-lost-generation-bumped',
    'drain-state-discarded-on-loss',
    'drain-worker-reset-active',
  ],
  deadOwner: [
    'dead-owner-janitor-reaps-lost',
    'dead-owner-session-lost',
    'dead-owner-worker-drops-belief',
    'dead-owner-no-reroute-lost',
    'dead-owner-state-discarded',
    'catalog-down-mutation-fails-closed',
    'catalog-down-no-ambiguous-commit',
    'catalog-recovered-same-session',
    'dead-owner-worker-restored-active',
  ],
  fencing: [
    'fence-reset-commits',
    'fence-bump-applied',
    'fence-stale-generation-rejected',
    'fence-stale-mutation-not-committed',
    'fence-transaction-evidence',
    'fence-revalidate-adopts-generation',
    'fence-renewal-after-revalidate',
    'fence-current-generation-commits',
    'fence-current-mutation-committed',
    'fence-lease-expired-rejected',
    'fence-lease-expired-not-committed',
    'fence-lease-renew-restores',
    'fence-inflight-holds-advisory-lock',
    'fence-janitor-defers-inflight',
    'fence-bump-blocked-while-inflight',
    'fence-transfer-blocked-while-inflight',
    'fence-drain-deadline-rejected',
    'fence-lock-released-after-inflight',
    'fence-inflight-no-partial-write',
    'fence-janitor-reaps-drained',
    'fence-drained-session-deleted-generation-bumped',
    'fence-drain-runtime-discarded',
    'fence-owner-retired-rejected',
    'fence-owner-retired-not-committed',
    'fence-janitor-reaps-owner-dead',
    'fence-reaped-owner-dead-lost',
    'fence-worker-restored-active',
    'fence-stale-resume-rejected',
    'fence-stale-resume-not-committed',
    'fence-stale-resume-revalidate-report',
    'fence-transfer-stable-runtime-identity',
    'fence-transfer-bumps-generation',
    'fence-transfer-old-entry-incompatible',
    'fence-transfer-nonholder-incompatible',
    'fence-transfer-no-new-identity',
    'fence-transfer-back-holder-report',
  ],
  forgedHop: [
    'forged-hop-bad-signature-rejected',
    'forged-hop-hop-limit-rejected',
    'forged-hop-deadline-rejected',
    'forged-hop-stale-generation-rejected',
    'forged-hop-cross-secret-rejected',
    'forged-hop-wrong-destination-rejected',
    'forged-hop-missing-headers-rejected',
    'forged-hop-valid-hop-accepts',
    'priv-public-no-privileged-execute',
    'priv-data-roles-no-privileged-execute',
    'priv-control-allowlist-complete',
    'priv-data-roles-keep-safe-reads',
    'priv-unauthorized-call-denied-42501',
    'public-origin-foreign-rejected',
    'public-origin-allowed-accepts',
    'public-host-foreign-rejected',
    'public-host-allowed-accepts',
  ],
  workloadAuth: [
    'prereq-runtime-lifecycle-887',
    'prereq-sql-isolation-888',
    'combined-gate-catalog-snapshot',
  ],
};

export function requiredChecks() {
  return Object.values(REQUIRED).flat();
}

// Node 22 linux container, unprivileged uid > 0 (the canonical image).
export function provenanceMatches(runtime) {
  return /^v22\./.test(runtime?.node ?? '') && runtime?.platform === 'linux'
    && Number.isInteger(runtime?.uid) && runtime.uid > 0;
}

export function resultFailures(result) {
  const failures = [];
  if (!result || result.protocol !== 1) failures.push('missing-or-invalid-protocol');
  if (!result || !['PASS', 'FAIL'].includes(result?.status)) failures.push('missing-status');
  if (!result || !Array.isArray(result.checks) || result.checks.length === 0) failures.push('missing-checks');
  return failures;
}

// The driver must PASS every required check and have no other failure.
export function driverEvidenceFailures(result) {
  const failures = resultFailures(result);
  if (failures.length) return failures;
  const passing = new Set(result.checks.filter((c) => c.status === 'PASS').map((c) => c.name));
  for (const name of requiredChecks()) if (!passing.has(name)) failures.push(`missing-pass:${name}`);
  for (const c of result.checks) if (c.status !== 'PASS') failures.push(`failed:${c.name}`);
  if (!result.acceptance?.combinedGate?.routingDrainingFencing) failures.push('combined-gate-routing');
  if (!result.acceptance?.combinedGate?.staleOwnerSafety) failures.push('combined-gate-stale-owner');
  if (result.acceptance?.combinedGate?.runtimeLifecycle887 !== 'PASS') failures.push('prerequisite-runtime-887');
  if (result.acceptance?.combinedGate?.sqlIsolation888 !== 'PASS') failures.push('prerequisite-sql-888');
  if (!result.workloadAuth?.productionRequirement || result.workloadAuth.claimed === true) failures.push('workload-auth-not-stated');
  return failures;
}

// Worker (serve) result: protocol, provenance, clean cleanup, no pool errors.
export function workerEvidenceFailures(result) {
  const failures = resultFailures(result);
  if (failures.length) return failures;
  if (!provenanceMatches(result.runtime)) failures.push('image-runtime-provenance');
  if (result.poolError) failures.push('idle-pool-errors');
  if (result.cleanup?.status !== 'PASS') failures.push('worker-cleanup');
  for (const c of result.cleanup?.resources ?? []) if (c.status !== 'PASS') failures.push(`cleanup:${c.resource}`);
  return failures;
}
