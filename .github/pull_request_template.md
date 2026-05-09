<!--
  This template is shown for EVERY PR. Most PRs check only the "all PRs"
  section. Breaking-change PRs (semver minor on 0.x, semver major post-1.0)
  must clear the additional checklist below.
-->

## Summary

<!-- 1-3 sentences. What changes for the consumer? -->

## Why

<!-- The motivation. Issue link, ticket, customer ask. -->

## All PRs — required boxes

- [ ] Tests pass locally (`npm test`)
- [ ] Type-check passes (`npm run typecheck`)
- [ ] No new dependencies, OR new deps are >1 month old AND not security-sensitive
- [ ] CHANGELOG updated (or N/A noted in PR description)

## Breaking-change PRs — additional boxes

<!-- Skip if this PR is non-breaking. -->

- [ ] Every `@inject` / `injections.X` claim in changed JSDoc resolves to a real type-system path (LSP-traceable, not aspirational)
- [ ] Every JSDoc `@example` block in changed `src/**` files type-checks against the actual signatures (verified by the JSDoc CI workflow at `.github/workflows/jsdoc-types.yml`)
- [ ] Ran `/review` skill before declaring ready for review; addressed or documented every CRITICAL finding
- [ ] An end-to-end test exists for any new injection seam, capturing the "this would have failed pre-change" regression case (template: `test/regression/injection-drift.test.ts`)
- [ ] Migration guide added at `docs/migration-<feature>.md` if consumers must change their bootstrap or types
- [ ] Rollback procedure documented at `docs/rollback-<version>.md` if any DB schema, persisted-state, or configuration shape changed
- [ ] External partners or design-partner integrations notified if they are affected by the change

## Test plan

<!-- Bulleted list of what was tested and how. Include browser smoke-test results
     for UI changes, curl outputs for API changes, integration runs for DB changes. -->

## Notes for the reviewer

<!-- Anything specific the reviewer should focus on. -->
