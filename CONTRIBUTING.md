# Contributing to Agents++

Contributions are welcome. This is a security-sensitive identity and cryptography library, so all changes go through review.

## Getting Started

1. Fork the repository
2. Create a feature branch from `main` (`git checkout -b my-feature`)
3. Install dependencies:
   ```bash
   bun install
   ```
4. Run the test suite to confirm everything passes before making changes:
   ```bash
   npm test
   ```

`bun.lock` is the canonical lockfile for this repo. Use `bun install` so contributor changes stay in sync; do not regenerate `package-lock.json`. Consumers installing `@abaxxlabs/agents` from npm are unaffected and can use any package manager.

## Development

### Available Scripts

| Script             | Description                                   |
|--------------------|-----------------------------------------------|
| `npm test`         | Run all tests (vitest)                        |
| `npm run test:watch` | Run tests in watch mode                     |
| `npm run build`    | Build ESM and CJS outputs                     |
| `npm run typecheck`| Type-check without emitting                   |
| `npm run lint`     | Lint with ESLint                              |
| `npm run lint:fix` | Auto-fix lint issues                          |
| `npm run format`   | Format with Prettier                          |

### Requirements

- Node.js >= 20.3.0
- Bun >= 1.3 (required dev tooling; the canonical lockfile is `bun.lock`)
- PostgreSQL (for integration tests): `supabase start` or a local Docker instance
- TypeScript -- all source is in `src/`, all tests in `test/`

## Code Style

- **TypeScript** -- no `any` without justification
- **Tests required** -- every PR that changes behavior should include or update tests
- **Comments** -- document _why_, not just _what_. This codebase carries product decisions, security considerations, and architectural tradeoffs in its comments. Continue that practice.
- **Formatting** -- run `npm run format` before submitting

## Pull Requests

1. Describe **what** changed and **why**
2. Include or update tests for any behavioral changes
3. Confirm `npm test` and `npm run typecheck` pass
4. Keep PRs focused -- one logical change per PR
5. If the change touches security-sensitive code (key handling, credential verification, scope enforcement, encryption), call that out explicitly in the PR description

## Reporting Issues

- **Security issues**: see [SECURITY.md](SECURITY.md) -- do not use public GitHub issues
- **Bugs**: open a GitHub issue with steps to reproduce, expected behavior, and actual behavior
- **Feature requests**: open a GitHub issue describing the use case and proposed approach

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
