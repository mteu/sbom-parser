# Contributing

## Fork & Pull Request Workflow

1. Fork this repository
2. Create feature branch: `git checkout -b feature/your-feature`
3. Install dependencies: `composer install`
4. Make your changes
5. Run quality checks:
   ```bash
   composer lint    # Check code style
   composer fix     # Fix code style issues
   composer sca     # Static analysis
   composer test    # Run tests
   ```
6. Commit: `git commit -m "Add your feature"`
7. Push: `git push origin feature/your-feature`
8. Create Pull Request on GitHub

## Requirements

- PHP 8.3+
- All tests must pass
- Code must pass PHPStan level max
- Follow existing code style (final readonly classes)
- Access properties directly instead of getters

## Testing

```bash
composer test                    # All tests
composer test:unit               # Unit tests only
composer test:coverage           # With coverage
composer test:mutation           # Mutation tests (needs pcov or Xdebug)
```

Mutation testing runs [Infection](https://infection.github.io/) against the
unit suite. On pull requests, CI mutates only the changed lines and every
mutant must be killed. On `main`, it mutates all of `src/` against the
thresholds in `infection.json5`. Changes that cannot affect the result
(docs, other workflows, integration tests) skip the workflow. To check your
branch the same way a pull request does:

```bash
composer test:mutation -- --git-diff-lines --git-diff-base=origin/main --min-msi=100 --min-covered-msi=100
```

Reports land in `.build/infection/`. If a mutant cannot change observable
behaviour (an equivalent mutant), ignore it in `infection.json5` and write
down why.

Run specific tests:
```bash
phpunit -c phpunit.unit.xml tests/Unit/Entity/BomTest.php
phpunit -c phpunit.unit.xml --filter testMethodName
```

## Entity/schema conformance

Entity constructors are the schema binding: the parser maps JSON keys onto
constructor parameters by name and silently ignores keys it cannot place.
`tests/Integration/EntitySchemaConformanceTest.php` compares every entity
against the bundled CycloneDX schemas (1.4 to 1.7) in both directions:

- every schema property needs a matching parameter, or an entry in
  `KNOWN_UNMODELLED` naming its tracking issue;
- every parameter needs a matching schema key, so a misspelt name fails
  instead of staying `null` forever.

When you model a field, delete its `KNOWN_UNMODELLED` line; the test fails
until you do. Hyphenated keys (`bom-ref`, `mime-type`, `x-trust-boundary`)
are converted by `CycloneDxParser::SCHEMA_KEY_ALIASES`. New entity classes
must be added to `SCHEMA_POINTERS`.

The schemas in `tests/Fixtures/schemas` are official CycloneDX files pinned
to one specification release. `composer schemas:check` verifies them (CI
runs it); `composer schemas:update` refreshes them. See the README in that
directory.
