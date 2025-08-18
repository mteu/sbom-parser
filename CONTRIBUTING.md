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
```

Run specific tests:
```bash
phpunit -c phpunit.unit.xml tests/Unit/Entity/BomTest.php
phpunit -c phpunit.unit.xml --filter testMethodName
```
