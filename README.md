<div align="center">

[![CGL](https://github.com/mteu/sbom-parser/actions/workflows/cgl.yaml/badge.svg)](https://github.com/mteu/sbom-parser/actions/workflows/cgl.yaml)
[![Tests](https://github.com/mteu/sbom-parser/actions/workflows/tests.yaml/badge.svg?branch=main)](https://github.com/mteu/sbom-parser/actions/workflows/tests.yaml)
[![Coverage](https://coveralls.io/repos/github/mteu/sbom-parser/badge.svg?branch=main)](https://coveralls.io/github/mteu/sbom-parser?branch=main)
[![Maintainability](https://qlty.sh/gh/mteu/projects/sbom-parser/maintainability.svg)](https://qlty.sh/gh/mteu/projects/sbom-parser)
[![PHP Version Require](https://poser.pugx.org/mteu/sbom-parser/require/php)](https://packagist.org/packages/mteu/sbom-parser)

# CycloneDX SBOM Parser
</div>

CycloneDX SBOM (Software Bill of Materials) parser for PHP 8.3+. Supports
[CycloneDX 1.4+ specifications](https://github.com/CycloneDX/specification) including components, vulnerabilities, and
metadata with full immutable entity design using Valinor for type mapping.

> [!NOTE]
> The CycloneDX ecosystem provides an official PHP library
> ([`cyclonedx/cyclonedx-library`](https://github.com/CycloneDX/cyclonedx-php-library))
> and a [Composer plugin](https://github.com/CycloneDX/cyclonedx-php-composer) for
> generating SBOMs. These tools are designed to produce BOMs as part of your build
> pipeline — not for consuming them in application code.
>
> This package aims to fill a different gap: Reading and inspecting existing SBOM
> files.
>
> If your application needs to parse a CycloneDX SBOM and work with its data —
> querying components, checking vulnerabilities, reading metadata — you need a
> lightweight, read-only library with clean, type-safe objects. That is what this
> package aims to provide.

## ⚡️ Quick Start
```php
use mteu\SbomParser\Parser\CycloneDxParser;

$parser = new CycloneDxParser();
$bom = $parser->parseFromFile('/path/to/sbom.json');

// Access components and vulnerabilities
$components = $bom->getAllComponents();
$vulnerabilities = $bom->vulnerabilities;
```

See [detailed documentation](docs/cyclonedx-parser.md) for complete usage examples and API reference.

## 🤝 Contributing
Contributions are very welcome! Please have a look at the [Contribution Guide](CONTRIBUTING.md). It lays out the
workflow of submitting new features or bugfixes.

## 🔒 Security
Please refer to the [security policy](SECURITY.md) if you discover a security vulnerability in
this extension. Be warned, though. I cannot afford bounty.

## ⭐ License
This extension is licensed under the [GPL-3.0-or-later](LICENSE) license.

## 💬 Support
For issues and feature requests, please use the [GitHub issue tracker](https://github.com/mteu/sbom-parser/issues).
