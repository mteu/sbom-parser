<div align="center">

[![CGL](https://github.com/mteu/sbom-parser/actions/workflows/cgl.yaml/badge.svg)](https://github.com/mteu/sbom-parser/actions/workflows/cgl.yaml)
[![Tests](https://github.com/mteu/sbom-parser/actions/workflows/tests.yaml/badge.svg?branch=main)](https://github.com/mteu/sbom-parser/actions/workflows/tests.yaml)
[![Coverage](https://coveralls.io/repos/github/mteu/sbom-parser/badge.svg?branch=main)](https://coveralls.io/github/mteu/sbom-parser?branch=main)
[![Maintainability](https://qlty.sh/gh/mteu/projects/sbom-parser/maintainability.svg)](https://qlty.sh/gh/mteu/projects/sbom-parser)

# CycloneDX SBOM Parser

[![PHP Version Require](https://poser.pugx.org/mteu/sbom-parser/require/php)](https://packagist.org/packages/mteu/sbom-parser)

</div>

CycloneDX SBOM (Software Bill of Materials) parser for PHP 8.3+. Supports [CycloneDX 1.4+ specifications](https://github.com/CycloneDX/specification) including components, vulnerabilities, and metadata with full immutable entity design using Valinor for type mapping.

## ⚡️ Quick Start
```php
use mteu\SbomParser\Parser\CycloneDxParser;

$parser = new CycloneDxParser();
$bom = $parser->parseFromFile('/path/to/sbom.json');

// Access components and vulnerabilities
$components = $bom->getAllComponents();
$vulnerabilities = $bom->getVulnerabilities();
```

See [detailed documentation](docs/cyclonedx-parser.md) for complete usage examples and API reference.

## 🤝 Contributing
Contributions are very welcome! Please have a look at the [Contribution Guide](CONTRIBUTING.md). It lays out the
workflow of submitting new features or bugfixes.

## 🔒 Security
Please refer to our [security policy](SECURITY.md) if you discover a security vulnerability in
this extension. Be warned, though. I cannot afford bounty. This is private project.

## ⭐ License
This extension is licensed under the [GPL-3.0-or-later](LICENSE) license.

## 💬 Support
For issues and feature requests, please use the [GitHub issue tracker](https://github.com/mteu/sbom-parser/issues).
