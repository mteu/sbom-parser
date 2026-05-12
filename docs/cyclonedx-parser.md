# CycloneDx Parser

Type-safe parser for CycloneDX 1.4+ Software Bill of Materials files with comprehensive validation and modern PHP architecture.

> **Note:** Only the **JSON** form of the CycloneDX specification is
> supported. The XML form is out of scope for this package.

## Quick Start

```php
use mteu\SbomParser\Parser\CycloneDxParser;

$parser = new CycloneDxParser();

// Parse from file (recommended)
$bom = $parser->parseFromFile('/path/to/sbom.json');

// Parse from JSON string
$jsonContent = file_get_contents('/path/to/sbom.json');
$bom = $parser->parseFromJson($jsonContent);

// Parse from decoded array
$data = json_decode($jsonContent, true);
$bom = $parser->parseFromArray($data);
```

## Core Components

### Parser Class: [`CycloneDxParser`](../src/Parser/CycloneDxParser.php)
SBOM parser implementing the `Parser` interface with comprehensive validation:

- `parseFromFile(string $filePath): Bom` - Parse from absolute file path with security validation.
- `parseFromArray(array $data): Bom` - Parse from decoded array with schema validation (the same `bomFormat` / `specVersion` / Valinor mapping checks as the JSON paths still apply)
- `isValidSbomFile(string $filePath): bool` - Validate file without full parsing
- `isValidSbomJson(string $json): bool` - Validate JSON without full parsing
- `isValidSbomArray(array $data): bool` - Validate array without full parsing

### Main Entity: [`Bom`](../src/Entity/Bom.php)
Represents the complete SBOM with helper methods:

```php
// Access basic properties
$bom->bomFormat;          // "CycloneDX"
$bom->specVersion;        // "1.6"
$bom->serialNumber;       // Optional serial number

// Get components
$components = $bom->components ?? [];       // Direct components
$allComponents = $bom->getAllComponents();  // Including nested

// Get vulnerabilities and services
$vulnerabilities = $bom->vulnerabilities ?? [];
$services = $bom->services ?? [];

// Find specific components
$libraries = $bom->findComponentsByType(ComponentType::LIBRARY);
$component = $bom->findComponentByPurl('pkg:composer/symfony/console@7.1.0');
```

### Component Entity: [`Component`](../src/Entity/Component.php)

Represents individual software components:

```php
$component->name;               // Component name
$component->version;            // Version string
$component->type;               // ComponentType enum
$component->purl;               // PURL if available
$component->licenses ?? [];     // Array of License objects
$component->hashes ?? [];       // Array of Hash objects
$component->components ?? [];   // Nested components
$component->hasComponents();    // Check if has nested components
```

## File Validation

The parser includes validation:

```php
// Validate before parsing
if ($parser->isValidSbomFile('/path/to/sbom.json')) {
    $bom = $parser->parseFromFile('/path/to/sbom.json');
}

if ($parser->isValidSbomJson($jsonString)) {
    $bom = $parser->parseFromJson($jsonString);
}

if ($parser->isValidSbomArray($decodedData)) {
    $bom = $parser->parseFromArray($decodedData);
}
```

## Configuration

`CycloneDxParser` is configured via an immutable `CycloneDxParserOptions` DTO. Default construction needs no arguments:

```php
$parser = new CycloneDxParser();
```

To override defaults, build a `CycloneDxParserOptions` and pass it in:

```php
use mteu\SbomParser\Parser\Configuration\CycloneDxParserOptions;
use mteu\SbomParser\Parser\CycloneDxParser;

// All arguments are optional
$options = new CycloneDxParserOptions(
    maxFileSize: 50 * 1024 * 1024,
    maxNodes: 5_000_000,
    allowedBaseDirectories: ['/srv/sboms'],
);

$parser = new CycloneDxParser($options);

// Or use the fluent `with*` mutators to change individual options while preserving the others.
$parser = new CycloneDxParser(
    (new CycloneDxParserOptions())
        ->withMaxFileSize(50 * 1024 * 1024)
        ->withMaxNodes(5_000_000)
        ->withAllowedBaseDirectories(['/srv/sboms', '/var/www/bom']),
);
```

### File size limit

`parseFromFile` and `isValidSbomFile` enforce a default cap of 10 MiB (`CycloneDxParserOptions::DEFAULT_MAX_FILE_SIZE`). Raise it by configuring `maxFileSize` on the options DTO as shown above.

### Max node limit

`parseFromArray` enforces a default maximum total node count in the decoded SBOM tree of `1_000_000` nodes to parsed (`CycloneDxParserOptions::DEFAULT_MAX_NODES`). Raise it by configuring `maxNodes` on the options DTO as shown above.

### Allowed base directories

`parseFromFile` and `isValidSbomFile` perform absolute-path and directory-traversal
checks on every call, but by default they will happily read any `.json` file the
PHP process has access to. When the file path comes from untrusted input (HTTP request,
queue payload, CLI argument), restrict reads to a known set of directories by configuring
`allowedBaseDirectories`:

```php
$parser = new CycloneDxParser(
    new CycloneDxParserOptions(allowedBaseDirectories: ['/srv/sboms']),
);

// Accepted - resolves under /srv/sboms
$parser->parseFromFile('/srv/sboms/customer-42/bom.json');

// Rejected - SbomParseException
$parser->parseFromFile('/etc/passwd.json');
```

## Error Handling

All parsing methods throw `SbomParseException` on failure:

```php
use mteu\SbomParser\Exception\SbomParseException;

try {
    $bom = $parser->parseFromFile('/path/to/sbom.json');
} catch (SbomParseException $e) {
    // Handle parsing errors
    error_log('SBOM parsing failed: ' . $e->getMessage());
}
```
