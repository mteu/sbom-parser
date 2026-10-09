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
$component->licenses ?? [];     // Array of LicenseChoice objects
$component->hashes ?? [];       // Array of Hash objects
$component->authors ?? [];      // Array of OrganizationalContact objects (1.6+)
$component->tags ?? [];         // Array of tag strings (1.6+)
$component->components ?? [];   // Nested components
$component->hasComponents();    // Check if has nested components
```

### License Entity: [`LicenseChoice`](../src/Entity/LicenseChoice.php)

CycloneDX does not list licenses directly. Each entry in `licenses` is a
`LicenseChoice`, which carries *either* a `License` object *or* an SPDX
license expression:

```php
foreach ($component->licenses ?? [] as $licenseChoice) {
    if ($licenseChoice->hasExpression()) {
        $licenseChoice->expression;     // e.g. 'Apache-2.0 OR MIT'

        continue;
    }

    $licenseChoice->license?->id;       // SPDX identifier, e.g. 'MIT'
    $licenseChoice->license?->name;     // Named license, when no SPDX id applies
    $licenseChoice->license?->url;      // Reference URL, if provided
}
```

The same shape applies to `Service::$licenses` and
`ComponentEvidence::$licenses`.

### Vulnerability Analysis: [`VulnerabilityAnalysis`](../src/Entity/Vulnerability/VulnerabilityAnalysis.php)

A VEX document records its verdict in `vulnerabilities[].analysis`. The
`state`, `justification` and `response` fields are enums.

```php
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisState;

foreach ($bom->vulnerabilities ?? [] as $vulnerability) {
    $analysis = $vulnerability->analysis;

    if ($analysis?->state === ImpactAnalysisState::NOT_AFFECTED) {
        $analysis->justification;      // ImpactAnalysisJustification, e.g. CODE_NOT_REACHABLE
    }

    $analysis?->response;              // list<ImpactAnalysisResponse>, e.g. [UPDATE]
    $analysis?->detail;                // Free text written by a person: escape it before display
}
```

The vocabulary is the same in every supported spec version. A value outside
it fails the parse with an `SbomParseException` whose `$details` name the path,
such as `vulnerabilities.2.analysis.state`.

A VEX document may carry no `components` at all. It parses like any other
document, and `Bom::hasComponents()` returns `false`.

### Timestamps

Every date field is a `\DateTimeImmutable` parsed from an RFC 3339 timestamp,
as the schemas require: `2026-10-01T09:15:00Z`, `2026-10-01T11:15:00+02:00`, or
either with a fraction of a second. The parsed date keeps the offset from the
document, and `Z` means UTC whatever the server's default time zone is.

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
The message format may change. When the  document itself is wrong, read
`$e->details` instead since it lists one `ParseErrorDetail` per value that
could not be mapped, in document order.

```php
foreach ($e->details as $detail) {
    $detail->path;    // e.g. "vulnerabilities.2.analysis.state"; "" for the document root
    $detail->message; // e.g. "Value 'nope' does not match any of ..."
}
```

The path uses the document's own key names, such as `components.0.bom-ref`.
The message may quote the value from the document, so escape it before
rendering! `$details` is empty when parsing failed before mapping. Invalid
JSON, an unsupported format or version, a file that cannot be read, or a
document over the size or node limits.
