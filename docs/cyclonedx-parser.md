# CycloneDx Parser

Type-safe parser for CycloneDX 1.4+ Software Bill of Materials files with comprehensive validation and modern PHP architecture.

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

- `parseFromFile(string $filePath): Bom` - Parse from absolute file path with security validation
- `parseFromJson(string $json): Bom` - Parse from JSON string with type validation
- `parseFromArray(array $data): Bom` - Parse from decoded array with schema validation
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
$component = $bom->findComponentByPurl('pkg:npm/lodash@4.17.21');
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
