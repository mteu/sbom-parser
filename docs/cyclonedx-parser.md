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

### Parser Class: `CycloneDxParser`

Location: `src/Parser/CycloneDxParser.php`

Modern SBOM parser implementing the `Parser` interface with comprehensive validation:

- `parseFromFile(string $filePath): Bom` - Parse from absolute file path with security validation
- `parseFromJson(string $json): Bom` - Parse from JSON string with type validation
- `parseFromArray(array $data): Bom` - Parse from decoded array with schema validation
- `isValidSbomFile(string $filePath): bool` - Validate file without full parsing
- `isValidSbomJson(string $json): bool` - Validate JSON without full parsing
- `isValidSbomArray(array $data): bool` - Validate array without full parsing

### Main Entity: `Bom`

Location: `src/Entity/Bom.php`

Represents the complete SBOM with helper methods:

```php
// Access basic properties
$bom->getBomFormat();     // "CycloneDX"
$bom->getSpecVersion();   // "1.6"
$bom->getSerialNumber();  // Optional serial number

// Get components
$components = $bom->getComponents();        // Direct components
$allComponents = $bom->getAllComponents();  // Including nested

// Get vulnerabilities
$vulnerabilities = $bom->getVulnerabilities();

// Find specific components
$libraries = $bom->findComponentsByType(ComponentType::LIBRARY);
$component = $bom->findComponentByPurl('pkg:npm/lodash@4.17.21');
```

### Component Entity: `Component`

Location: `src/Entity/Component.php`

Represents individual software components:

```php
$component->getName();           // Component name
$component->getVersion();        // Version string
$component->getType();          // ComponentType enum
$component->getPackageUrl();    // PURL if available
$component->getLicenses();      // Array of License objects
$component->getHashes();        // Array of Hash objects
$component->getComponents();    // Nested components
```

## Validation

The parser includes comprehensive validation:

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

## Working with Components

```php
foreach ($bom->getAllComponents() as $component) {
    printf("%-30s %s\n", $component->getName(), $component->getVersion());

    // Check component type
    if ($component->getType() === ComponentType::LIBRARY) {
        echo "  Library component\n";
    }

    // Get licenses
    foreach ($component->getLicenses() as $license) {
        if ($license->getSpdxId()) {
            echo "  License: " . $license->getSpdxId() . "\n";
        }
    }

    // Get package URL (for ecosystem identification)
    if ($component->getPackageUrl()) {
        echo "  PURL: " . $component->getPackageUrl() . "\n";
    }
}
```

## Working with Vulnerabilities

```php
foreach ($bom->getVulnerabilities() as $vulnerability) {
    echo "Vulnerability: " . $vulnerability->getId() . "\n";
    echo "Description: " . $vulnerability->getDescription() . "\n";

    // Get severity rating
    $highestRating = $vulnerability->getHighestSeverityRating();
    if ($highestRating) {
        echo "Severity: " . $highestRating->getSeverity() . "\n";
        echo "Score: " . $highestRating->getScore() . "\n";
    }

    // Get affected components
    foreach ($vulnerability->getAffects() as $affects) {
        echo "Affects: " . $affects->getRef() . "\n";
        foreach ($affects->getVersions() as $versionRange) {
            echo "  Version: " . $versionRange->getVersion() . "\n";
            echo "  Range: " . $versionRange->getRange() . "\n";
        }
    }
}
```

## Advanced Usage

### Component Filtering

```php
// Filter components by analyzable status
$analyzableComponents = array_filter(
    $bom->getAllComponents(),
    fn(Component $c) => $c->getType() !== ComponentType::OPERATING_SYSTEM
        && $c->getVersion() !== null
        && !str_contains($c->getVersion(), '*')
);

// Find components by ecosystem
$npmComponents = array_filter(
    $bom->getAllComponents(),
    fn(Component $c) => str_starts_with($c->getPackageUrl() ?? '', 'pkg:npm/')
);
```

## Supported Formats

- **CycloneDX 1.4+** - Primary support
- **CycloneDX 1.5** - Full support
- **CycloneDX 1.6** - Full support with latest features
- **JSON format** - Primary format support
