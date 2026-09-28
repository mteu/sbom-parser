<?php

declare(strict_types=1);

/*
 * This file is part of the package "mteu/sbom-parser".
 *
 * Copyright (C) 2026 Martin Adler <mteu@mailbox.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

namespace mteu\SbomParser\Tests\Integration;

use mteu\SbomParser\Entity;
use mteu\SbomParser\Entity\Vulnerability;
use mteu\SbomParser\Parser\CycloneDxParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Guards the binding between entity constructors and the CycloneDX schemas.
 *
 * The parser maps with `allowSuperfluousKeys()`, so a schema property without
 * a matching constructor parameter is discarded silently, and a parameter
 * whose name matches no schema property never receives data. Both failure
 * modes are invisible to tests that only assert on modelled fields. This test
 * compares names in both directions for every supported spec version.
 *
 * Accepted gaps live in {@see self::KNOWN_UNMODELLED}. Modelling a field means
 * deleting its line there; the stale-entry check enforces that.
 *
 * Only names are compared. A property that is modelled under the right name
 * but with the wrong type is out of reach for this test.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final class EntitySchemaConformanceTest extends TestCase
{
    /**
     * Entity class => JSON pointers into the schema that describe its shape.
     * A pointer that does not exist in a given spec version is skipped for it.
     * Array nodes are unwrapped to their items; `oneOf`/`anyOf`/`allOf`
     * branches are merged, because the entities flatten choices into one class.
     *
     * @var array<class-string, list<string>>
     */
    private const array SCHEMA_POINTERS = [
        Entity\AlgorithmProperties::class => ['/definitions/cryptoProperties/properties/algorithmProperties'],
        Entity\Attachment::class => ['/definitions/attachment'],
        Entity\Bom::class => [''],
        Entity\Citation::class => ['/definitions/citation'],
        Entity\Commit::class => ['/definitions/commit'],
        Entity\Component::class => ['/definitions/component'],
        Entity\ComponentEvidence::class => ['/definitions/componentEvidence'],
        Entity\Compositions::class => ['/definitions/compositions'],
        Entity\Copyright::class => ['/definitions/copyright'],
        Entity\CryptoProperties::class => ['/definitions/cryptoProperties'],
        Entity\DataClassification::class => ['/definitions/service/properties/data'],
        Entity\Dependency::class => ['/definitions/dependency'],
        Entity\Diff::class => ['/definitions/diff'],
        Entity\ExternalReference::class => ['/definitions/externalReference'],
        Entity\Hash::class => ['/definitions/hash'],
        Entity\Issue::class => ['/definitions/issue'],
        Entity\License::class => ['/definitions/license'],
        Entity\LicenseChoice::class => ['/definitions/licenseChoice'],
        Entity\Licensing::class => ['/definitions/license/properties/licensing'],
        Entity\LicensingParty::class => [
            '/definitions/license/properties/licensing/properties/licensor',
            '/definitions/license/properties/licensing/properties/licensee',
            '/definitions/license/properties/licensing/properties/purchaser',
        ],
        Entity\Metadata::class => ['/definitions/metadata'],
        Entity\Note::class => ['/definitions/note'],
        Entity\OrganizationalContact::class => ['/definitions/organizationalContact'],
        Entity\OrganizationalEntity::class => ['/definitions/organizationalEntity'],
        Entity\Patch::class => ['/definitions/patch'],
        Entity\PatentAssertion::class => ['/definitions/patentAssertions'],
        Entity\PostalAddress::class => ['/definitions/postalAddress'],
        Entity\Pedigree::class => ['/definitions/component/properties/pedigree'],
        Entity\Property::class => ['/definitions/property'],
        Entity\ReleaseNotes::class => ['/definitions/releaseNotes'],
        Entity\Service::class => ['/definitions/service'],
        Entity\SwidTag::class => ['/definitions/swid'],
        Entity\Tool::class => ['/definitions/tool'],
        // Branch 0 is the 1.5+ object form. The legacy array form is mapped
        // onto Tools::$legacyTools by CycloneDxParser::normalizeLegacyTools().
        Entity\Tools::class => ['/definitions/metadata/properties/tools/oneOf/0'],
        Vulnerability\Vulnerability::class => ['/definitions/vulnerability'],
        Vulnerability\VulnerabilityAdvisory::class => ['/definitions/advisory'],
        Vulnerability\VulnerabilityAffectedVersions::class => [
            '/definitions/vulnerability/properties/affects/items/properties/versions',
        ],
        Vulnerability\VulnerabilityAffects::class => ['/definitions/vulnerability/properties/affects'],
        Vulnerability\VulnerabilityAnalysis::class => ['/definitions/vulnerability/properties/analysis'],
        Vulnerability\VulnerabilityCredit::class => ['/definitions/vulnerability/properties/credits'],
        Vulnerability\ProofOfConcept::class => ['/definitions/vulnerability/properties/proofOfConcept'],
        Vulnerability\VulnerabilityRating::class => ['/definitions/rating'],
        Vulnerability\VulnerabilityReference::class => ['/definitions/vulnerability/properties/references'],
        Vulnerability\VulnerabilitySource::class => ['/definitions/vulnerabilitySource'],
    ];

    /**
     * Entity classes deliberately not compared against the CycloneDX schema.
     *
     * @var array<class-string, string>
     */
    private const array EXCLUDED_ENTITIES = [
        Entity\Signature::class => 'JSF signature, defined by an external schema and mapped as an opaque value',
    ];

    /**
     * Schema properties that are knowingly not modelled, keyed by entity class,
     * with the issue that tracks them. Except for `$schema`, each entry is data
     * the parser currently discards without notice.
     *
     * @var array<class-string, array<string, string>>
     */
    private const array KNOWN_UNMODELLED = [
        Entity\Bom::class => [
            '$schema' => 'JSON Schema reference, not SBOM content',
            'annotations' => 'untracked',
            'formulation' => 'untracked',
            'declarations' => 'untracked',
            'definitions' => 'untracked',
        ],
        Entity\Citation::class => [
            'pointers' => 'untracked',
            'expressions' => 'untracked',
            'timestamp' => 'untracked',
            'note' => 'untracked',
            'signature' => 'untracked',
        ],
        Entity\Component::class => [
            'modelCard' => '#59',
            'data' => '#59',
            'versionRange' => 'untracked',
            'isExternal' => 'untracked',
        ],
        Entity\ComponentEvidence::class => [
            'identity' => '#59',
            'occurrences' => '#59',
            'callstack' => '#59',
        ],
        Entity\CryptoProperties::class => [
            'certificateProperties' => 'untracked',
            'relatedCryptoMaterialProperties' => 'untracked',
            'protocolProperties' => 'untracked',
            'oid' => 'untracked',
        ],
        Entity\DataClassification::class => [
            'name' => 'untracked, serviceData since 1.5',
            'description' => 'untracked, serviceData since 1.5',
            'governance' => 'untracked, serviceData since 1.5',
            'source' => 'untracked, serviceData since 1.5',
            'destination' => 'untracked, serviceData since 1.5',
        ],
        Entity\ExternalReference::class => [
            'properties' => 'untracked',
        ],
        Entity\LicenseChoice::class => [
            'expressionDetails' => 'untracked',
            'licensing' => 'untracked',
            'properties' => 'untracked',
        ],
        Entity\Metadata::class => [
            'distributionConstraints' => 'untracked',
        ],
    ];

    /**
     * Constructor parameters that intentionally have no schema counterpart.
     *
     * @var array<class-string, array<string, string>>
     */
    private const array SYNTHETIC_PARAMETERS = [
        Entity\Tools::class => [
            'legacyTools' => 'filled by CycloneDxParser::normalizeLegacyTools() from the pre-1.5 array form',
        ],
    ];

    /**
     * Constructor parameters that match no schema property by mistake, so they
     * never receive data. Renaming them is a breaking change.
     *
     * @var array<class-string, array<string, string>>
     */
    private const array KNOWN_UNBOUND_PARAMETERS = [
        Entity\Citation::class => [
            'text' => 'untracked, the 1.7 schema names this property `note`',
        ],
    ];

    private const string SCHEMA_DIRECTORY = __DIR__ . '/../Fixtures/schemas';

    /**
     * @var array<string, array<string, mixed>>
     */
    private static array $schemaCache = [];

    /**
     * @return iterable<string, array{string, class-string}>
     */
    public static function entityPerSpecVersionProvider(): iterable
    {
        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $specVersion) {
            foreach (array_keys(self::SCHEMA_POINTERS) as $entityClass) {
                if (self::collectSchemaPropertiesForVersion($entityClass, $specVersion) === null) {
                    continue;
                }

                yield sprintf('%s in %s', self::shortName($entityClass), $specVersion) => [$specVersion, $entityClass];
            }
        }
    }

    /**
     * @return iterable<string, array{class-string}>
     */
    public static function entityProvider(): iterable
    {
        foreach (array_keys(self::SCHEMA_POINTERS) as $entityClass) {
            yield self::shortName($entityClass) => [$entityClass];
        }
    }

    /**
     * @param class-string $entityClass
     */
    #[Test]
    #[DataProvider('entityPerSpecVersionProvider')]
    public function everySchemaPropertyIsModelledOrKnowinglyUnmodelled(string $specVersion, string $entityClass): void
    {
        $schemaProperties = self::collectSchemaPropertiesForVersion($entityClass, $specVersion) ?? [];
        $parameters = self::constructorParameterNames($entityClass);
        $knownUnmodelled = array_keys(self::KNOWN_UNMODELLED[$entityClass] ?? []);

        $unmodelled = array_values(array_diff($schemaProperties, $parameters, $knownUnmodelled));

        self::assertSame(
            [],
            $unmodelled,
            sprintf(
                "%s does not model these CycloneDX %s properties, so the parser discards them silently.\n"
                . "Model them, or add them to KNOWN_UNMODELLED with a tracking issue.",
                $entityClass,
                $specVersion,
            ),
        );
    }

    /**
     * @param class-string $entityClass
     */
    #[Test]
    #[DataProvider('entityProvider')]
    public function everyConstructorParameterMatchesASchemaProperty(string $entityClass): void
    {
        $schemaProperties = self::collectSchemaPropertiesAcrossVersions($entityClass);
        $synthetic = array_keys(self::SYNTHETIC_PARAMETERS[$entityClass] ?? []);
        $knownUnbound = array_keys(self::KNOWN_UNBOUND_PARAMETERS[$entityClass] ?? []);

        $unmatched = array_values(array_diff(
            self::constructorParameterNames($entityClass),
            $schemaProperties,
            $synthetic,
            $knownUnbound,
        ));

        self::assertSame(
            [],
            $unmatched,
            sprintf(
                "These %s parameters match no property in any supported schema version, so they never receive data.\n"
                . 'Check the spelling against the schema key.',
                $entityClass,
            ),
        );
    }

    /**
     * @param class-string $entityClass
     */
    #[Test]
    #[DataProvider('entityProvider')]
    public function knownUnmodelledEntriesAreStillUnmodelledSchemaProperties(string $entityClass): void
    {
        $schemaProperties = self::collectSchemaPropertiesAcrossVersions($entityClass);
        $parameters = self::constructorParameterNames($entityClass);

        foreach (array_keys(self::KNOWN_UNMODELLED[$entityClass] ?? []) as $property) {
            self::assertContains(
                $property,
                $schemaProperties,
                sprintf('KNOWN_UNMODELLED lists %s::%s, but no supported schema defines it.', $entityClass, $property),
            );
            self::assertNotContains(
                $property,
                $parameters,
                sprintf('%s now models "%s". Remove it from KNOWN_UNMODELLED.', $entityClass, $property),
            );
        }
    }

    /**
     * @param class-string $entityClass
     */
    #[Test]
    #[DataProvider('entityProvider')]
    public function knownUnboundParametersStillExistAndStillMatchNoSchemaProperty(string $entityClass): void
    {
        $schemaProperties = self::collectSchemaPropertiesAcrossVersions($entityClass);
        $parameters = self::constructorParameterNames($entityClass);

        foreach (array_keys(self::KNOWN_UNBOUND_PARAMETERS[$entityClass] ?? []) as $parameter) {
            self::assertContains(
                $parameter,
                $parameters,
                sprintf('KNOWN_UNBOUND_PARAMETERS lists %s::$%s, which no longer exists.', $entityClass, $parameter),
            );
            self::assertNotContains(
                $parameter,
                $schemaProperties,
                sprintf('%s::$%s now matches a schema property. Remove it from KNOWN_UNBOUND_PARAMETERS.', $entityClass, $parameter),
            );
        }
    }

    #[Test]
    public function allowlistsOnlyNameCheckedEntities(): void
    {
        $allowlisted = [
            ...array_keys(self::KNOWN_UNMODELLED),
            ...array_keys(self::SYNTHETIC_PARAMETERS),
            ...array_keys(self::KNOWN_UNBOUND_PARAMETERS),
        ];

        self::assertSame([], array_values(array_diff($allowlisted, array_keys(self::SCHEMA_POINTERS))));
    }

    #[Test]
    public function everyEntityClassIsCheckedOrExplicitlyExcluded(): void
    {
        $unchecked = [];

        foreach (self::discoverEntityClasses() as $entityClass) {
            if (!array_key_exists($entityClass, self::SCHEMA_POINTERS) && !array_key_exists($entityClass, self::EXCLUDED_ENTITIES)) {
                $unchecked[] = $entityClass;
            }
        }

        self::assertSame(
            [],
            $unchecked,
            'Add these entities to SCHEMA_POINTERS so their schema binding is checked.',
        );
    }

    /**
     * @param class-string $entityClass
     */
    #[Test]
    #[DataProvider('entityProvider')]
    public function everyEntityIsDescribedBySomeSupportedSchemaVersion(string $entityClass): void
    {
        self::assertNotSame(
            [],
            self::collectSchemaPropertiesAcrossVersions($entityClass),
            sprintf('No schema pointer for %s resolves to an object with properties.', $entityClass),
        );
    }

    /**
     * @param class-string $entityClass
     * @return list<string>|null null when no pointer exists in this spec version
     */
    private static function collectSchemaPropertiesForVersion(string $entityClass, string $specVersion): ?array
    {
        $schema = self::loadSchema($specVersion);
        $properties = [];
        $found = false;

        foreach (self::SCHEMA_POINTERS[$entityClass] as $pointer) {
            $node = self::resolvePointer($schema, $pointer);
            if ($node === null) {
                continue;
            }

            $found = true;
            $properties = [...$properties, ...self::collectPropertyNames($schema, $node)];
        }

        if (!$found) {
            return null;
        }

        return array_values(array_unique(array_map(self::convertSchemaKey(...), $properties)));
    }

    /**
     * @param class-string $entityClass
     * @return list<string>
     */
    private static function collectSchemaPropertiesAcrossVersions(string $entityClass): array
    {
        $properties = [];

        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $specVersion) {
            $properties = [...$properties, ...(self::collectSchemaPropertiesForVersion($entityClass, $specVersion) ?? [])];
        }

        return array_values(array_unique($properties));
    }

    /**
     * Applies the parser's own key aliases rather than a copy, so a key the
     * parser forgets to convert shows up here as an unmodelled property.
     */
    private static function convertSchemaKey(string $key): string
    {
        /** @var array<string, string> $aliases */
        $aliases = (new \ReflectionClassConstant(CycloneDxParser::class, 'SCHEMA_KEY_ALIASES'))->getValue();

        return $aliases[$key] ?? $key;
    }

    /**
     * @param class-string $entityClass
     * @return list<string>
     */
    private static function constructorParameterNames(string $entityClass): array
    {
        $constructor = (new \ReflectionClass($entityClass))->getConstructor();
        self::assertNotNull($constructor, sprintf('%s has no constructor', $entityClass));

        return array_map(
            static fn (\ReflectionParameter $parameter): string => $parameter->getName(),
            $constructor->getParameters(),
        );
    }

    /**
     * @param array<string, mixed> $schema
     * @return array<mixed>|null
     */
    private static function resolvePointer(array $schema, string $pointer): ?array
    {
        $node = $schema;

        foreach (array_slice(explode('/', $pointer), 1) as $segment) {
            $node = self::dereference($schema, $node);
            if ($node === null || !is_array($node[$segment] ?? null)) {
                return null;
            }

            $node = $node[$segment];
        }

        return self::dereference($schema, $node);
    }

    /**
     * External references (the SPDX and JSF schemas) resolve to null.
     *
     * @param array<string, mixed> $schema
     * @param array<mixed> $node
     * @return array<mixed>|null
     */
    private static function dereference(array $schema, array $node): ?array
    {
        while (is_string($node['$ref'] ?? null)) {
            $reference = $node['$ref'];
            if (!str_starts_with($reference, '#/')) {
                return null;
            }

            $target = self::resolvePointer($schema, substr($reference, 1));
            if ($target === null) {
                return null;
            }

            $node = $target;
        }

        return $node;
    }

    /**
     * @param array<string, mixed> $schema
     * @param array<mixed> $node
     * @return list<string>
     */
    private static function collectPropertyNames(array $schema, array $node): array
    {
        $resolved = self::dereference($schema, $node);
        if ($resolved === null) {
            return [];
        }

        $names = is_array($resolved['properties'] ?? null) ? array_map(strval(...), array_keys($resolved['properties'])) : [];

        $children = [];
        foreach (['oneOf', 'anyOf', 'allOf'] as $combinator) {
            if (is_array($resolved[$combinator] ?? null)) {
                $children = [...$children, ...array_values($resolved[$combinator])];
            }
        }

        $items = $resolved['items'] ?? null;
        if (is_array($items)) {
            $children = [...$children, ...(array_is_list($items) ? $items : [$items])];
        }

        foreach ($children as $child) {
            if (is_array($child)) {
                $names = [...$names, ...self::collectPropertyNames($schema, $child)];
            }
        }

        return $names;
    }

    /**
     * @return array<string, mixed>
     */
    private static function loadSchema(string $specVersion): array
    {
        if (!array_key_exists($specVersion, self::$schemaCache)) {
            $path = sprintf('%s/bom-%s.schema.json', self::SCHEMA_DIRECTORY, $specVersion);
            $schema = json_decode((string)file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);
            self::assertIsArray($schema, sprintf('Schema %s did not decode to an object', $path));

            /** @var array<string, mixed> $schema */
            self::$schemaCache[$specVersion] = $schema;
        }

        return self::$schemaCache[$specVersion];
    }

    /**
     * @return list<class-string>
     */
    private static function discoverEntityClasses(): array
    {
        $entityDirectory = dirname(__DIR__, 2) . '/src/Entity';
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($entityDirectory, \FilesystemIterator::SKIP_DOTS));

        $classes = [];
        foreach ($iterator as $file) {
            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $relative = substr($file->getPathname(), strlen($entityDirectory) + 1, -4);
            $className = 'mteu\\SbomParser\\Entity\\' . str_replace(DIRECTORY_SEPARATOR, '\\', $relative);

            if (!class_exists($className) || (new \ReflectionClass($className))->isEnum()) {
                continue;
            }

            $classes[] = $className;
        }

        sort($classes);

        return $classes;
    }

    private static function shortName(string $className): string
    {
        return substr($className, (int)strrpos($className, '\\') + 1);
    }
}
