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

use JsonSchema\Validator as JsonSchemaValidator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * SchemaComplianceTest.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final class SchemaComplianceTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function schemaFixtureProvider(): iterable
    {
        yield '1.4 fixture validates against 1.4 schema' => ['bom-1.4.schema.json', 'bom-1.4.json'];
        yield '1.5 fixture validates against 1.5 schema' => ['bom-1.5.schema.json', 'bom-1.5.json'];
        yield '1.6 fixture validates against 1.6 schema' => ['bom-1.6.schema.json', 'bom-1.6.json'];
        yield '1.7 fixture validates against 1.7 schema' => ['bom-1.7.schema.json', 'bom-1.7.json'];
    }

    #[Test]
    #[DataProvider('schemaFixtureProvider')]
    public function fixtureIsValidAgainstOfficialSchema(string $schemaFile, string $fixtureFile): void
    {
        $schemaPath  = dirname(__DIR__, 1) . '/Fixtures/schemas/' . $schemaFile;
        $fixturePath = dirname(__DIR__, 1) . '/Fixtures/sbom/' . $fixtureFile;

        self::assertFileExists($schemaPath, "Schema file missing: $schemaFile");
        self::assertFileExists($fixturePath, "Fixture file missing: $fixtureFile");

        $data = json_decode(file_get_contents($fixturePath));
        $schema = (object) ['$ref' => 'file://' . realpath($schemaPath)];

        $validator = new JsonSchemaValidator();
        $validator->validate($data, $schema);

        self::assertTrue(
            $validator->isValid(),
            sprintf(
                "Fixture '%s' does not conform to schema '%s':\n%s",
                $fixtureFile,
                $schemaFile,
                implode("\n", array_map(
                    fn (array $e) => sprintf('  [%s] %s', $e['property'], $e['message']),
                    $validator->getErrors(),
                )),
            ),
        );
    }
}
