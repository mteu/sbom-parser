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

use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisJustification;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisResponse;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisState;
use mteu\SbomParser\Parser\CycloneDxParser;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Pins the analysis enums against the vocabulary of every supported spec
 * version. One enum serves all of them, so a value added or removed upstream
 * has to fail here before it fails a consumer's VEX upload.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final class AnalysisVocabularyTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string, list<string>}> spec version, slash-separated path into the schema, enum values
     */
    public static function vocabularyProvider(): iterable
    {
        // The response vocabulary has no named definition; it is inlined.
        $enums = [
            'definitions/impactAnalysisState' => ImpactAnalysisState::cases(),
            'definitions/impactAnalysisJustification' => ImpactAnalysisJustification::cases(),
            'definitions/vulnerability/properties/analysis/properties/response/items' => ImpactAnalysisResponse::cases(),
        ];

        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $version) {
            foreach ($enums as $pointer => $cases) {
                yield "$pointer in $version" => [
                    $version,
                    $pointer,
                    array_map(static fn (\BackedEnum $case): string => (string)$case->value, $cases),
                ];
            }
        }
    }

    /**
     * @param list<string> $enumValues
     */
    #[Test]
    #[DataProvider('vocabularyProvider')]
    public function enumMatchesTheSchemaVocabulary(string $version, string $pointer, array $enumValues): void
    {
        $path = dirname(__DIR__) . "/Fixtures/schemas/bom-$version.schema.json";
        $node = json_decode((string)file_get_contents($path), true, flags: JSON_THROW_ON_ERROR);

        foreach (explode('/', $pointer) as $key) {
            self::assertIsArray($node);
            $node = $node[$key] ?? null;
        }

        self::assertIsArray($node);
        $schemaValues = $node['enum'] ?? null;
        self::assertIsArray($schemaValues, "Schema $version has no enum at $pointer.");

        sort($schemaValues);
        sort($enumValues);
        self::assertSame($schemaValues, $enumValues);
    }
}
