<?php

declare(strict_types=1);

/*
 * This file is part of the package "mteu/sbom-parser".
 *
 * Copyright (C) 2025 Martin Adler <mteu@mailbox.org>
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

namespace mteu\SbomParser\Tests\Unit\Parser;

use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Exception\SbomParseException;
use mteu\SbomParser\Parser\CycloneDxParser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * CycloneDxParserTest.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(CycloneDxParser::class)]
#[CoversClass(SbomParseException::class)]
final class CycloneDxParserTest extends TestCase
{
    private CycloneDxParser $subject;
    private string $tempOutputDir;

    protected function setUp(): void
    {
        parent::setUp();
        $this->subject = new CycloneDxParser();

        $this->tempOutputDir = dirname(__DIR__, 2) . '/Unit/tmp/unit_' . uniqid();
        mkdir($this->tempOutputDir, 0755, true);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempOutputDir)) {
            $this->removeDirectory($this->tempOutputDir);
        }

        parent::tearDown();
    }

    private function removeDirectory(string $dir): bool
    {
        if (!is_dir($dir)) {
            return false;
        }

        $files = array_diff(scandir($dir), ['.', '..']);

        foreach ($files as $file) {
            $path = $dir . '/' . $file;
            is_dir($path) ? $this->removeDirectory($path) : unlink($path);
        }

        return rmdir($dir);
    }

    /**
     * @param-immediately-invoked-callable $operation
     */
    private function runParserTest(callable $operation, bool $expectsException, string $expectedMessage): void
    {
        if ($expectsException) {
            $this->expectException(SbomParseException::class);
            $this->expectExceptionMessage($expectedMessage);
        }

        $result = $operation();

        if (!$expectsException) {
            self::assertInstanceOf(Bom::class, $result);
        }
    }


    #[Test]
    public function validatingSbomFileSucceedsForAProperFile(): void
    {
        self::assertTrue(
            $this->subject->isValidSbomFile(dirname(__DIR__, ) . '/Fixtures/cdx.sbom.json')
        );
    }


    /**
     * @param array<string, mixed> $data
     */
    #[Test]
    #[DataProvider('validateDataStructureProvider')]
    public function validateDataStructure(array $data, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromArray($data), $expectsException, $expectedMessage);
    }

    #[Test]
    #[DataProvider('validateSbomPathProvider')]
    public function validateSbomPath(string $filePath, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromFile($filePath), $expectsException, $expectedMessage);
    }

    /** @return \Generator<string, array{array<string, mixed>, bool, string}> */
    public static function validateDataStructureProvider(): \Generator
    {
        yield 'valid CycloneDX 1.4' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.4'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.4 with patch level' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.4.2'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.5' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.5'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.5 with patch level' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.5.0.0'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.6' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.6'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.6 with version qualifier' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.6-rc1'],
            false,
            '',
        ];

        yield 'missing bomFormat' => [
            ['specVersion' => '1.5'],
            true,
            'Missing required field: bomFormat',
        ];

        yield 'missing specVersion' => [
            ['bomFormat' => 'CycloneDX'],
            true,
            'Missing required field: specVersion',
        ];

        yield 'invalid bomFormat type' => [
            ['bomFormat' => 123, 'specVersion' => '1.5'],
            true,
            'Field bomFormat must be a string',
        ];

        yield 'invalid specVersion type' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => 123],
            true,
            'Field specVersion must be a string',
        ];

        yield 'unsupported bomFormat' => [
            ['bomFormat' => 'SPDX', 'specVersion' => '1.5'],
            true,
            'Unsupported SBOM format: SPDX',
        ];

        yield 'unsupported specVersion' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.3'],
            true,
            'Unsupported SBOM version: 1.3',
        ];
    }

    /** @return \Generator<string, array{string, bool, string}> */
    public static function validateSbomPathProvider(): \Generator
    {
        yield 'valid absolute path with json extension' => [
            dirname(__DIR__) . '/Fixtures/cdx.sbom.json',
            false,
            '',
        ];

        yield 'relative path' => [
            'relative/path/file.json',
            true,
            'SBOM file path must be absolute',
        ];

        yield 'path with directory traversal' => [
            '/tmp/../etc/sbom.json',
            true,
            'Directory traversal not allowed in SBOM path',
        ];

        yield 'path without extension' => [
            '/tmp/noextension',
            true,
            'SBOM file must have .json extension',
        ];

        yield 'path with wrong extension' => [
            '/tmp/wrong.xml',
            true,
            'SBOM file must have .json extension',
        ];

        yield 'file not found' => [
            dirname(__DIR__) . '/Fixtures/nonexistent.json',
            true,
            'File not found',
        ];
    }

    #[Test]
    public function parseFromFileThrowsExceptionForUnreadableFile(): void
    {
        $filePath = tempnam($this->tempOutputDir, 'parse_json') . '.json';
        file_put_contents($filePath, '{}');
        chmod($filePath, 0222); // write-only to simulate unreadable

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage("File not readable: $filePath");
        $this->subject->parseFromFile($filePath);
    }

    #[Test]
    #[DataProvider('parseFromJsonProvider')]
    public function parseFromJson(string $json, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromJson($json), $expectsException, $expectedMessage);
    }

    /**
     * @param array<string, mixed> $data
     */
    #[Test]
    #[DataProvider('parseFromArrayProvider')]
    public function parseFromArray(array $data, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromArray($data), $expectsException, $expectedMessage);
    }

    /** @return \Generator<string, array{string, bool, string}> */
    public static function parseFromJsonProvider(): \Generator
    {
        yield 'valid JSON object parses successfully' => [
            '{"bomFormat":"CycloneDX","specVersion":"1.5"}',
            false,
            '',
        ];

        yield 'malformed JSON with missing quote' => [
            '{"bomFormat":"CycloneDX,"specVersion":"1.5"}',
            true,
            'Invalid JSON:',
        ];

        yield 'malformed JSON with trailing comma' => [
            '{"bomFormat":"CycloneDX","specVersion":"1.5",}',
            true,
            'Invalid JSON:',
        ];

        yield 'malformed JSON with missing brace' => [
            '{"bomFormat":"CycloneDX","specVersion":"1.5"',
            true,
            'Invalid JSON:',
        ];

        yield 'valid JSON but indexed array instead of object' => [
            '["bomFormat","CycloneDX"]',
            true,
            'Missing required field: bomFormat',
        ];

        yield 'valid JSON but string instead of object' => [
            '"not an object"',
            true,
            'Decoded JSON is not an array',
        ];

        yield 'valid JSON but number instead of object' => [
            '42',
            true,
            'Decoded JSON is not an array',
        ];

        yield 'valid JSON but null' => [
            'null',
            true,
            'Decoded JSON is not an array',
        ];
    }

    /** @return \Generator<string, array{array<string, mixed>, bool, string}> */
    public static function parseFromArrayProvider(): \Generator
    {
        yield 'valid minimal structure maps successfully' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.5'],
            false,
            '',
        ];

        yield 'valid structure with complex metadata' => [
            [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.5',
                'serialNumber' => 'urn:uuid:12345',
                'version' => 1,
                'metadata' => [
                    'timestamp' => '2025-01-01T12:00:00Z',
                    'tools' => [
                        ['name' => 'test-tool', 'version' => '1.0']
                    ]
                ]
            ],
            false,
            '',
        ];

        yield 'invalid version type causes mapping error' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.5', 'version' => 'not-a-number'],
            true,
            'Valinor mapping failed',
        ];

        yield 'invalid serialNumber type causes mapping error' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.5', 'serialNumber' => 123],
            true,
            'Valinor mapping failed',
        ];

        yield 'invalid metadata structure causes mapping error' => [
            [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.5',
                'metadata' => 'invalid-metadata-string'
            ],
            true,
            'Valinor mapping failed',
        ];

        yield 'invalid components array causes mapping error' => [
            [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.5',
                'components' => 'not-an-array'
            ],
            true,
            'Valinor mapping failed',
        ];
    }
}
