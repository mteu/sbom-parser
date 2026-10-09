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

use mteu\SbomParser\Entity\Attachment;
use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Entity\Component;
use mteu\SbomParser\Entity\ComponentType;
use mteu\SbomParser\Entity\Dependency;
use mteu\SbomParser\Entity\Hash;
use mteu\SbomParser\Entity\HashAlgorithm;
use mteu\SbomParser\Entity\LicenseAcknowledgement;
use mteu\SbomParser\Entity\LicenseType;
use mteu\SbomParser\Entity\OrganizationalContact;
use mteu\SbomParser\Entity\Property;
use mteu\SbomParser\Entity\Tool;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisJustification;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisResponse;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisState;
use mteu\SbomParser\Entity\Vulnerability\Vulnerability;
use mteu\SbomParser\Entity\Vulnerability\VulnerabilityAffects;
use mteu\SbomParser\Exception\ParseErrorDetail;
use mteu\SbomParser\Exception\SbomParseException;
use mteu\SbomParser\Parser\Configuration\CycloneDxParserOptions;
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
#[CoversClass(CycloneDxParserOptions::class)]
#[CoversClass(SbomParseException::class)]
#[CoversClass(ParseErrorDetail::class)]
final class CycloneDxParserTest extends TestCase
{
    private static function fixtureDir(): string
    {
        return (string) realpath(__DIR__ . '/../../Fixtures/sbom');
    }

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

    /**
     * @param array<string, mixed> $data
     */
    #[Test]
    #[DataProvider('validateDataStructureProvider')]
    public function validateDataStructure(array $data, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromArray($data), $expectsException, $expectedMessage);
    }

    /** @return \Generator<string, array{array<string, mixed>, bool, string}> */
    public static function validateDataStructureProvider(): \Generator
    {
        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $version) {
            yield "valid CycloneDX {$version}" => [
                ['bomFormat' => 'CycloneDX', 'specVersion' => $version],
                false,
                '',
            ];
        }

        yield 'valid CycloneDX 1.4 with patch level' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.4.2'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.5 with patch level' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.5.0.0'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.6 with version qualifier' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.6-rc1'],
            false,
            '',
        ];

        yield 'valid CycloneDX 1.7 with patch level' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.7.0'],
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

    #[Test]
    #[DataProvider('validateSbomPathProvider')]
    public function validateSbomPath(string $filePath, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromFile($filePath), $expectsException, $expectedMessage);
    }

    /** @return \Generator<string, array{string, bool, string}> */
    public static function validateSbomPathProvider(): \Generator
    {
        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $version) {
            yield "valid absolute path for bom-{$version}.json" => [
                self::fixtureDir() . "/bom-{$version}.json",
                false,
                '',
            ];
        }

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

        yield 'path with URL-encoded directory traversal (lowercase)' => [
            '/tmp/%2e%2e/etc/sbom.json',
            true,
            'Directory traversal not allowed in SBOM path',
        ];

        yield 'path with URL-encoded directory traversal (uppercase)' => [
            '/tmp/%2E%2E/etc/sbom.json',
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
            dirname(__DIR__, 2) . '/Fixtures/sbom/nonexistent.json',
            true,
            'File not found',
        ];

        yield 'non-existent directory' => [
            '/nonexistent_dir_abc123/file.json',
            true,
            'SBOM directory does not exist or is not accessible',
        ];
    }

    #[Test]
    public function parseFromFileAcceptsDoubleDotInsideFilename(): void
    {
        $filePath = $this->tempOutputDir . '/foo..bar.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $bom = $this->subject->parseFromFile($filePath);

        self::assertSame('CycloneDX', $bom->bomFormat);
        self::assertSame('1.5', $bom->specVersion);
    }

    #[Test]
    public function parseFromFileAcceptsDoubleDotInsideDirectoryName(): void
    {
        $directory = $this->tempOutputDir . '/data..backup';
        mkdir($directory);
        $filePath = $directory . '/sbom.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $bom = $this->subject->parseFromFile($filePath);

        self::assertSame('CycloneDX', $bom->bomFormat);
    }

    #[Test]
    public function parseFromFileRejectsSymlinkPointingOutsideDirectory(): void
    {
        if (!function_exists('symlink')) {
            self::markTestSkipped('symlink() not available on this platform');
        }

        $target = tempnam(sys_get_temp_dir(), 'sbom_symlink_target_');
        self::assertNotFalse($target);
        file_put_contents($target, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $symlinkPath = $this->tempOutputDir . '/sbom.json';

        set_error_handler(static fn () => true);
        try {
            $created = symlink($target, $symlinkPath);
        } finally {
            restore_error_handler();
        }

        if (!$created) {
            unlink($target);
            self::markTestSkipped('Could not create symlink (insufficient permissions)');
        }

        try {
            $this->expectException(SbomParseException::class);
            $this->expectExceptionMessage('Directory traversal not allowed in SBOM path');
            $this->subject->parseFromFile($symlinkPath);
        } finally {
            if (is_link($symlinkPath) || file_exists($symlinkPath)) {
                unlink($symlinkPath);
            }
            if (file_exists($target)) {
                unlink($target);
            }
        }
    }

    #[Test]
    #[DataProvider('isAbsolutePathProvider')]
    public function isAbsolutePathRecognisesPlatformConventions(string $path, bool $expected): void
    {
        $reflection = new \ReflectionMethod(CycloneDxParser::class, 'isAbsolutePath');
        self::assertSame($expected, $reflection->invoke($this->subject, $path));
    }

    /** @return \Generator<string, array{string, bool}> */
    public static function isAbsolutePathProvider(): \Generator
    {
        yield 'unix absolute' => ['/tmp/sbom.json', true];
        yield 'unix relative' => ['tmp/sbom.json', false];
        yield 'empty string' => ['', false];
        yield 'plain dot' => ['./sbom.json', false];

        yield 'windows drive with backslash' => ['C:\\Users\\foo\\sbom.json', true];
        yield 'windows drive with forward slash' => ['C:/Users/foo/sbom.json', true];
        yield 'windows drive lowercase letter' => ['d:\\sbom.json', true];
        yield 'windows drive without separator' => ['C:sbom.json', false];
        yield 'colon-only is not absolute' => [':sbom', false];

        yield 'unc path' => ['\\\\server\\share\\sbom.json', true];
    }

    #[Test]
    #[DataProvider('containsTraversalSegmentProvider')]
    public function containsTraversalSegmentDetectsOnlyRealTraversal(string $path, bool $expected): void
    {
        $reflection = new \ReflectionMethod(CycloneDxParser::class, 'containsTraversalSegment');
        self::assertSame($expected, $reflection->invoke($this->subject, $path));
    }

    /** @return \Generator<string, array{string, bool}> */
    public static function containsTraversalSegmentProvider(): \Generator
    {
        yield 'clean unix path' => ['/var/data/sbom.json', false];
        yield 'literal traversal segment' => ['/tmp/../etc/sbom.json', true];
        yield 'trailing traversal segment' => ['/var/data/..', true];
        yield 'url-encoded lowercase' => ['/tmp/%2e%2e/etc/sbom.json', true];
        yield 'url-encoded uppercase' => ['/tmp/%2E%2E/etc/sbom.json', true];
        yield 'url-encoded mixed case' => ['/tmp/%2e%2E/etc/sbom.json', true];
        yield 'double-dot inside filename is allowed' => ['/var/data/foo..bar.json', false];
        yield 'double-dot inside directory is allowed' => ['/var/data..backup/sbom.json', false];
        yield 'leading double-dot inside segment is allowed' => ['/var/..hidden/sbom.json', false];
        yield 'trailing double-dot inside segment is allowed' => ['/var/hidden../sbom.json', false];
        yield 'windows-style traversal segment' => ['C:\\Users\\..\\etc\\sbom.json', true];
    }

    #[Test]
    public function parseFromFileThrowsExceptionForUnreadableFile(): void
    {
        $filePath = tempnam($this->tempOutputDir, 'parse_json') . '.json';
        file_put_contents($filePath, '{}');
        chmod($filePath, 0222);

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage("File not readable: $filePath");
        $this->subject->parseFromFile($filePath);
    }

    #[Test]
    public function parseFromFileThrowsExceptionForFileTooLarge(): void
    {
        $maxFileSize = 256;
        $parser = new CycloneDxParser(new CycloneDxParserOptions(maxFileSize: $maxFileSize));

        $filePath = tempnam($this->tempOutputDir, 'large_file') . '.json';
        file_put_contents($filePath, str_repeat('a', $maxFileSize + 1));

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage('File too large');
        $parser->parseFromFile($filePath);
    }

    #[Test]
    public function parseFromFileAcceptsFileWithinCustomMaxFileSize(): void
    {
        $payload = '{"bomFormat":"CycloneDX","specVersion":"1.5"}';
        $parser = new CycloneDxParser(new CycloneDxParserOptions(maxFileSize: strlen($payload) + 1));

        $filePath = tempnam($this->tempOutputDir, 'within_cap') . '.json';
        file_put_contents($filePath, $payload);

        $bom = $parser->parseFromFile($filePath);

        self::assertSame('1.5', $bom->specVersion);
    }

    #[Test]
    public function isValidSbomFileReturnsFalseForFileExceedingMaxSize(): void
    {
        $parser = new CycloneDxParser(new CycloneDxParserOptions(maxFileSize: 64));

        $filePath = tempnam($this->tempOutputDir, 'over_cap') . '.json';
        file_put_contents($filePath, str_repeat('a', 256));

        self::assertFalse($parser->isValidSbomFile($filePath));
    }

    #[Test]
    public function parseFromFileAcceptsPathWithinAllowedBaseDirectory(): void
    {
        $base = (string) realpath($this->tempOutputDir);
        $parser = new CycloneDxParser(
            new CycloneDxParserOptions(allowedBaseDirectories: [$base]),
        );

        $filePath = $this->tempOutputDir . '/sbom.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $bom = $parser->parseFromFile($filePath);

        self::assertSame('1.5', $bom->specVersion);
    }

    #[Test]
    public function parseFromFileRejectsPathOutsideAllowedBaseDirectory(): void
    {
        $allowed = $this->tempOutputDir . '/allowed';
        $other = $this->tempOutputDir . '/other';
        mkdir($allowed, 0755, true);
        mkdir($other, 0755, true);

        $parser = new CycloneDxParser(
            new CycloneDxParserOptions(allowedBaseDirectories: [(string) realpath($allowed)]),
        );

        $filePath = $other . '/sbom.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage('SBOM file path is outside the allowed base directories');
        $parser->parseFromFile($filePath);
    }

    #[Test]
    public function parseFromFileAcceptsPathWithinAnyOfMultipleAllowedDirectories(): void
    {
        $first = $this->tempOutputDir . '/first';
        $second = $this->tempOutputDir . '/second';
        mkdir($first, 0755, true);
        mkdir($second, 0755, true);

        $parser = new CycloneDxParser(
            new CycloneDxParserOptions(
                allowedBaseDirectories: [
                    (string) realpath($first),
                    (string) realpath($second),
                ],
            ),
        );

        $filePath = $second . '/sbom.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $bom = $parser->parseFromFile($filePath);

        self::assertSame('1.5', $bom->specVersion);
    }

    #[Test]
    public function parseFromFileRejectsSiblingDirectoryWithSharedPrefix(): void
    {
        $allowed = $this->tempOutputDir . '/data';
        $sibling = $this->tempOutputDir . '/data-other';
        mkdir($allowed, 0755, true);
        mkdir($sibling, 0755, true);

        $parser = new CycloneDxParser(
            new CycloneDxParserOptions(allowedBaseDirectories: [(string) realpath($allowed)]),
        );

        $filePath = $sibling . '/sbom.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage('SBOM file path is outside the allowed base directories');
        $parser->parseFromFile($filePath);
    }

    #[Test]
    public function parseFromFileIgnoresAllowedBaseDirectoriesWhenEmpty(): void
    {
        $parser = new CycloneDxParser(
            new CycloneDxParserOptions(allowedBaseDirectories: []),
        );

        $filePath = $this->tempOutputDir . '/sbom.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $bom = $parser->parseFromFile($filePath);

        self::assertSame('1.5', $bom->specVersion);
    }

    #[Test]
    public function parseFromFileSkipsNonExistentAllowedBaseDirectory(): void
    {
        $allowed = $this->tempOutputDir . '/real';
        mkdir($allowed, 0755, true);

        $parser = new CycloneDxParser(
            new CycloneDxParserOptions(
                allowedBaseDirectories: [
                    $this->tempOutputDir . '/does-not-exist',
                    (string) realpath($allowed),
                ],
            ),
        );

        $filePath = $allowed . '/sbom.json';
        file_put_contents($filePath, '{"bomFormat":"CycloneDX","specVersion":"1.5"}');

        $bom = $parser->parseFromFile($filePath);

        self::assertSame('1.5', $bom->specVersion);
    }

    #[Test]
    public function parseFromArrayRejectsPayloadExceedingNodeBudget(): void
    {
        $parser = new CycloneDxParser(new CycloneDxParserOptions(maxNodes: 10));

        $components = [];
        for ($i = 0; $i < 100; $i++) {
            $components[] = ['type' => 'library', 'name' => "lib-{$i}"];
        }

        $data = [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => $components,
        ];

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage('Decoded SBOM exceeds maximum node count of 10');
        $parser->parseFromArray($data);
    }

    #[Test]
    public function parseFromArrayAcceptsPayloadWithinNodeBudget(): void
    {
        $parser = new CycloneDxParser(new CycloneDxParserOptions(maxNodes: 100));

        $bom = $parser->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [['type' => 'library', 'name' => 'lib']],
        ]);

        self::assertSame('CycloneDX', $bom->bomFormat);
    }

    #[Test]
    public function parseFromJsonRejectsWidePayloadExceedingNodeBudget(): void
    {
        $parser = new CycloneDxParser(new CycloneDxParserOptions(maxNodes: 50));

        $wide = [];
        for ($i = 0; $i < 200; $i++) {
            $wide["k{$i}"] = $i;
        }

        $json = (string) json_encode([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'metadata' => ['properties' => $wide],
        ]);

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage('Decoded SBOM exceeds maximum node count');
        $parser->parseFromJson($json);
    }

    #[Test]
    public function parseFromArrayRenamesBomRefToBomRef(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'symfony/console',
                    'bom-ref' => 'composer/symfony/console',
                ],
            ],
        ]);

        $components = $bom->components ?? [];
        self::assertCount(1, $components);
        self::assertSame('composer/symfony/console', $components[0]->bomRef);
    }

    #[Test]
    public function parseFromArrayMapsComponentMimeTypeKey(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'file',
                    'name' => 'README.md',
                    'mime-type' => 'text/markdown',
                ],
            ],
        ]);

        $components = $bom->components ?? [];
        self::assertCount(1, $components);
        self::assertSame('text/markdown', $components[0]->mimeType);
    }

    #[Test]
    public function parseFromArrayMapsServiceTrustBoundaryKey(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'services' => [
                [
                    'name' => 'billing-api',
                    'x-trust-boundary' => true,
                ],
            ],
        ]);

        $services = $bom->services ?? [];
        self::assertCount(1, $services);
        self::assertTrue($services[0]->xTrustBoundary);
    }

    #[Test]
    public function parseFromArrayHydratesLicenseChoices(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.7',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'licensed-component',
                    'licenses' => [
                        [
                            'license' => ['id' => 'MIT'],
                        ],
                        ['expression' => 'Apache-2.0 OR MIT'],
                    ],
                ],
            ],
        ]);

        $licenses = $bom->components[0]->licenses ?? [];

        self::assertCount(2, $licenses);
        self::assertNotNull($licenses[0]->license);
        self::assertSame('MIT', $licenses[0]->license->id);
        self::assertSame('Apache-2.0 OR MIT', $licenses[1]->expression);
    }

    #[Test]
    public function parseFromArrayHydratesLicenseTextAsAttachment(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'licensed-component',
                    'licenses' => [
                        [
                            'license' => [
                                'name' => 'Custom License',
                                'text' => [
                                    'contentType' => 'text/plain',
                                    'encoding' => 'base64',
                                    'content' => 'FooBar',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $license = ($bom->components[0]->licenses ?? [])[0]->license ?? null;

        self::assertNotNull($license);
        self::assertSame('Custom License', $license->name);
        self::assertInstanceOf(Attachment::class, $license->text);
        self::assertSame('text/plain', $license->text->contentType);
        self::assertSame('base64', $license->text->encoding);
        self::assertSame('FooBar', $license->text->content);
    }

    #[Test]
    public function parseFromArrayHydratesLicenseTextWithoutOptionalAttachmentFields(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'licensed-component',
                    'licenses' => [
                        [
                            'license' => [
                                'name' => 'Custom License',
                                'text' => ['content' => 'MIT'],
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $license = ($bom->components[0]->licenses ?? [])[0]->license ?? null;

        self::assertNotNull($license);
        self::assertInstanceOf(Attachment::class, $license->text);
        self::assertSame('MIT', $license->text->content);
        self::assertNull($license->text->contentType);
        self::assertNull($license->text->encoding);
    }

    #[Test]
    public function parseFromArrayHydratesLicenseAcknowledgement(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'licensed-component',
                    'licenses' => [
                        [
                            'license' => ['id' => 'MIT', 'acknowledgement' => 'declared'],
                        ],
                        [
                            'expression' => 'Apache-2.0 OR MIT',
                            'acknowledgement' => 'concluded',
                        ],
                    ],
                ],
            ],
        ]);

        $licenses = $bom->components[0]->licenses ?? [];

        self::assertCount(2, $licenses);
        self::assertSame(LicenseAcknowledgement::DECLARED, $licenses[0]->license?->acknowledgement);
        self::assertSame(LicenseAcknowledgement::CONCLUDED, $licenses[1]->acknowledgement);
    }

    #[Test]
    public function parseFromArrayLeavesLicenseAcknowledgementNullWhenAbsent(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'licensed-component',
                    'licenses' => [['license' => ['id' => 'MIT']]],
                ],
            ],
        ]);

        $licenses = $bom->components[0]->licenses ?? [];

        self::assertCount(1, $licenses);
        self::assertNull($licenses[0]->license?->acknowledgement);
        self::assertNull($licenses[0]->acknowledgement);
    }

    #[Test]
    public function parseFromArrayHydratesLicenseBomRefAndProperties(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'licensed-component',
                    'licenses' => [
                        [
                            'license' => [
                                'id' => 'MIT',
                                'bom-ref' => 'license-mit',
                                'properties' => [
                                    ['name' => 'internal:reviewed', 'value' => 'true'],
                                ],
                            ],
                            'bom-ref' => 'choice-mit',
                        ],
                    ],
                ],
            ],
        ]);

        $licenseChoice = ($bom->components[0]->licenses ?? [])[0];

        self::assertSame('choice-mit', $licenseChoice->bomRef);
        self::assertNotNull($licenseChoice->license);
        self::assertSame('license-mit', $licenseChoice->license->bomRef);
        self::assertNotNull($licenseChoice->license->properties);
        self::assertCount(1, $licenseChoice->license->properties);
        self::assertSame('internal:reviewed', $licenseChoice->license->properties[0]->name);
        self::assertSame('true', $licenseChoice->license->properties[0]->value);
    }

    #[Test]
    public function parseFromArrayHydratesLicenseLicensing(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'licensed-component',
                    'licenses' => [
                        [
                            'license' => [
                                'name' => 'Commercial License',
                                'licensing' => [
                                    'altIds' => ['acme-ent', 'acme-enterprise'],
                                    'licensor' => [
                                        'organization' => ['name' => 'Acme Inc.'],
                                    ],
                                    'licensee' => [
                                        'individual' => [
                                            'name' => 'Jane Doe',
                                            'email' => 'jane@example.com',
                                        ],
                                    ],
                                    'purchaser' => [
                                        'individual' => ['name' => 'John Doe'],
                                    ],
                                    'purchaseOrder' => 'PO-12345',
                                    'licenseTypes' => ['subscription', 'named-user'],
                                    'lastRenewal' => '2026-01-15T00:00:00Z',
                                    'expiration' => '2027-01-15T00:00:00Z',
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ]);

        $licensing = (($bom->components[0]->licenses ?? [])[0]->license ?? null)?->licensing;

        self::assertNotNull($licensing);
        self::assertSame(['acme-ent', 'acme-enterprise'], $licensing->altIds);
        self::assertSame('Acme Inc.', $licensing->licensor?->organization?->name);
        self::assertSame('jane@example.com', $licensing->licensee?->individual?->email);
        self::assertSame('John Doe', $licensing->purchaser?->individual?->name);
        self::assertSame('PO-12345', $licensing->purchaseOrder);
        self::assertSame([LicenseType::SUBSCRIPTION, LicenseType::NAMED_USER], $licensing->licenseTypes);
        self::assertSame('2026-01-15', $licensing->lastRenewal?->format('Y-m-d'));
        self::assertSame('2027-01-15', $licensing->expiration?->format('Y-m-d'));
    }

    /**
     * Acknowledgement was introduced in CycloneDX 1.6, so the 1.4 and 1.5
     * fixtures legitimately carry none.
     */
    #[Test]
    public function parseFromFileHydratesLicenseAcknowledgementFromFixtures(): void
    {
        foreach (['1.6', '1.7'] as $version) {
            $bom = $this->subject->parseFromFile(self::fixtureDir() . "/bom-{$version}.json");

            $acknowledgements = [];
            foreach ($bom->components ?? [] as $component) {
                foreach ($component->licenses ?? [] as $licenseChoice) {
                    $acknowledgement = $licenseChoice->license?->acknowledgement;
                    if ($acknowledgement !== null) {
                        $acknowledgements[] = $acknowledgement;
                    }
                }
            }

            self::assertContains(
                LicenseAcknowledgement::DECLARED,
                $acknowledgements,
                sprintf('bom-%s.json declares license acknowledgements that were not hydrated.', $version),
            );
        }
    }

    /** @return \Generator<string, array{string, string}> */
    public static function parseFromFileFixtureProvider(): \Generator
    {
        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $version) {
            yield "bom-{$version}.json parses successfully" => [
                self::fixtureDir() . "/bom-{$version}.json",
                $version,
            ];
        }
    }

    #[Test]
    #[DataProvider('parseFromFileFixtureProvider')]
    public function parseFromFileSucceedsForFixture(string $filePath, string $expectedVersion): void
    {
        $bom = $this->subject->parseFromFile($filePath);

        self::assertInstanceOf(Bom::class, $bom);
        self::assertSame('CycloneDX', $bom->bomFormat);
        self::assertSame($expectedVersion, $bom->specVersion);
    }

    #[Test]
    #[DataProvider('parseFromJsonFixtureProvider')]
    public function parseFromFileMapsMetadataComponentAsTheRootComponent(string $fixturePath): void
    {
        $bom = $this->subject->parseFromFile($fixturePath);

        $root = $bom->metadata?->component;
        self::assertInstanceOf(Component::class, $root);
        self::assertSame(ComponentType::APPLICATION, $root->type);
        self::assertSame('mteu/sbom-parser-dev-main', $root->bomRef);
        self::assertSame('pkg:composer/mteu/sbom-parser@dev-main', $root->purl);
        self::assertSame('dev-main', $root->version);

        $dependencyRefs = array_map(
            static fn (Dependency $dependency): string => $dependency->ref,
            $bom->dependencies ?? [],
        );
        self::assertContains($root->bomRef, $dependencyRefs);
    }

    /** @return \Generator<string, array{string}> */
    public static function parseFromJsonFixtureProvider(): \Generator
    {
        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $version) {
            yield "bom-{$version}.json" => [self::fixtureDir() . "/bom-{$version}.json"];
        }
    }

    #[Test]
    #[DataProvider('parseFromJsonFixtureProvider')]
    public function parseFromJsonSucceedsForFixture(string $fixturePath): void
    {
        $content = file_get_contents($fixturePath);
        self::assertNotFalse($content, "Could not read fixture: $fixturePath");

        $bom = $this->subject->parseFromJson($content);
        self::assertInstanceOf(Bom::class, $bom);
    }

    #[Test]
    #[DataProvider('parseFromJsonProvider')]
    public function parseFromJson(string $json, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromJson($json), $expectsException, $expectedMessage);
    }

    /** @return \Generator<string, array{string, bool, string}> */
    public static function parseFromJsonProvider(): \Generator
    {
        yield 'valid minimal JSON object parses successfully' => [
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

    /**
     * @param array<string, mixed> $data
     */
    #[Test]
    #[DataProvider('parseFromArrayProvider')]
    public function parseFromArray(array $data, bool $expectsException, string $expectedMessage = ''): void
    {
        $this->runParserTest(fn () => $this->subject->parseFromArray($data), $expectsException, $expectedMessage);
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
                        ['name' => 'test-tool', 'version' => '1.0'],
                    ],
                ],
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
                'metadata' => 'invalid-metadata-string',
            ],
            true,
            'Valinor mapping failed',
        ];

        yield 'invalid components array causes mapping error' => [
            [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.5',
                'components' => 'not-an-array',
            ],
            true,
            'Valinor mapping failed',
        ];

        yield 'valid 1.7 structure with citations maps successfully' => [
            [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.7',
                'citations' => [
                    [
                        'attributedTo' => ['comp-ref-1'],
                        'text' => 'Sourced from internal vulnerability database',
                    ],
                ],
            ],
            false,
            '',
        ];

        yield 'valid 1.7 structure with patentAssertions and cryptoProperties maps successfully' => [
            [
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.7',
                'components' => [
                    [
                        'type' => 'cryptographic-asset',
                        'name' => 'AES-128-GCM',
                        'bom-ref' => 'crypto-asset-1',
                        'patentAssertions' => [
                            [
                                'bom-ref' => 'patent-assertion-1',
                                'assertionType' => 'ownership',
                                'asserter' => 'org-1',
                                'patentRefs' => ['patent-1'],
                                'notes' => 'Held until 2030.',
                            ],
                        ],
                        'cryptoProperties' => [
                            'assetType' => 'algorithm',
                            'algorithmProperties' => [
                                'primitive' => 'ae',
                                'parameterSetIdentifier' => '128',
                                'mode' => 'gcm',
                                'cryptoFunctions' => ['encrypt', 'decrypt', 'tag'],
                                'classicalSecurityLevel' => 128,
                            ],
                        ],
                    ],
                ],
            ],
            false,
            '',
        ];
    }

    #[Test]
    public function parseFromArrayHydratesMetadataAuthors(): void
    {
        $data = [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'metadata' => [
                'authors' => [
                    [
                        'name' => 'John Doe',
                        'email' => 'foo@example.com',
                        'phone' => '+49-30-000000',
                    ],
                    [
                        'name' => 'Jane Doe',
                    ],
                ],
            ],
        ];

        $bom = $this->subject->parseFromArray($data);
        $authors = $bom->metadata->authors ?? [];

        self::assertCount(2, $authors);

        self::assertInstanceOf(OrganizationalContact::class, $authors[0]);
        self::assertSame('John Doe', $authors[0]->name);
        self::assertSame('foo@example.com', $authors[0]->email);
        self::assertSame('+49-30-000000', $authors[0]->phone);

        self::assertInstanceOf(OrganizationalContact::class, $authors[1]);
        self::assertSame('Jane Doe', $authors[1]->name);
        self::assertNull($authors[1]->email);
        self::assertNull($authors[1]->phone);
    }

    #[Test]
    public function parseFromArrayHydratesMetadataLicenses(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'metadata' => [
                'licenses' => [
                    [
                        'license' => ['id' => 'GPL-3.0-or-later', 'acknowledgement' => 'declared'],
                    ],
                ],
            ],
        ]);

        $licenses = $bom->metadata->licenses ?? [];

        self::assertCount(1, $licenses);

        $license = $licenses[0]->license;

        self::assertNotNull($license);
        self::assertSame('GPL-3.0-or-later', $license->id);
        self::assertSame(LicenseAcknowledgement::DECLARED, $license->acknowledgement);
    }

    #[Test]
    public function parseFromArrayHydratesMetadataLicenseExpression(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'metadata' => [
                'licenses' => [
                    ['expression' => 'Apache-2.0 OR MIT'],
                ],
            ],
        ]);

        $licenses = $bom->metadata->licenses ?? [];

        self::assertCount(1, $licenses);
        self::assertTrue($licenses[0]->hasExpression());
        self::assertSame('Apache-2.0 OR MIT', $licenses[0]->expression);
    }

    #[Test]
    public function parseFromArrayHydratesModernToolsObject(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'metadata' => [
                'tools' => [
                    'components' => [
                        ['type' => 'application', 'name' => 'cyclonedx-php-composer', 'version' => '6.0'],
                    ],
                    'services' => [
                        ['name' => 'sbom-service'],
                    ],
                ],
            ],
        ]);

        $tools = $bom->metadata?->tools;

        self::assertNotNull($tools);
        self::assertNull($tools->legacyTools);

        $components = $tools->components ?? [];
        $services = $tools->services ?? [];

        self::assertCount(1, $components);
        self::assertSame('cyclonedx-php-composer', $components[0]->name);
        self::assertSame(ComponentType::APPLICATION, $components[0]->type);
        self::assertCount(1, $services);
        self::assertSame('sbom-service', $services[0]->name);
    }

    #[Test]
    public function parseFromArrayHydratesLegacyToolsArray(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.4',
            'metadata' => [
                'tools' => [
                    ['vendor' => 'cyclonedx', 'name' => 'cyclonedx-php-composer', 'version' => '6.0'],
                    ['name' => 'composer', 'version' => '2.9.5'],
                ],
            ],
        ]);

        $tools = $bom->metadata?->tools;

        self::assertNotNull($tools);
        self::assertNull($tools->components);
        self::assertNull($tools->services);

        $legacyTools = $tools->legacyTools ?? [];

        self::assertCount(2, $legacyTools);
        self::assertInstanceOf(Tool::class, $legacyTools[0]);
        self::assertSame('cyclonedx', $legacyTools[0]->vendor);
        self::assertSame('cyclonedx-php-composer', $legacyTools[0]->name);
        self::assertSame('composer', $legacyTools[1]->name);
        self::assertNull($legacyTools[1]->vendor);
    }

    #[Test]
    public function parseFromArrayLeavesToolsNullWhenAbsent(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'metadata' => ['timestamp' => '2026-01-15T00:00:00Z'],
        ]);

        self::assertNull($bom->metadata?->tools);
    }

    #[Test]
    public function parseFromFileHydratesLegacyToolsFromFixtures(): void
    {
        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $version) {
            $bom = $this->subject->parseFromFile(self::fixtureDir() . "/bom-{$version}.json");

            $tools = $bom->metadata?->tools;

            self::assertNotNull($tools, sprintf('bom-%s.json declares metadata.tools.', $version));

            $legacyTools = $tools->legacyTools ?? [];

            self::assertNotEmpty(
                $legacyTools,
                sprintf('bom-%s.json declares tools that were not hydrated.', $version),
            );
            self::assertSame('composer', $legacyTools[0]->name);
        }
    }

    #[Test]
    public function parseFromArrayHydratesPatentAssertionAndAlgorithmProperties(): void
    {
        $data = [
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.7',
            'components' => [
                [
                    'type' => 'cryptographic-asset',
                    'name' => 'AES-128-GCM',
                    'bom-ref' => 'crypto-asset-1',
                    'patentAssertions' => [
                        [
                            'assertionType' => 'license',
                            'asserter' => 'org-1',
                            'patentRefs' => ['patent-1'],
                        ],
                    ],
                    'cryptoProperties' => [
                        'assetType' => 'algorithm',
                        'algorithmProperties' => [
                            'primitive' => 'ae',
                            'mode' => 'gcm',
                            'cryptoFunctions' => ['encrypt', 'decrypt'],
                            'classicalSecurityLevel' => 128,
                        ],
                    ],
                ],
            ],
        ];

        $bom = $this->subject->parseFromArray($data);
        $components = $bom->components ?? [];

        self::assertCount(1, $components);
        $component = $components[0];

        self::assertSame(\mteu\SbomParser\Entity\ComponentType::CRYPTOGRAPHIC_ASSET, $component->type);

        self::assertNotNull($component->patentAssertions);
        self::assertCount(1, $component->patentAssertions);
        $assertion = $component->patentAssertions[0];
        self::assertSame(\mteu\SbomParser\Entity\PatentAssertionType::LICENSE, $assertion->assertionType);
        self::assertSame('org-1', $assertion->asserter);
        self::assertSame(['patent-1'], $assertion->patentRefs);

        self::assertNotNull($component->cryptoProperties);
        self::assertSame(\mteu\SbomParser\Entity\CryptoAssetType::ALGORITHM, $component->cryptoProperties->assetType);

        $algo = $component->cryptoProperties->algorithmProperties;
        self::assertNotNull($algo);
        self::assertSame(\mteu\SbomParser\Entity\CryptographicPrimitive::AE, $algo->primitive);
        self::assertSame(\mteu\SbomParser\Entity\CryptoMode::GCM, $algo->mode);
        self::assertSame(
            [\mteu\SbomParser\Entity\CryptoFunction::ENCRYPT, \mteu\SbomParser\Entity\CryptoFunction::DECRYPT],
            $algo->cryptoFunctions,
        );
        self::assertSame(128, $algo->classicalSecurityLevel);
    }

    #[Test]
    public function parseFromArrayHydratesHash(): void
    {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.7',
            'components' => [
                [
                    'type' => 'library',
                    'name' => 'component',
                    'hashes' => [
                        [
                            'alg' => 'SHA-256',
                            'content' => 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                        ],
                    ],
                ],
            ],
        ]);

        $hashes = $bom->components[0]->hashes ?? [];

        self::assertCount(1, $hashes);
        self::assertSame('SHA-256', $hashes[0]->alg->value);
        self::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $hashes[0]->content);
    }

    #[Test]
    public function parseFromFileHydratesHashesFromHandAuthoredFixture(): void
    {
        $bom = $this->subject->parseFromFile(self::fixtureDir() . '/bom-1.6-custom.json');

        $components = $bom->components ?? [];
        self::assertCount(1, $components);

        $hashes = $components[0]->hashes ?? [];
        self::assertCount(4, $hashes);
        self::assertSame(
            [HashAlgorithm::SHA1, HashAlgorithm::SHA256, HashAlgorithm::SHA512, HashAlgorithm::BLAKE3],
            array_map(static fn (Hash $hash): HashAlgorithm => $hash->alg, $hashes),
        );
        self::assertSame('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', $hashes[1]->content);
    }

    #[Test]
    public function parseFromFileHydratesBomRefOnOrganizationalEntitiesContactsAndCompositions(): void
    {
        $bom = $this->parseHandAuthoredFixture();

        $manufacturer = $bom->metadata?->manufacturer;
        self::assertNotNull($manufacturer);
        self::assertSame('org-acme', $manufacturer->bomRef);

        $contacts = $manufacturer->contact ?? [];
        self::assertCount(1, $contacts);
        self::assertSame('contact-jane', $contacts[0]->bomRef);

        $compositions = $bom->compositions ?? [];
        self::assertCount(1, $compositions);
        self::assertSame('composition-complete', $compositions[0]->bomRef);
    }

    #[Test]
    public function parseFromFileHydratesComponentAndServiceTagsAndServiceTrustZone(): void
    {
        $bom = $this->parseHandAuthoredFixture();

        $components = $bom->components ?? [];
        self::assertCount(1, $components);
        self::assertSame(['php', 'parser'], $components[0]->tags);

        $services = $bom->services ?? [];
        self::assertCount(1, $services);
        self::assertSame(['api', 'billing'], $services[0]->tags);
        self::assertSame('public', $services[0]->trustZone);
    }

    #[Test]
    public function parseFromFileHydratesComponentProvenanceAndMetadataManufacturer(): void
    {
        $bom = $this->parseHandAuthoredFixture();

        self::assertSame('Acme Corporation', $bom->metadata?->manufacturer?->name);

        $components = $bom->components ?? [];
        self::assertCount(1, $components);
        $component = $components[0];

        self::assertSame('Acme Manufacturing', $component->manufacturer?->name);

        $authors = $component->authors ?? [];
        self::assertCount(1, $authors);
        self::assertSame('John Roe', $authors[0]->name);
        self::assertSame('john@acme.example', $authors[0]->email);
        self::assertSame('author-john', $authors[0]->bomRef);

        self::assertSame(['gitoid:blob:sha1:261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64'], $component->omniborId);
        self::assertSame(['swh:1:cnt:94a9ed024d3859793618152ea559a168bbcbb5e2'], $component->swhid);
        self::assertSame(
            ['algorithm' => 'ES256', 'value' => 'c2lnbmF0dXJlLXZhbHVl'],
            $component->signature?->signatureData,
        );
    }

    #[Test]
    public function parseFromFileHydratesDependencyProvidesCompositionVulnerabilitiesAndReferenceHashes(): void
    {
        $bom = $this->parseHandAuthoredFixture();

        $dependencies = $bom->dependencies ?? [];
        self::assertCount(1, $dependencies);
        self::assertSame(['service-billing'], $dependencies[0]->provides);

        $compositions = $bom->compositions ?? [];
        self::assertCount(1, $compositions);
        self::assertSame(['vuln-1'], $compositions[0]->vulnerabilities);

        $components = $bom->components ?? [];
        self::assertCount(1, $components);
        $externalReferences = $components[0]->externalReferences ?? [];
        self::assertCount(1, $externalReferences);

        $hashes = $externalReferences[0]->hashes ?? [];
        self::assertCount(1, $hashes);
        self::assertSame(HashAlgorithm::SHA256, $hashes[0]->alg);
        self::assertSame('2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae', $hashes[0]->content);
    }

    #[Test]
    public function parseFromFileHydratesVulnerabilityWorkaroundAndRejectionTimestamp(): void
    {
        $bom = $this->parseHandAuthoredFixture();

        $vulnerabilities = $bom->vulnerabilities ?? [];
        self::assertCount(1, $vulnerabilities);
        self::assertSame('Disable the affected feature flag.', $vulnerabilities[0]->workaround);
        self::assertSame('2026-03-01T11:00:00.250000+01:00', $vulnerabilities[0]->rejected?->format('Y-m-d\TH:i:s.uP'));
    }

    #[Test]
    public function parseFromFileHydratesOrganizationalEntityPostalAddress(): void
    {
        $bom = $this->parseHandAuthoredFixture();

        $address = $bom->metadata?->manufacturer?->address;
        self::assertNotNull($address);
        self::assertSame('address-acme-hq', $address->bomRef);
        self::assertSame('DE', $address->country);
        self::assertSame('Berlin', $address->region);
        self::assertSame('Berlin', $address->locality);
        self::assertSame('1234', $address->postOfficeBoxNumber);
        self::assertSame('10115', $address->postalCode);
        self::assertSame('Invalidenstraße 1', $address->streetAddress);
    }

    #[Test]
    public function parseFromFileHydratesVulnerabilityProofOfConceptWithSupportingMaterial(): void
    {
        $bom = $this->parseHandAuthoredFixture();

        $vulnerabilities = $bom->vulnerabilities ?? [];
        self::assertCount(1, $vulnerabilities);

        $proofOfConcept = $vulnerabilities[0]->proofOfConcept;
        self::assertNotNull($proofOfConcept);
        self::assertSame('Send a crafted SBOM to the upload endpoint.', $proofOfConcept->reproductionSteps);
        self::assertSame('PHP 8.4 on Linux', $proofOfConcept->environment);

        $supportingMaterial = $proofOfConcept->supportingMaterial ?? [];
        self::assertCount(1, $supportingMaterial);
        self::assertSame('text/plain', $supportingMaterial[0]->contentType);
        self::assertSame('curl -X POST ...', $supportingMaterial[0]->content);
    }

    private function parseHandAuthoredFixture(): Bom
    {
        return $this->subject->parseFromFile(self::fixtureDir() . '/bom-1.6-custom.json');
    }

    #[Test]
    public function parseFromFileTypesTheAnalysisOfAVexDocument(): void
    {
        $vulnerabilities = $this->parseVexFixture()->vulnerabilities ?? [];
        self::assertCount(6, $vulnerabilities);

        self::assertSame(
            [
                ImpactAnalysisState::NOT_AFFECTED,
                ImpactAnalysisState::EXPLOITABLE,
                ImpactAnalysisState::RESOLVED,
                ImpactAnalysisState::FALSE_POSITIVE,
                ImpactAnalysisState::IN_TRIAGE,
                ImpactAnalysisState::NOT_AFFECTED,
            ],
            array_map(static fn (Vulnerability $vulnerability): ?ImpactAnalysisState => $vulnerability->analysis?->state, $vulnerabilities),
        );

        $notAffected = $vulnerabilities[0]->analysis;
        self::assertNotNull($notAffected);
        self::assertSame(ImpactAnalysisJustification::CODE_NOT_REACHABLE, $notAffected->justification);
        self::assertNull($notAffected->response);
        self::assertSame('Fragments are never rendered, so the vulnerable path is never called.', $notAffected->detail);
        self::assertSame('2026-10-01T09:15:00+00:00', $notAffected->firstIssued?->format(\DateTimeInterface::ATOM));
        self::assertSame('2026-10-01T09:15:00+00:00', $notAffected->lastUpdated?->format(\DateTimeInterface::ATOM));

        self::assertSame([ImpactAnalysisResponse::UPDATE], $vulnerabilities[1]->analysis?->response);
    }

    #[Test]
    public function parseFromFileKeepsEveryEntryOfAVulnerabilityIdThatHitsTwoComponents(): void
    {
        $vulnerabilities = array_values(array_filter(
            $this->parseVexFixture()->vulnerabilities ?? [],
            static fn (Vulnerability $vulnerability): bool => $vulnerability->id === 'CVE-2026-1234',
        ));

        self::assertCount(2, $vulnerabilities);
        self::assertSame(
            [
                ['pkg:composer/symfony/http-kernel@5.4.19'],
                ['pkg:composer/symfony/http-kernel@6.4.2'],
            ],
            array_map(
                static fn (Vulnerability $vulnerability): array => array_map(
                    static fn (VulnerabilityAffects $affects): string => $affects->ref,
                    $vulnerability->affects ?? [],
                ),
                $vulnerabilities,
            ),
        );
        self::assertNotSame($vulnerabilities[0]->analysis?->state, $vulnerabilities[1]->analysis?->state);
    }

    #[Test]
    public function parseFromFileKeepsTheReferencesAndPropertiesOfAVexDocument(): void
    {
        $bom = $this->parseVexFixture();
        $vulnerabilities = $bom->vulnerabilities ?? [];

        self::assertNull($bom->serialNumber);
        self::assertSame('NVD', $vulnerabilities[0]->source?->name);
        self::assertSame('GHSA-jfh8-c2jp-5v3q', ($vulnerabilities[0]->references ?? [])[0]->id ?? null);

        self::assertSame(
            [['mteu:vex:justification', 'component_not_present']],
            array_map(
                static fn (Property $property): array => [$property->name, $property->value],
                $vulnerabilities[5]->properties ?? [],
            ),
        );
        self::assertSame(ImpactAnalysisJustification::CODE_NOT_PRESENT, $vulnerabilities[5]->analysis?->justification);
    }

    #[Test]
    public function parseFromFileFindsTheComponentsAVexDocumentRepeatsByPurl(): void
    {
        $bom = $this->parseVexFixture();

        self::assertCount(5, $bom->components ?? []);
        self::assertSame('http-kernel', $bom->findComponentByPurl('pkg:composer/symfony/http-kernel@6.4.2')?->name);
    }

    #[Test]
    public function parseFromFileReadsAVexDocumentWithoutComponents(): void
    {
        $bom = $this->subject->parseFromFile(self::fixtureDir() . '/vex-1.6-without-components.json');

        self::assertFalse($bom->hasComponents());
        self::assertSame([], $bom->getAllComponents());
        self::assertSame(ImpactAnalysisState::IN_TRIAGE, ($bom->vulnerabilities ?? [])[0]->analysis?->state);
    }

    /**
     * @return \Generator<string, array{array<string, mixed>, string}>
     */
    public static function unknownAnalysisValueProvider(): \Generator
    {
        yield 'state' => [['state' => 'resolved_with_hope'], 'vulnerabilities.1.analysis.state'];
        yield 'justification' => [['state' => 'not_affected', 'justification' => 'nobody_uses_it'], 'vulnerabilities.1.analysis.justification'];
        yield 'one of several responses' => [['state' => 'exploitable', 'response' => ['update', 'teleport']], 'vulnerabilities.1.analysis.response.1'];
    }

    /**
     * @param array<string, mixed> $analysis
     */
    #[Test]
    #[DataProvider('unknownAnalysisValueProvider')]
    public function parseFromArrayRejectsAnAnalysisValueOutsideTheVocabularyAndNamesItsPath(array $analysis, string $expectedPath): void
    {
        $exception = $this->catchParseException([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'vulnerabilities' => [
                ['id' => 'CVE-2026-0001', 'analysis' => ['state' => 'in_triage']],
                ['id' => 'CVE-2026-0002', 'analysis' => $analysis],
            ],
        ]);

        self::assertSame([$expectedPath], array_map(static fn (ParseErrorDetail $detail): string => $detail->path, $exception->details));
        self::assertStringContainsString('Error at path: ' . $expectedPath, $exception->getMessage());
    }

    #[Test]
    public function parseFromArrayListsEveryMappingErrorInDocumentOrder(): void
    {
        $exception = $this->catchParseException([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'components' => [['type' => 'library', 'name' => 'psr7', 'bom-ref' => ['not', 'a', 'string']]],
            'vulnerabilities' => [['id' => 'CVE-2026-0001', 'analysis' => ['state' => 'resolved_with_hope']]],
        ]);

        self::assertSame(SbomParseException::CODE_VALIDATION_FAILED, $exception->getCode());
        self::assertSame(
            ['components.0.bom-ref', 'vulnerabilities.0.analysis.state'],
            array_map(static fn (ParseErrorDetail $detail): string => $detail->path, $exception->details),
        );
        self::assertStringContainsString("'resolved_with_hope'", $exception->details[1]->message);
        self::assertStringContainsString('Total errors: 2', $exception->getMessage());
    }

    /**
     * @return \Generator<string, array{string, string}>
     */
    public static function rfc3339TimestampProvider(): \Generator
    {
        yield 'Z' => ['2026-10-01T09:15:00Z', '2026-10-01T09:15:00.000000+00:00'];
        yield 'numeric offset' => ['2026-10-01T11:15:00+02:00', '2026-10-01T09:15:00.000000+00:00'];
        yield 'fraction with Z' => ['2026-10-01T09:15:00.5Z', '2026-10-01T09:15:00.500000+00:00'];
        yield 'fraction with offset' => ['2026-10-01T11:15:00.123+02:00', '2026-10-01T09:15:00.123000+00:00'];
        yield 'fraction with negative offset' => ['2026-10-01T04:15:00.123456-05:00', '2026-10-01T09:15:00.123456+00:00'];
        yield 'nanoseconds are cut to microseconds' => ['2026-10-01T09:15:00.123456789Z', '2026-10-01T09:15:00.123456+00:00'];
        yield 'unknown local offset' => ['2026-10-01T09:15:00-00:00', '2026-10-01T09:15:00.000000+00:00'];
    }

    #[Test]
    #[DataProvider('rfc3339TimestampProvider')]
    public function parseFromArrayReadsAnRfc3339TimestampIndependentOfTheDefaultTimeZone(string $timestamp, string $expectedUtc): void
    {
        $defaultTimeZone = date_default_timezone_get();
        date_default_timezone_set('Europe/Berlin');

        try {
            $bom = $this->subject->parseFromArray([
                'bomFormat' => 'CycloneDX',
                'specVersion' => '1.6',
                'metadata' => ['timestamp' => $timestamp],
            ]);
        } finally {
            date_default_timezone_set($defaultTimeZone);
        }

        self::assertSame(
            $expectedUtc,
            $bom->metadata?->timestamp?->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.uP'),
        );
    }

    /**
     * @return \Generator<string, array{string}>
     */
    public static function invalidTimestampProvider(): \Generator
    {
        yield 'no offset' => ['2026-10-01T09:15:00'];
        yield 'space instead of T' => ['2026-10-01 09:15:00Z'];
        yield 'date only' => ['2026-10-01'];
        yield 'month 13' => ['2026-13-01T09:15:00Z'];
        yield 'day 32' => ['2026-10-32T09:15:00Z'];
        yield 'empty fraction' => ['2026-10-01T09:15:00.Z'];
        yield 'unpadded fields' => ['2026-1-01T09:15:00Z'];
        yield 'leap second' => ['2026-12-31T23:59:60Z'];
        yield 'lowercase z' => ['2026-10-01T09:15:00z'];
        yield 'offset without colon' => ['2026-10-01T09:15:00+0200'];
        yield 'offset in hours only' => ['2026-10-01T09:15:00+02'];
        yield 'time zone abbreviation' => ['2026-10-01T09:15:00GMT'];
        yield 'trailing text' => ['2026-10-01T09:15:00Z trailing'];
    }

    #[Test]
    #[DataProvider('invalidTimestampProvider')]
    public function parseFromArrayRejectsATimestampThatIsNotRfc3339(string $timestamp): void
    {
        $exception = $this->catchParseException([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'metadata' => ['timestamp' => $timestamp],
        ]);

        self::assertSame(['metadata.timestamp'], array_map(static fn (ParseErrorDetail $detail): string => $detail->path, $exception->details));
        self::assertStringContainsString('is not an RFC 3339 timestamp', $exception->details[0]->message);
    }

    /**
     * @return \Generator<string, array{string, int}>
     */
    public static function failureBeforeMappingProvider(): \Generator
    {
        yield 'invalid JSON' => ['{', SbomParseException::CODE_INVALID_JSON];
        yield 'unsupported version' => ['{"bomFormat": "CycloneDX", "specVersion": "0.9"}', SbomParseException::CODE_UNSUPPORTED_VERSION];
        yield 'node budget' => ['{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1}', SbomParseException::CODE_VALIDATION_FAILED];
    }

    #[Test]
    #[DataProvider('failureBeforeMappingProvider')]
    public function parseFailureBeforeMappingCarriesNoDetails(string $json, int $expectedCode): void
    {
        $parser = new CycloneDxParser(new CycloneDxParserOptions(maxNodes: 2));

        try {
            $parser->parseFromJson($json);
        } catch (SbomParseException $exception) {
            self::assertSame($expectedCode, $exception->getCode());
            self::assertSame([], $exception->details);

            return;
        }

        self::fail('Expected an SbomParseException.');
    }

    /**
     * @param array<string, mixed> $data
     */
    private function catchParseException(array $data): SbomParseException
    {
        try {
            $this->subject->parseFromArray($data);
        } catch (SbomParseException $exception) {
            return $exception;
        }

        self::fail('Expected an SbomParseException.');
    }

    /**
     * @return \Generator<string, array{array<string, mixed>, ImpactAnalysisState, ImpactAnalysisJustification|null, list<ImpactAnalysisResponse>|null}>
     */
    public static function everyAnalysisValueProvider(): \Generator
    {
        foreach (ImpactAnalysisState::cases() as $state) {
            yield 'state ' . $state->value => [['state' => $state->value], $state, null, null];
        }
        foreach (ImpactAnalysisJustification::cases() as $justification) {
            yield 'justification ' . $justification->value => [
                ['state' => 'not_affected', 'justification' => $justification->value],
                ImpactAnalysisState::NOT_AFFECTED,
                $justification,
                null,
            ];
        }
        foreach (ImpactAnalysisResponse::cases() as $response) {
            yield 'response ' . $response->value => [
                ['state' => 'exploitable', 'response' => [$response->value]],
                ImpactAnalysisState::EXPLOITABLE,
                null,
                [$response],
            ];
        }
    }

    /**
     * @param array<string, mixed> $analysis
     * @param list<ImpactAnalysisResponse>|null $expectedResponse
     */
    #[Test]
    #[DataProvider('everyAnalysisValueProvider')]
    public function parseFromArrayMapsEveryAnalysisValueOfTheVocabularyToItsEnumCase(
        array $analysis,
        ImpactAnalysisState $expectedState,
        ?ImpactAnalysisJustification $expectedJustification,
        ?array $expectedResponse,
    ): void {
        $bom = $this->subject->parseFromArray([
            'bomFormat' => 'CycloneDX',
            'specVersion' => '1.6',
            'vulnerabilities' => [['id' => 'CVE-2026-0001', 'analysis' => $analysis]],
        ]);

        $parsed = ($bom->vulnerabilities ?? [])[0]->analysis;
        self::assertNotNull($parsed);
        self::assertSame($expectedState, $parsed->state);
        self::assertSame($expectedJustification, $parsed->justification);
        self::assertSame($expectedResponse, $parsed->response);
    }

    private function parseVexFixture(): Bom
    {
        return $this->subject->parseFromFile(self::fixtureDir() . '/vex-1.6.json');
    }

    #[Test]
    #[DataProvider('isValidSbomFileProvider')]
    public function isValidSbomFile(string $filePath, bool $expected): void
    {
        self::assertSame($expected, $this->subject->isValidSbomFile($filePath));
    }

    /** @return \Generator<string, array{string, bool}> */
    public static function isValidSbomFileProvider(): \Generator
    {
        foreach (CycloneDxParser::SUPPORTED_VERSIONS as $version) {
            yield "valid bom-{$version}.json" => [self::fixtureDir() . "/bom-{$version}.json", true];
        }

        yield 'non-existent file' => ['/tmp/nonexistent-file-abc123.json', false];
        yield 'invalid relative path' => ['relative/path.json', false];
    }

    #[Test]
    #[DataProvider('isValidSbomJsonProvider')]
    public function isValidSbomJson(string $json, bool $expected): void
    {
        self::assertSame($expected, $this->subject->isValidSbomJson($json));
    }

    /** @return \Generator<string, array{string, bool}> */
    public static function isValidSbomJsonProvider(): \Generator
    {
        yield 'non-array JSON' => ['"just a string"', false];
        yield 'malformed JSON' => ['{broken json', false];
    }

    /**
     * @param array<string, mixed> $data
     */
    #[Test]
    #[DataProvider('isValidSbomArrayProvider')]
    public function isValidSbomArray(array $data, bool $expected): void
    {
        self::assertSame($expected, $this->subject->isValidSbomArray($data));
    }

    /** @return \Generator<string, array{array<string, mixed>, bool}> */
    public static function isValidSbomArrayProvider(): \Generator
    {
        yield 'valid structure' => [
            ['bomFormat' => 'CycloneDX', 'specVersion' => '1.5'],
            true,
        ];

        yield 'invalid format' => [
            ['bomFormat' => 'SPDX', 'specVersion' => '1.5'],
            false,
        ];
    }
}
