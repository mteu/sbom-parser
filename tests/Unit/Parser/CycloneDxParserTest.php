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

        $this->tempOutputDir = dirname(__DIR__, 2) . '/Unit/_temp/unit_' . uniqid();
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

    #[Test]
    public function parserSucceedsInParsingAPerfectlyValidSbomJson(): void
    {
        $sbom = $this->subject->parseFromFile(dirname(__DIR__, ) . '/Fixtures/cdx.sbom.json');
        self::assertInstanceOf(Bom::class, $sbom);
    }

    #[Test]
    public function validatingSbomFileSucceedsForAProperFile(): void
    {
        self::assertTrue(
            $this->subject->isValidSbomFile(dirname(__DIR__, ) . '/Fixtures/cdx.sbom.json')
        );
    }

    #[Test]
    public function parserThrowsExceptionForMissingFileInPath(): void
    {
        self::expectException(SbomParseException::class);
        self::expectExceptionMessage('SBOM validation failed: File not found');
        $this->subject->parseFromFile(dirname(__DIR__, ) . '/Fixtures/meh.json');
    }

    #[Test]
    public function parserThrowsExceptionIfFileIsNotWithJsonExtension(): void
    {
        $filePath = tempnam($this->tempOutputDir,'json_');
        chmod($filePath, 0222); // write-only to simulate unreadable

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage('SBOM validation failed: SBOM file must have .json extension');
        $this->subject->parseFromFile($filePath);
    }

    #[Test]
    public function parserThrowsExceptionForUnreadableFileInPath(): void
    {
        $filePath = tempnam($this->tempOutputDir,'parse_json');
        rename($filePath, $filePath . '.json');
        $filePath = $filePath . '.json';
        chmod($filePath, 0222); // write-only to simulate unreadable

        $this->expectException(SbomParseException::class);
        $this->expectExceptionMessage("File not readable: $filePath");
        $this->subject->parseFromFile($filePath);
    }
}
