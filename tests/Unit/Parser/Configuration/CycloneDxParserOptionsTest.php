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

namespace mteu\SbomParser\Tests\Unit\Parser\Configuration;

use mteu\SbomParser\Parser\Configuration\CycloneDxParserOptions;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(CycloneDxParserOptions::class)]
final class CycloneDxParserOptionsTest extends TestCase
{
    #[Test]
    #[DataProvider('invalidMaxFileSizeProvider')]
    public function constructorRejectsNonPositiveMaxFileSize(int $invalid): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('maxFileSize must be a positive integer');
        new CycloneDxParserOptions(maxFileSize: $invalid);
    }

    /** @return \Generator<string, array{int}> */
    public static function invalidMaxFileSizeProvider(): \Generator
    {
        yield 'zero' => [0];
        yield 'negative one' => [-1];
        yield 'large negative' => [-1024 * 1024];
    }

    #[Test]
    public function withMaxFileSizeReturnsNewInstance(): void
    {
        $original = new CycloneDxParserOptions(maxFileSize: 1024);
        $mutated = $original->withMaxFileSize(2048);

        self::assertNotSame($original, $mutated);
        self::assertSame(1024, $original->maxFileSize);
        self::assertSame(2048, $mutated->maxFileSize);
    }

    #[Test]
    public function withMaxFileSizeValidatesNewValue(): void
    {
        $original = new CycloneDxParserOptions();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('maxFileSize must be a positive integer');
        $original->withMaxFileSize(0);
    }
}
