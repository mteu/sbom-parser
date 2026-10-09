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

namespace mteu\SbomParser\Tests\Unit\Exception;

use mteu\SbomParser\Exception\ParseErrorDetail;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(ParseErrorDetail::class)]
final class ParseErrorDetailTest extends TestCase
{
    /**
     * @return \Generator<string, array{string}>
     */
    public static function blankMessageProvider(): \Generator
    {
        yield 'empty' => [''];
        yield 'whitespace only' => ["  \n"];
    }

    #[Test]
    #[DataProvider('blankMessageProvider')]
    public function constructorRejectsABlankMessage(string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ParseErrorDetail('metadata.timestamp', $message);
    }

    #[Test]
    public function constructorAcceptsAnEmptyPathForTheDocumentRoot(): void
    {
        self::assertSame('', (new ParseErrorDetail('', 'Cannot be empty.'))->path);
    }
}
