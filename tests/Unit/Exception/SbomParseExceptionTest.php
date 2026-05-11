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

namespace mteu\SbomParser\Tests\Unit\Exception;

use mteu\SbomParser\Exception\SbomParseException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(SbomParseException::class)]
final class SbomParseExceptionTest extends TestCase
{
    #[Test]
    public function invalidJsonCarriesItsCodeAndPreviousException(): void
    {
        $previous = new \RuntimeException('underlying');
        $exception = SbomParseException::invalidJson('boom', $previous);

        self::assertSame(SbomParseException::CODE_INVALID_JSON, $exception->getCode());
        self::assertSame($previous, $exception->getPrevious());
        self::assertStringContainsString('Invalid JSON: boom', $exception->getMessage());
    }

    #[Test]
    public function validationFailedCarriesItsCodeAndPreviousException(): void
    {
        $previous = new \LogicException('cause');
        $exception = SbomParseException::validationFailed('bad shape', $previous);

        self::assertSame(SbomParseException::CODE_VALIDATION_FAILED, $exception->getCode());
        self::assertSame($previous, $exception->getPrevious());
        self::assertStringContainsString('SBOM validation failed: bad shape', $exception->getMessage());
    }

    #[Test]
    public function unsupportedFormatCarriesItsCode(): void
    {
        $exception = SbomParseException::unsupportedFormat('SPDX');

        self::assertSame(SbomParseException::CODE_UNSUPPORTED_FORMAT, $exception->getCode());
        self::assertNull($exception->getPrevious());
        self::assertStringContainsString('SPDX', $exception->getMessage());
    }

    #[Test]
    public function unsupportedVersionCarriesItsCode(): void
    {
        $exception = SbomParseException::unsupportedVersion('0.9');

        self::assertSame(SbomParseException::CODE_UNSUPPORTED_VERSION, $exception->getCode());
        self::assertNull($exception->getPrevious());
        self::assertStringContainsString('0.9', $exception->getMessage());
    }

    #[Test]
    public function errorCodesAreDistinct(): void
    {
        $codes = [
            SbomParseException::CODE_INVALID_JSON,
            SbomParseException::CODE_VALIDATION_FAILED,
            SbomParseException::CODE_UNSUPPORTED_FORMAT,
            SbomParseException::CODE_UNSUPPORTED_VERSION,
        ];

        self::assertCount(count($codes), array_unique($codes));
    }
}
