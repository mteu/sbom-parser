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

namespace mteu\SbomParser\Tests\Unit\Entity;

use mteu\SbomParser\Entity\License;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * LicenseTest.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(License::class)]
final class LicenseTest extends TestCase
{
    #[Test]
    public function hasExpressionReturnsFalseWhenNull(): void
    {
        $license = new License(id: 'MIT');

        self::assertFalse($license->hasExpression());
    }

    #[Test]
    public function hasExpressionReturnsTrueWhenExpressionExists(): void
    {
        $license = new License(expression: 'MIT OR Apache-2.0');

        self::assertTrue($license->hasExpression());
    }

    #[Test]
    public function hasExpressionReturnsTrueWhenExpressionIsEmptyString(): void
    {
        $license = new License(expression: '');

        self::assertTrue($license->hasExpression());
    }
}
