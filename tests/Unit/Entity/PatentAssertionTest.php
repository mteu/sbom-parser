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

namespace mteu\SbomParser\Tests\Unit\Entity;

use mteu\SbomParser\Entity\OrganizationalEntity;
use mteu\SbomParser\Entity\PatentAssertion;
use mteu\SbomParser\Entity\PatentAssertionType;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * PatentAssertionTest.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(PatentAssertion::class)]
final class PatentAssertionTest extends TestCase
{
    #[Test]
    public function constructsWithRequiredFieldsOnly(): void
    {
        $assertion = new PatentAssertion(
            assertionType: PatentAssertionType::OWNERSHIP,
            asserter: 'org-1',
        );

        self::assertSame(PatentAssertionType::OWNERSHIP, $assertion->assertionType);
        self::assertSame('org-1', $assertion->asserter);
        self::assertNull($assertion->bomRef);
        self::assertNull($assertion->patentRefs);
        self::assertNull($assertion->notes);
    }

    #[Test]
    public function constructsWithOrganizationalEntityAsserter(): void
    {
        $entity = new OrganizationalEntity(name: 'Acme Corp');
        $assertion = new PatentAssertion(
            assertionType: PatentAssertionType::LICENSE,
            asserter: $entity,
            bomRef: 'patent-assertion-1',
            patentRefs: ['patent-1', 'patent-family-1'],
            notes: 'Limited to EU jurisdiction.',
        );

        self::assertSame($entity, $assertion->asserter);
        self::assertSame('patent-assertion-1', $assertion->bomRef);
        self::assertSame(['patent-1', 'patent-family-1'], $assertion->patentRefs);
        self::assertSame('Limited to EU jurisdiction.', $assertion->notes);
    }

    #[Test]
    public function supportsAllAssertionTypes(): void
    {
        foreach (PatentAssertionType::cases() as $type) {
            $assertion = new PatentAssertion(
                assertionType: $type,
                asserter: 'org-x',
            );

            self::assertSame($type, $assertion->assertionType);
        }
    }
}
