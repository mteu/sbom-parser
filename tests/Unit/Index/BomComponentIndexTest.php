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

namespace mteu\SbomParser\Tests\Unit\Index;

use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Entity\Component;
use mteu\SbomParser\Entity\ComponentType;
use mteu\SbomParser\Index\BomComponentIndex;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(BomComponentIndex::class)]
final class BomComponentIndexTest extends TestCase
{
    #[Test]
    public function flattenReturnsEmptyListWhenBomHasNoComponents(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        self::assertSame([], BomComponentIndex::flatten($bom));
    }

    #[Test]
    public function flattenWalksComponentsDepthFirstInOrder(): void
    {
        $grandchild = new Component(ComponentType::LIBRARY, 'grandchild');
        $child = new Component(ComponentType::LIBRARY, 'child', components: [$grandchild]);
        $sibling = new Component(ComponentType::LIBRARY, 'sibling');
        $parent = new Component(ComponentType::APPLICATION, 'parent', components: [$child, $sibling]);
        $bom = new Bom('CycloneDX', '1.6', components: [$parent]);

        self::assertSame(
            [$parent, $child, $grandchild, $sibling],
            BomComponentIndex::flatten($bom),
        );
    }

    #[Test]
    public function flattenCachesPerBomInstance(): void
    {
        $bom = new Bom('CycloneDX', '1.6', components: [
            new Component(ComponentType::LIBRARY, 'a'),
        ]);

        $first = BomComponentIndex::flatten($bom);
        $second = BomComponentIndex::flatten($bom);

        self::assertSame($first, $second);
    }

    #[Test]
    public function flattenSegregatesCachesAcrossBomInstances(): void
    {
        $a = new Component(ComponentType::LIBRARY, 'a');
        $b = new Component(ComponentType::LIBRARY, 'b');
        $bomA = new Bom('CycloneDX', '1.6', components: [$a]);
        $bomB = new Bom('CycloneDX', '1.6', components: [$b]);

        self::assertSame([$a], BomComponentIndex::flatten($bomA));
        self::assertSame([$b], BomComponentIndex::flatten($bomB));
    }

    #[Test]
    public function byPurlReturnsEmptyMapWhenNoComponentsHavePurls(): void
    {
        $bom = new Bom('CycloneDX', '1.6', components: [
            new Component(ComponentType::LIBRARY, 'no-purl'),
        ]);

        self::assertSame([], BomComponentIndex::byPurl($bom));
    }

    #[Test]
    public function byPurlIndexesComponentsByTheirPurl(): void
    {
        $a = new Component(ComponentType::LIBRARY, 'symfony/console', purl: 'pkg:composer/symfony/console@7.1.0');
        $b = new Component(ComponentType::LIBRARY, 'cuyz/valinor', purl: 'pkg:composer/cuyz/valinor@2.0.0');
        $bom = new Bom('CycloneDX', '1.6', components: [$a, $b]);

        $index = BomComponentIndex::byPurl($bom);

        self::assertSame($a, $index['pkg:composer/symfony/console@7.1.0']);
        self::assertSame($b, $index['pkg:composer/cuyz/valinor@2.0.0']);
    }

    #[Test]
    public function byPurlSkipsComponentsWithoutPurl(): void
    {
        $withPurl = new Component(ComponentType::LIBRARY, 'symfony/console', purl: 'pkg:composer/symfony/console@7.1.0');
        $withoutPurl = new Component(ComponentType::LIBRARY, 'no-purl');
        $bom = new Bom('CycloneDX', '1.6', components: [$withPurl, $withoutPurl]);

        self::assertSame(['pkg:composer/symfony/console@7.1.0' => $withPurl], BomComponentIndex::byPurl($bom));
    }

    #[Test]
    public function byPurlKeepsFirstOccurrenceWhenPurlIsDuplicated(): void
    {
        $first = new Component(ComponentType::LIBRARY, 'first', purl: 'pkg:composer/symfony/console@7.1.0');
        $second = new Component(ComponentType::LIBRARY, 'second', purl: 'pkg:composer/symfony/console@7.1.0');
        $bom = new Bom('CycloneDX', '1.6', components: [$first, $second]);

        self::assertSame($first, BomComponentIndex::byPurl($bom)['pkg:composer/symfony/console@7.1.0']);
    }

    #[Test]
    public function byPurlIndexesNestedComponents(): void
    {
        $nested = new Component(ComponentType::LIBRARY, 'phpunit/phpunit', purl: 'pkg:composer/phpunit/phpunit@11.5.0');
        $parent = new Component(ComponentType::APPLICATION, 'parent', components: [$nested]);
        $bom = new Bom('CycloneDX', '1.6', components: [$parent]);

        self::assertSame($nested, BomComponentIndex::byPurl($bom)['pkg:composer/phpunit/phpunit@11.5.0']);
    }

    #[Test]
    public function byPurlCachesPerBomInstance(): void
    {
        $bom = new Bom('CycloneDX', '1.6', components: [
            new Component(ComponentType::LIBRARY, 'symfony/console', purl: 'pkg:composer/symfony/console@7.1.0'),
        ]);

        $first = BomComponentIndex::byPurl($bom);
        $second = BomComponentIndex::byPurl($bom);

        self::assertSame($first, $second);
    }
}
