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

use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Entity\Component;
use mteu\SbomParser\Entity\ComponentType;
use mteu\SbomParser\Entity\Service;
use mteu\SbomParser\Entity\Vulnerability\Vulnerability;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * BomTest.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(Bom::class)]
final class BomTest extends TestCase
{
    #[Test]
    public function getComponentsReturnsEmptyArrayWhenNull(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        self::assertSame([], $bom->getComponents());
    }

    #[Test]
    public function getComponentsReturnsComponentsWhenSet(): void
    {
        $component = new Component(ComponentType::LIBRARY, 'test-lib');
        $bom = new Bom('CycloneDX', '1.6', components: [$component]);

        self::assertSame([$component], $bom->getComponents());
    }

    #[Test]
    public function getVulnerabilitiesReturnsEmptyArrayWhenNull(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        self::assertSame([], $bom->getVulnerabilities());
    }

    #[Test]
    public function getVulnerabilitiesReturnsVulnerabilitiesWhenSet(): void
    {
        $vulnerability = new Vulnerability(id: 'CVE-2023-1234');
        $bom = new Bom('CycloneDX', '1.6', vulnerabilities: [$vulnerability]);

        self::assertSame([$vulnerability], $bom->getVulnerabilities());
    }

    #[Test]
    public function hasComponentsReturnsFalseWhenNull(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        self::assertFalse($bom->hasComponents());
    }

    #[Test]
    public function hasComponentsReturnsFalseWhenEmptyArray(): void
    {
        $bom = new Bom('CycloneDX', '1.6', components: []);

        self::assertFalse($bom->hasComponents());
    }

    #[Test]
    public function hasComponentsReturnsTrueWhenComponentsExist(): void
    {
        $component = new Component(ComponentType::LIBRARY, 'test-lib');
        $bom = new Bom('CycloneDX', '1.6', components: [$component]);

        self::assertTrue($bom->hasComponents());
    }

    #[Test]
    public function hasVulnerabilitiesReturnsFalseWhenNull(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        self::assertFalse($bom->hasVulnerabilities());
    }

    #[Test]
    public function hasVulnerabilitiesReturnsFalseWhenEmptyArray(): void
    {
        $bom = new Bom('CycloneDX', '1.6', vulnerabilities: []);

        self::assertFalse($bom->hasVulnerabilities());
    }

    #[Test]
    public function hasVulnerabilitiesReturnsTrueWhenVulnerabilitiesExist(): void
    {
        $vulnerability = new Vulnerability(id: 'CVE-2023-1234');
        $bom = new Bom('CycloneDX', '1.6', vulnerabilities: [$vulnerability]);

        self::assertTrue($bom->hasVulnerabilities());
    }

    #[Test]
    public function hasServicesReturnsFalseWhenNull(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        self::assertFalse($bom->hasServices());
    }

    #[Test]
    public function hasServicesReturnsFalseWhenEmptyArray(): void
    {
        $bom = new Bom('CycloneDX', '1.6', services: []);

        self::assertFalse($bom->hasServices());
    }

    #[Test]
    public function hasServicesReturnsTrueWhenServicesExist(): void
    {
        $service = new Service('test-service');
        $bom = new Bom('CycloneDX', '1.6', services: [$service]);

        self::assertTrue($bom->hasServices());
    }

    #[Test]
    public function getAllComponentsReturnsEmptyArrayWhenNoComponents(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        self::assertSame([], $bom->getAllComponents());
    }

    #[Test]
    public function getAllComponentsReturnsDirectComponentsOnly(): void
    {
        $component1 = new Component(ComponentType::LIBRARY, 'lib1');
        $component2 = new Component(ComponentType::APPLICATION, 'app1');
        $bom = new Bom('CycloneDX', '1.6', components: [$component1, $component2]);

        $result = $bom->getAllComponents();

        self::assertCount(2, $result);
        self::assertSame($component1, $result[0]);
        self::assertSame($component2, $result[1]);
    }

    #[Test]
    public function getAllComponentsIncludesNestedComponents(): void
    {
        $nestedComponent = new Component(ComponentType::LIBRARY, 'nested-lib');
        $parentComponent = new Component(
            ComponentType::APPLICATION,
            'parent-app',
            components: [$nestedComponent]
        );
        $bom = new Bom('CycloneDX', '1.6', components: [$parentComponent]);

        $result = $bom->getAllComponents();

        self::assertCount(2, $result);
        self::assertSame($parentComponent, $result[0]);
        self::assertSame($nestedComponent, $result[1]);
    }

    #[Test]
    public function getAllComponentsIncludesDeeplyNestedComponents(): void
    {
        $deeplyNestedComponent = new Component(ComponentType::LIBRARY, 'deeply-nested');
        $nestedComponent = new Component(
            ComponentType::LIBRARY,
            'nested',
            components: [$deeplyNestedComponent]
        );
        $parentComponent = new Component(
            ComponentType::APPLICATION,
            'parent',
            components: [$nestedComponent]
        );
        $bom = new Bom('CycloneDX', '1.6', components: [$parentComponent]);

        $result = $bom->getAllComponents();

        self::assertCount(3, $result);
        self::assertSame($parentComponent, $result[0]);
        self::assertSame($nestedComponent, $result[1]);
        self::assertSame($deeplyNestedComponent, $result[2]);
    }

    #[Test]
    public function findComponentsByTypeReturnsEmptyArrayWhenNoComponents(): void
    {
        $bom = new Bom('CycloneDX', '1.6');

        $result = $bom->findComponentsByType(ComponentType::LIBRARY);

        self::assertSame([], $result);
    }

    #[Test]
    public function findComponentsByTypeFiltersCorrectly(): void
    {
        $library1 = new Component(ComponentType::LIBRARY, 'lib1');
        $library2 = new Component(ComponentType::LIBRARY, 'lib2');
        $application = new Component(ComponentType::APPLICATION, 'app1');
        $bom = new Bom('CycloneDX', '1.6', components: [$library1, $application, $library2]);

        $result = $bom->findComponentsByType(ComponentType::LIBRARY);

        self::assertCount(2, $result);
        self::assertContains($library1, $result);
        self::assertContains($library2, $result);
        self::assertNotContains($application, $result);
    }

    #[Test]
    public function findComponentsByTypeIncludesNestedComponents(): void
    {
        $nestedLibrary = new Component(ComponentType::LIBRARY, 'nested-lib');
        $parentApp = new Component(
            ComponentType::APPLICATION,
            'parent-app',
            components: [$nestedLibrary]
        );
        $bom = new Bom('CycloneDX', '1.6', components: [$parentApp]);

        $result = $bom->findComponentsByType(ComponentType::LIBRARY);

        self::assertCount(1, $result);
        self::assertSame($nestedLibrary, array_values($result)[0]);
    }

    #[Test]
    public function findComponentByPurlReturnsNullWhenNotFound(): void
    {
        $component = new Component(ComponentType::LIBRARY, 'lib1', purl: 'pkg:npm/lib1@1.0.0');
        $bom = new Bom('CycloneDX', '1.6', components: [$component]);

        $result = $bom->findComponentByPurl('pkg:npm/lib2@1.0.0');

        self::assertNull($result);
    }

    #[Test]
    public function findComponentByPurlReturnsNullWhenNoPurl(): void
    {
        $component = new Component(ComponentType::LIBRARY, 'lib1');
        $bom = new Bom('CycloneDX', '1.6', components: [$component]);

        $result = $bom->findComponentByPurl('pkg:npm/lib1@1.0.0');

        self::assertNull($result);
    }

    #[Test]
    public function findComponentByPurlReturnsMatchingComponent(): void
    {
        $component1 = new Component(ComponentType::LIBRARY, 'lib1', purl: 'pkg:npm/lib1@1.0.0');
        $component2 = new Component(ComponentType::LIBRARY, 'lib2', purl: 'pkg:npm/lib2@2.0.0');
        $bom = new Bom('CycloneDX', '1.6', components: [$component1, $component2]);

        $result = $bom->findComponentByPurl('pkg:npm/lib2@2.0.0');

        self::assertSame($component2, $result);
    }

    #[Test]
    public function findComponentByPurlSearchesNestedComponents(): void
    {
        $nestedComponent = new Component(ComponentType::LIBRARY, 'nested', purl: 'pkg:npm/nested@1.0.0');
        $parentComponent = new Component(
            ComponentType::APPLICATION,
            'parent',
            components: [$nestedComponent]
        );
        $bom = new Bom('CycloneDX', '1.6', components: [$parentComponent]);

        $result = $bom->findComponentByPurl('pkg:npm/nested@1.0.0');

        self::assertSame($nestedComponent, $result);
    }
}
