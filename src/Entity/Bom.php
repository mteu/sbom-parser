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

namespace mteu\SbomParser\Entity;

use mteu\SbomParser\Entity\Vulnerability\Vulnerability;

/**
 * Bom.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final readonly class Bom
{
    public function __construct(
        public string $bomFormat,
        public string $specVersion,
        public ?string $serialNumber = null,
        public ?int $version = null,
        public ?Metadata $metadata = null,
        /** @var Component[]|null */
        public ?array $components = null,
        /** @var Service[]|null */
        public ?array $services = null,
        /** @var ExternalReference[]|null */
        public ?array $externalReferences = null,
        /** @var Dependency[]|null */
        public ?array $dependencies = null,
        /** @var Compositions[]|null */
        public ?array $compositions = null,
        /** @var Vulnerability[]|null */
        public ?array $vulnerabilities = null,
        /** @var Property[]|null */
        public ?array $properties = null,
        public ?Signature $signature = null,
    ) {
    }




    public function hasComponents(): bool
    {
        return $this->components !== null && count($this->components) > 0;
    }

    public function hasVulnerabilities(): bool
    {
        return $this->vulnerabilities !== null && count($this->vulnerabilities) > 0;
    }

    /**
     * @return Component[]
     */
    public function getAllComponents(): array
    {
        $allComponents = [];

        foreach (($this->components ?? []) as $component) {
            $allComponents[] = $component;
            $allComponents = array_merge($allComponents, $this->extractNestedComponents($component));
        }

        return $allComponents;
    }

    /**
     * @return Component[]
     */
    private function extractNestedComponents(Component $component): array
    {
        $nested = [];

        foreach (($component->components ?? []) as $childComponent) {
            $nested[] = $childComponent;
            $nested = array_merge($nested, $this->extractNestedComponents($childComponent));
        }

        return $nested;
    }

    /**
     * @return Component[]
     */
    public function findComponentsByType(ComponentType $type): array
    {
        return array_filter(
            $this->getAllComponents(),
            static fn (Component $component): bool => $component->type === $type
        );
    }

    public function findComponentByPurl(string $purl): ?Component
    {
        foreach ($this->getAllComponents() as $component) {
            if ($component->purl === $purl) {
                return $component;
            }
        }

        return null;
    }


    public function hasServices(): bool
    {
        return $this->services !== null && count($this->services) > 0;
    }


    public function hasCompositions(): bool
    {
        return $this->compositions !== null && count($this->compositions) > 0;
    }

}
