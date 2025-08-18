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

    /**
     * @deprecated Trivial getter - access property directly
     */
    public function getBomFormat(): string
    {
        return $this->bomFormat;
    }

    /**
     * @deprecated Trivial getter - access property directly
     */
    public function getSpecVersion(): string
    {
        return $this->specVersion;
    }

    /**
     * @deprecated Trivial getter - access property directly
     */
    public function getSerialNumber(): ?string
    {
        return $this->serialNumber;
    }

    /**
     * @deprecated Trivial getter - access property directly
     */
    public function getVersion(): ?int
    {
        return $this->version;
    }

    /**
     * @deprecated Trivial getter - access property directly
     */
    public function getMetadata(): ?Metadata
    {
        return $this->metadata;
    }

    /**
     * @return Component[]
     */
    public function getComponents(): array
    {
        return $this->components ?? [];
    }

    /**
     * @return Vulnerability[]
     */
    public function getVulnerabilities(): array
    {
        return $this->vulnerabilities ?? [];
    }

    /**
     * @deprecated Trivial getter - access property directly with null coalescing
     * @return ExternalReference[]
     */
    public function getExternalReferences(): array
    {
        return $this->externalReferences ?? [];
    }

    /**
     * @deprecated Trivial getter - access property directly with null coalescing
     * @return Dependency[]
     */
    public function getDependencies(): array
    {
        return $this->dependencies ?? [];
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

        foreach ($this->getComponents() as $component) {
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

    /**
     * @deprecated Trivial getter - access property directly with null coalescing
     * @return Service[]
     */
    public function getServices(): array
    {
        return $this->services ?? [];
    }

    public function hasServices(): bool
    {
        return $this->services !== null && count($this->services) > 0;
    }

    /**
     * @deprecated Trivial getter - access property directly with null coalescing
     * @return Compositions[]
     */
    public function getCompositions(): array
    {
        return $this->compositions ?? [];
    }

    public function hasCompositions(): bool
    {
        return $this->compositions !== null && count($this->compositions) > 0;
    }

    /**
     * @deprecated Trivial getter - access property directly
     */
    public function getSignature(): ?Signature
    {
        return $this->signature;
    }

    /**
     * @deprecated Trivial getter - access property directly with null coalescing
     * @return Property[]
     */
    public function getProperties(): array
    {
        return $this->properties ?? [];
    }
}
