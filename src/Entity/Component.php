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

/**
 * Component entity based on CycloneDX 1.4+ specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final readonly class Component
{
    public function __construct(
        public ComponentType $type,
        public string $name,
        public ?string $bomRef = null,
        public ?OrganizationalEntity $supplier = null,
        public ?string $author = null,
        public ?string $publisher = null,
        public ?string $group = null,
        public ?string $version = null,
        public ?string $description = null,
        public ?string $scope = null,
        /** @var Hash[]|null */
        public ?array $hashes = null,
        /** @var License[]|null */
        public ?array $licenses = null,
        public ?string $copyright = null,
        public ?string $cpe = null,
        public ?string $purl = null,
        public ?string $mimeType = null,
        public ?SwidTag $swid = null,
        public ?ComponentEvidence $evidence = null,
        public ?ReleaseNotes $releaseNotes = null,
        public ?bool $modified = null,
        public ?Pedigree $pedigree = null,
        /** @var ExternalReference[]|null */
        public ?array $externalReferences = null,
        /** @var Property[]|null */
        public ?array $properties = null,
        /** @var Component[]|null */
        public ?array $components = null,
    ) {
    }



    public function hasComponents(): bool
    {
        return $this->components !== null && count($this->components) > 0;
    }

}
