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
 * SbomComponent based on CycloneDX 1.4+ specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final readonly class SbomComponent
{
    public function __construct(
        public string $name,
        public string $version,
        public string $type, // library, application, etc.
        public string $ecosystem, // npm, maven, pypi, etc.
        public string $purl, // Package URL
        public ?string $namespace = null,
        public ?string $scope = null,
        public ?string $group = null,
        public ?string $description = null,
        /** @var array<string, mixed> */
        public array $licenses = [],
        /** @var array<string, mixed> */
        public array $hashes = [],
        /** @var array<string, mixed> */
        public array $externalReferences = [],
    ) {
    }

    /**
     * Get the package identifier for vulnerability lookups
     */
    public function getPackageIdentifier(): string
    {
        if ($this->namespace !== null && $this->namespace !== '') {
            return $this->namespace . '/' . $this->name;
        }

        if ($this->group !== null && $this->group !== '') {
            return $this->group . ':' . $this->name;
        }

        return $this->name;
    }

    /**
     * Get the ecosystem normalized for API calls
     */
    public function getNormalizedEcosystem(): string
    {
        return match (strtolower($this->ecosystem)) {
            'npm', 'node' => 'npm',
            'maven', 'java' => 'Maven',
            'pypi', 'python' => 'PyPI',
            'nuget', '.net' => 'NuGet',
            'composer', 'php' => 'Packagist',
            'go', 'golang' => 'Go',
            'cargo', 'rust' => 'crates.io',
            'gem', 'ruby' => 'RubyGems',
            default => $this->ecosystem,
        };
    }

    /**
     * Check if this component should be included in vulnerability analysis
     */
    public function isAnalyzable(): bool
    {
        // Skip certain types that are not relevant for vulnerability analysis
        $skipTypes = ['operating-system', 'device', 'firmware'];

        if (in_array(strtolower($this->type), $skipTypes, true)) {
            return false;
        }

        // Must have name and version
        if ($this->name === '' || $this->version === '') {
            return false;
        }

        // Skip version ranges or dynamic versions
        if (str_contains($this->version, '*') ||
            str_contains($this->version, '>') ||
            str_contains($this->version, '<') ||
            str_contains($this->version, '~') ||
            str_contains($this->version, '^')) {
            return false;
        }

        return true;
    }

    /**
     * Convert to array format for easier processing
     */
    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'version' => $this->version,
            'type' => $this->type,
            'ecosystem' => $this->ecosystem,
            'purl' => $this->purl,
            'namespace' => $this->namespace,
            'scope' => $this->scope,
            'group' => $this->group,
            'description' => $this->description,
            'licenses' => $this->licenses,
            'hashes' => $this->hashes,
            'externalReferences' => $this->externalReferences,
        ];
    }
}
