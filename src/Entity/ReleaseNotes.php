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
 * Release notes entity for detailed change tracking.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 * @codeCoverageIgnore
 */
final readonly class ReleaseNotes
{
    public function __construct(
        public ReleaseType $type,
        public ?string $title = null,
        public ?string $featuredImage = null,
        public ?string $socialImage = null,
        public ?string $description = null,
        public ?\DateTimeImmutable $timestamp = null,
        /** @var string[]|null */
        public ?array $aliases = null,
        /** @var string[]|null */
        public ?array $tags = null,
        /** @var Issue[]|null */
        public ?array $resolves = null,
        /** @var Note[]|null */
        public ?array $notes = null,
        /** @var Property[]|null */
        public ?array $properties = null,
    ) {
    }

    /**
     * @return string[]
     */
    public function getAliases(): array
    {
        return $this->aliases ?? [];
    }

    /**
     * @return string[]
     */
    public function getTags(): array
    {
        return $this->tags ?? [];
    }

    /**
     * @return Issue[]
     */
    public function getResolves(): array
    {
        return $this->resolves ?? [];
    }

    /**
     * @return Note[]
     */
    public function getNotes(): array
    {
        return $this->notes ?? [];
    }
}
