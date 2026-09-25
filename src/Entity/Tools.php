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
 * Tools based on CycloneDX 1.5 specification.
 *
 * The specification models metadata.tools as a choice: either this
 * object, listing the components and services that produced the BOM, or
 * the pre-1.5 array of tool objects, which {@see self::$legacyTools}
 * carries. The parser normalises the array form into that property, so
 * both shapes are reachable without losing data.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 * @codeCoverageIgnore
 */
final readonly class Tools
{
    public function __construct(
        /** @var Component[]|null */
        public ?array $components = null,
        /** @var Service[]|null */
        public ?array $services = null,
        /** @var Tool[]|null */
        public ?array $legacyTools = null,
    ) {
    }
}
