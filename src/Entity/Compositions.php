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
 * Compositions entity for BOM completeness tracking.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 * @codeCoverageIgnore
 */
final readonly class Compositions
{
    public function __construct(
        public AggregateType $aggregate,
        /** @var string[]|null */
        public ?array $assemblies = null,
        /** @var string[]|null */
        public ?array $dependencies = null,
        /** @var array<string, string|int|bool|array<string, string>>|string|null Digital signature */
        public array|string|null $signature = null,
    ) {
    }

}
