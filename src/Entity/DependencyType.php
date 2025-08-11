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

enum DependencyType: string
{
    case REQUIRE = 'require';
    case REQUIRE_DEV = 'require-dev';
    case ROOT = 'root';
    case NPM = 'npm';
    case NPM_DEV = 'npm-dev';

    public function getDisplayName(): string
    {
        return match ($this) {
            self::REQUIRE => 'Dependency',
            self::REQUIRE_DEV => 'Dev Dependency',
            self::ROOT => 'Root Package',
            self::NPM => 'NPM Dependency',
            self::NPM_DEV => 'NPM Dev Dependency',
        };
    }

    public function getBadgeClass(): string
    {
        return match ($this) {
            self::ROOT => 'badge-primary',
            self::REQUIRE => 'badge-secondary',
            self::REQUIRE_DEV => 'badge-info',
            self::NPM => 'badge-warning',
            self::NPM_DEV => 'badge-light',
        };
    }
}
