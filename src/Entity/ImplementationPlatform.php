<?php

declare(strict_types=1);

/*
 * This file is part of the package "mteu/sbom-parser".
 *
 * Copyright (C) 2026 Martin Adler <mteu@mailbox.org>
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
 * ImplementationPlatform enum based on CycloneDX 1.7 specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
enum ImplementationPlatform: string
{
    case GENERIC = 'generic';
    case X86_32 = 'x86_32';
    case X86_64 = 'x86_64';
    case ARMV7_A = 'armv7-a';
    case ARMV7_M = 'armv7-m';
    case ARMV8_A = 'armv8-a';
    case ARMV8_M = 'armv8-m';
    case ARMV9_A = 'armv9-a';
    case ARMV9_M = 'armv9-m';
    case S390X = 's390x';
    case PPC64 = 'ppc64';
    case PPC64LE = 'ppc64le';
    case OTHER = 'other';
    case UNKNOWN = 'unknown';
}
