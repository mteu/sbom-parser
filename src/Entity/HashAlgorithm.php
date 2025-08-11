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
 * HashAlgorithm enum based on CycloneDX 1.4+ specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
enum HashAlgorithm: string
{
    case MD5 = 'MD5';
    case SHA1 = 'SHA-1';
    case SHA256 = 'SHA-256';
    case SHA384 = 'SHA-384';
    case SHA512 = 'SHA-512';
    case SHA3_256 = 'SHA3-256';
    case SHA3_384 = 'SHA3-384';
    case SHA3_512 = 'SHA3-512';
    case BLAKE2B_256 = 'BLAKE2b-256';
    case BLAKE2B_384 = 'BLAKE2b-384';
    case BLAKE2B_512 = 'BLAKE2b-512';
    case BLAKE3 = 'BLAKE3';
}
