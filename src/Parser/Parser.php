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

namespace mteu\SbomParser\Parser;

use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Exception\SbomParseException;

/**
 * Modern SBOM Parser Interface.
 *
 * Type-safe interface for parsing CycloneDX SBOM files
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
interface Parser
{
    /**
     * Parse SBOM from file path
     *
     * @param string $filePath Absolute path to CycloneDX JSON file
     * @return Bom Fully parsed and validated SBOM object
     * @throws SbomParseException When file is invalid, unreadable, or contains invalid SBOM data
     */
    public function parseFromFile(string $filePath): Bom;

    /**
     * Parse SBOM from JSON string
     *
     * @param string $json Valid CycloneDX JSON content
     * @return Bom Fully parsed and validated SBOM object
     * @throws SbomParseException When JSON is malformed or contains invalid SBOM data
     */
    public function parseFromJson(string $json): Bom;

    /**
     * Parse SBOM from decoded array structure
     *
     * @param array<string, mixed> $data Pre-decoded CycloneDX data structure
     * @return Bom Fully parsed and validated SBOM object
     * @throws SbomParseException When data structure is invalid
     */
    public function parseFromArray(array $data): Bom;

    /**
     * Get supported file formats
     *
     * @return list<string> Currently supported formats
     */
    public function getSupportedFormats(): array;

    /**
     * Validate JSON content without full parsing
     *
     * @param string $json JSON content to validate
     * @return bool True if valid CycloneDX SBOM
     */
    public function isValidSbomJson(string $json): bool;

    /**
     * Validate file content without full parsing
     *
     * @param string $filePath Path to file to validate
     * @return bool True if file contains valid CycloneDX SBOM
     */
    public function isValidSbomFile(string $filePath): bool;

    /**
     * Validate array structure without full parsing
     *
     * @param array<string, mixed> $data Array structure to validate
     * @return bool True if valid CycloneDX SBOM structure
     */
    public function isValidSbomArray(array $data): bool;
}
