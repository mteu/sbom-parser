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

namespace mteu\SbomParser\Parser\Configuration;

/**
 * Immutable configuration for {@see \mteu\SbomParser\Parser\CycloneDxParser}.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final readonly class CycloneDxParserOptions
{
    /**
     * Default maximum size in bytes of an SBOM file passed to
     * {@see \mteu\SbomParser\Parser\CycloneDxParser::parseFromFile()}.
     * Override via {@see withMaxFileSize()} when working with
     * legitimately large SBOMs.
     */
    public const int DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;

    /**
     * Default maximum total node count in the decoded SBOM tree. Caps
     * wide payloads that would otherwise pass the file-size limit but
     * still exhaust memory once decoded. Override via {@see withMaxNodes()}
     * when working with legitimately very large SBOMs.
     */
    public const int DEFAULT_MAX_NODES = 1_000_000;

    public function __construct(
        public int $maxFileSize = self::DEFAULT_MAX_FILE_SIZE,
        public int $maxNodes = self::DEFAULT_MAX_NODES,
    ) {
        if ($maxFileSize <= 0) {
            throw new \InvalidArgumentException(
                sprintf('maxFileSize must be a positive integer, got %d', $maxFileSize)
            );
        }

        if ($maxNodes <= 0) {
            throw new \InvalidArgumentException(
                sprintf('maxNodes must be a positive integer, got %d', $maxNodes)
            );
        }
    }

    public function withMaxFileSize(int $bytes): self
    {
        return new self(maxFileSize: $bytes, maxNodes: $this->maxNodes);
    }

    public function withMaxNodes(int $count): self
    {
        return new self(maxFileSize: $this->maxFileSize, maxNodes: $count);
    }
}
