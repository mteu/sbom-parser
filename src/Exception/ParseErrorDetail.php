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

namespace mteu\SbomParser\Exception;

/**
 * One value of an SBOM that could not be mapped, as listed by
 * {@see SbomParseException::$details}.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final readonly class ParseErrorDetail
{
    /**
     * @param string $path dotted path into the document with its own key names, such as
     *     `vulnerabilities.2.analysis.state` or `components.0.bom-ref`; empty for the document root
     * @param string $message may quote the offending value from the document: escape it before rendering
     */
    public function __construct(
        public string $path,
        public string $message,
    ) {
        if (trim($message) === '') {
            throw new \InvalidArgumentException('A parse error detail has to describe the error.');
        }
    }
}
