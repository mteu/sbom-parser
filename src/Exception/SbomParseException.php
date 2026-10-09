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

namespace mteu\SbomParser\Exception;

final class SbomParseException extends \Exception
{
    public const int CODE_INVALID_JSON = 1778272290;
    public const int CODE_VALIDATION_FAILED = 1778272291;
    public const int CODE_UNSUPPORTED_FORMAT = 1778272292;
    public const int CODE_UNSUPPORTED_VERSION = 1778272293;

    /**
     * @param list<ParseErrorDetail> $details one entry per value that could not be mapped; empty
     *     when parsing failed before mapping. Unlike the message, this is meant to be read by code.
     */
    public function __construct(
        string $message = '',
        int $code = 0,
        ?\Throwable $previous = null,
        public readonly array $details = [],
    ) {
        parent::__construct($message, $code, $previous);
    }

    public static function invalidJson(string $message, ?\Throwable $previous = null): self
    {
        return new self(sprintf('Invalid JSON: %s', $message), self::CODE_INVALID_JSON, $previous);
    }

    public static function validationFailed(string $message, ?\Throwable $previous = null): self
    {
        return new self(sprintf('SBOM validation failed: %s', $message), self::CODE_VALIDATION_FAILED, $previous);
    }

    /**
     * @param list<ParseErrorDetail> $details
     */
    public static function mappingFailed(array $details, ?\Throwable $previous = null): self
    {
        $lines = ['Valinor mapping failed with the following errors:', ''];

        foreach ($details as $index => $detail) {
            $lines[] = sprintf('%d. Error at path: %s', $index + 1, $detail->path === '' ? 'root' : $detail->path);
            $lines[] = $detail->message;
            $lines[] = '';
        }

        $lines[] = sprintf('Total errors: %d', count($details));

        return new self(
            sprintf('SBOM validation failed: %s', implode(PHP_EOL, $lines)),
            self::CODE_VALIDATION_FAILED,
            $previous,
            $details,
        );
    }

    public static function unsupportedFormat(string $format): self
    {
        return new self(sprintf('Unsupported SBOM format: %s', $format), self::CODE_UNSUPPORTED_FORMAT);
    }

    public static function unsupportedVersion(string $version): self
    {
        return new self(sprintf('Unsupported SBOM version: %s', $version), self::CODE_UNSUPPORTED_VERSION);
    }
}
