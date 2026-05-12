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

use CuyZ\Valinor\Mapper\MappingError;
use CuyZ\Valinor\Mapper\TreeMapper;
use CuyZ\Valinor\MapperBuilder;
use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Exception\SbomParseException;
use mteu\SbomParser\Parser\Configuration\CycloneDxParserOptions;

/**
 * Type-Safe SBOM Parser.
 *
 * Parses CycloneDX 1.4+ SBOM files using Valinor for comprehensive type validation
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final readonly class CycloneDxParser implements Parser
{
    public const array SUPPORTED_VERSIONS = ['1.4', '1.5', '1.6', '1.7'];

    private const int JSON_MAX_DEPTH = 64;

    private TreeMapper $mapper;

    public function __construct(
        private CycloneDxParserOptions $options = new CycloneDxParserOptions(),
    ) {
        $this->mapper = (new MapperBuilder())
            ->supportDateFormats('Y-m-d\TH:i:s.u\Z', 'Y-m-d\TH:i:s\Z', \DateTimeImmutable::ATOM)
            ->registerKeyConverter(
                static fn (string $key): string => $key === 'bom-ref' ? 'bomRef' : $key,
            )
            ->allowSuperfluousKeys()
            ->mapper();
    }

    public function parseFromFile(string $filePath): Bom
    {
        $this->validateSbomPath($filePath);

        $content = $this->readFile($filePath);
        $data = $this->decodeJson($content);
        unset($content);

        return $this->parseFromArray($data);
    }

    public function parseFromJson(string $json): Bom
    {
        return $this->parseFromArray($this->decodeJson($json));
    }

    /**
     * @param array<string, mixed> $data
     */
    public function parseFromArray(array $data): Bom
    {
        $this->validateDataStructure($data);
        $this->enforceNodeBudget($data);

        try {
            return $this->mapper->map(Bom::class, $data);
        } catch (MappingError $e) {
            throw SbomParseException::validationFailed(
                $this->formatMappingError($e),
                $e,
            );
        }
    }

    /**
     * Walk the decoded structure once and abort if the total number of
     * values exceeds {@see CycloneDxParserOptions::$maxNodes}. Protects
     * against wide JSON payloads that fit under the file-size cap but
     * would otherwise blow up memory during Valinor mapping.
     *
     * @param array<int|string, mixed> $data
     * @throws SbomParseException
     */
    private function enforceNodeBudget(array $data): void
    {
        $count = 0;
        $stack = [$data];

        while ($stack !== []) {
            $current = array_pop($stack);
            foreach ($current as $value) {
                $count++;
                if ($count > $this->options->maxNodes) {
                    throw SbomParseException::validationFailed(
                        sprintf(
                            'Decoded SBOM exceeds maximum node count of %d',
                            $this->options->maxNodes,
                        )
                    );
                }
                if (is_array($value)) {
                    $stack[] = $value;
                }
            }
        }
    }

    /** @codeCoverageIgnore */
    public function getSupportedFormats(): array
    {
        return ['json'];
    }

    public function isValidSbomFile(string $filePath): bool
    {
        try {
            $this->validateSbomPath($filePath);
            $content = $this->readFile($filePath);

            return $this->isValidSbomJson($content);
        } catch (SbomParseException) {
            return false;
        }
    }

    /**
     * @throws SbomParseException
     */
    private function readFile(string $filePath): string
    {
        if (!file_exists($filePath)) {
            throw SbomParseException::validationFailed(sprintf('File not found: %s', $filePath));
        }

        if (!is_readable($filePath)) {
            throw SbomParseException::validationFailed(sprintf('File not readable: %s', $filePath));
        }

        $fileSize = filesize($filePath);
        if ($fileSize === false) {
            throw SbomParseException::validationFailed(sprintf('Could not determine file size: %s', $filePath));
        }

        if ($fileSize > $this->options->maxFileSize) {
            throw SbomParseException::validationFailed(
                sprintf('File too large: %d bytes (maximum: %d bytes)', $fileSize, $this->options->maxFileSize)
            );
        }

        $content = file_get_contents($filePath);
        if ($content === false) {
            throw SbomParseException::validationFailed(sprintf('Could not read file: %s', $filePath));
        }

        return $content;
    }

    /**
     * @return array<string, mixed>
     * @throws SbomParseException
     */
    private function decodeJson(string $json): array
    {
        try {
            $data = json_decode($json, true, self::JSON_MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw SbomParseException::invalidJson($e->getMessage(), $e);
        }

        if (!is_array($data)) {
            throw SbomParseException::validationFailed('Decoded JSON is not an array');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    public function isValidSbomJson(string $json): bool
    {
        try {
            $data = json_decode($json, true, self::JSON_MAX_DEPTH, JSON_THROW_ON_ERROR);

            if (!is_array($data)) {
                return false;
            }

            /** @var array<string, mixed> $data */
            return $this->isValidSbomArray($data);
        } catch (\JsonException) {
            return false;
        }
    }

    /**
     * @param array<string, mixed> $data
     */
    public function isValidSbomArray(array $data): bool
    {
        try {
            $this->validateDataStructure($data);
            return true;
        } catch (SbomParseException) {
            return false;
        }
    }

    /**
     * Validate that SBOM path is secure and accessible
     *
     * @throws SbomParseException
     */
    private function validateSbomPath(string $sbomFilePath): void
    {
        if (!$this->isAbsolutePath($sbomFilePath)) {
            throw SbomParseException::validationFailed('SBOM file path must be absolute');
        }

        if ($this->containsTraversalSegment($sbomFilePath)) {
            throw SbomParseException::validationFailed('Directory traversal not allowed in SBOM path');
        }

        $directory = dirname($sbomFilePath);
        $realDirectory = realpath($directory);
        if ($realDirectory === false) {
            throw SbomParseException::validationFailed('SBOM directory does not exist or is not accessible');
        }

        $fileName = basename($sbomFilePath);
        $expectedRealPath = $realDirectory . DIRECTORY_SEPARATOR . $fileName;

        if (file_exists($sbomFilePath)) {
            $realFilePath = realpath($sbomFilePath);
            if ($realFilePath === false || $realFilePath !== $expectedRealPath) {
                throw SbomParseException::validationFailed('Directory traversal not allowed in SBOM path');
            }
        }

        if ($this->options->allowedBaseDirectories !== []
            && !$this->isWithinAllowedBaseDirectory($expectedRealPath)
        ) {
            throw SbomParseException::validationFailed(
                'SBOM file path is outside the allowed base directories'
            );
        }

        $allowedExtensions = ['.json'];
        $dotPosition = strrpos($sbomFilePath, '.');
        if ($dotPosition === false) {
            throw SbomParseException::validationFailed('SBOM file must have .json extension');
        }
        $extension = strtolower(substr($sbomFilePath, $dotPosition));
        if (!in_array($extension, $allowedExtensions, true)) {
            throw SbomParseException::validationFailed('SBOM file must have .json extension');
        }
    }

    /**
     * Detects absolute paths in a cross-platform way: Unix (`/foo`),
     * Windows drive (`C:\foo`, `C:/foo`), and UNC (`\\server\share`).
     */
    private function isAbsolutePath(string $path): bool
    {
        if ($path === '') {
            return false;
        }

        if ($path[0] === '/') {
            return true;
        }

        if (str_starts_with($path, '\\\\')) {
            return true;
        }

        return preg_match('#^[A-Za-z]:[\\\\/]#', $path) === 1;
    }

    /**
     * Verifies that the resolved SBOM path lives under one of the
     * configured allowed base directories. Each prefix is normalised
     * via realpath() so symlinked or relative entries resolve to a
     * canonical absolute form before the comparison.
     */
    private function isWithinAllowedBaseDirectory(string $resolvedFilePath): bool
    {
        foreach ($this->options->allowedBaseDirectories as $allowed) {
            $realAllowed = realpath($allowed);
            if ($realAllowed === false) {
                continue;
            }

            $needle = rtrim($realAllowed, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (str_starts_with($resolvedFilePath, $needle)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Detects traversal at the path-segment level so legitimate names
     * like `foo..bar.json` or `data..backup/` are not falsely rejected.
     */
    private function containsTraversalSegment(string $path): bool
    {
        // Normalise URL-encoded dots so the segment check sees them too.
        $normalized = preg_replace('/%2e/i', '.', $path) ?? $path;

        $segments = preg_split('#[\\\\/]+#', $normalized);
        if ($segments === false) {
            return false;
        }

        foreach ($segments as $segment) {
            if ($segment === '..') {
                return true;
            }
        }

        return false;
    }

    /**
     * @param array<string, mixed> $data
     * @throws SbomParseException
     */
    private function validateDataStructure(array $data): void
    {
        if (!array_key_exists('bomFormat', $data)) {
            throw SbomParseException::validationFailed('Missing required field: bomFormat');
        }

        $bomFormat = $data['bomFormat'];
        if (!is_string($bomFormat)) {
            throw SbomParseException::validationFailed('Field bomFormat must be a string');
        }

        if ($bomFormat !== 'CycloneDX') {
            throw SbomParseException::unsupportedFormat($bomFormat);
        }

        if (!array_key_exists('specVersion', $data)) {
            throw SbomParseException::validationFailed('Missing required field: specVersion');
        }

        $specVersion = $data['specVersion'];
        if (!is_string($specVersion)) {
            throw SbomParseException::validationFailed('Field specVersion must be a string');
        }

        $supported = array_filter(self::SUPPORTED_VERSIONS, fn (string $version) => str_starts_with($specVersion, $version)) !== [];

        if (!$supported) {
            throw SbomParseException::unsupportedVersion($specVersion);
        }
    }

    private function formatMappingError(MappingError $error): string
    {
        $messages = [];
        $messages[] = 'Valinor mapping failed with the following errors:';
        $messages[] = '';

        $errorNumber = 1;
        foreach ($error->messages() as $nodeMessage) {

            $path = $nodeMessage->path();
            $pathString = $path === '' ? 'root' : $path;

            $messages[] = sprintf(
                '%d. Error at path: %s',
                $errorNumber++,
                $pathString
            );

            $messages[] = $nodeMessage . ' ';

            // Show the actual value if available
            if ($nodeMessage->sourceValue() !== '') {
                $value = $nodeMessage->sourceValue();
                $valueType = get_debug_type($value);
                $valuePreview = $this->formatValuePreview($value);
                $messages[] = sprintf('   Value: %s (%s)', $valuePreview, $valueType);
            }

            $messages[] = '';
        }

        $messages[] = sprintf(
            'Total errors: %d',
            $errorNumber - 1,
        );

        return implode(PHP_EOL, $messages);
    }

    private function formatValuePreview(mixed $value): string
    {
        if ($value === null) {
            return 'null';
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_string($value)) {
            return strlen($value) > 100 ? substr($value, 0, 100) . '...' : $value;
        }

        if (is_numeric($value)) {
            return (string)$value;
        }

        if (is_array($value)) {
            $count = count($value);
            if ($count === 0) {
                return '[]';
            }

            $keys = array_keys($value);
            $keyPreview = implode(', ', array_slice($keys, 0, 3));
            if ($count > 3) {
                $keyPreview .= ', ...';
            }

            return sprintf('array[%d] with keys: %s', $count, $keyPreview);
        }

        if (is_object($value)) {
            return sprintf('object(%s)', $value::class);
        }

        return 'unknown';
    }
}
