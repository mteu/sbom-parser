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
use CuyZ\Valinor\Mapper\Tree\Message\Messages;
use CuyZ\Valinor\Mapper\Tree\Message\NodeMessage;
use CuyZ\Valinor\Mapper\TreeMapper;
use CuyZ\Valinor\MapperBuilder;
use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Entity\Component;
use mteu\SbomParser\Entity\ComponentType;
use mteu\SbomParser\Entity\ExternalReferenceType;
use mteu\SbomParser\Entity\HashAlgorithm;
use mteu\SbomParser\Exception\SbomParseException;

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

    /**
     * Default maximum size in bytes of an SBOM file passed to
     * {@see parseFromFile()}.
     * Please override via the constructor when working with legitimately large SBOMs.
     */
    public const int DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024;

    private const int JSON_MAX_DEPTH = 64;

    private TreeMapper $mapper;
    private int $maxFileSize;

    public function __construct(int $maxFileSize = self::DEFAULT_MAX_FILE_SIZE)
    {
        if ($maxFileSize <= 0) {
            throw new \InvalidArgumentException(
                sprintf('maxFileSize must be a positive integer, got %d', $maxFileSize)
            );
        }

        $this->maxFileSize = $maxFileSize;
        $this->mapper = (new MapperBuilder())
            ->supportDateFormats('Y-m-d\TH:i:s.u\Z', 'Y-m-d\TH:i:s\Z', \DateTimeImmutable::ATOM)
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
        $data = $this->normalizeHyphenatedKeys($data);

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
     * @param mixed[] $data
     * @return array<string, mixed>
     */
    private function normalizeHyphenatedKeys(array $data): array
    {
        $keyMap = [
            'bom-ref' => 'bomRef',
        ];

        $result = [];
        foreach ($data as $key => $value) {
            $normalizedKey = $keyMap[(string) $key] ?? (string) $key;
            $result[$normalizedKey] = is_array($value)
                ? $this->normalizeHyphenatedKeys($value)
                : $value;
        }

        return $result;
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

        if ($fileSize > $this->maxFileSize) {
            throw SbomParseException::validationFailed(
                sprintf('File too large: %d bytes (maximum: %d bytes)', $fileSize, $this->maxFileSize)
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
