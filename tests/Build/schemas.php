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

/*
 * Keeps tests/Fixtures/schemas identical to the official CycloneDX schemas.
 *
 *   composer schemas:update   download the pinned files and overwrite the local copies
 *   composer schemas:check    exit 1 if a local copy differs from the pinned upstream file
 *
 * Bump SPECIFICATION_TAG and SPECIFICATION_COMMIT together. The commit is
 * what gets downloaded, because a tag can be moved.
 */

const SPECIFICATION_REPOSITORY = 'CycloneDX/specification';
const SPECIFICATION_TAG = '1.7.2';
const SPECIFICATION_COMMIT = '349314a9d7671d7d2ca5b711a725f49a73979da6';

const SCHEMA_FILES = [
    'bom-1.4.schema.json',
    'bom-1.5.schema.json',
    'bom-1.6.schema.json',
    'bom-1.7.schema.json',
    'jsf-0.82.schema.json',
    'spdx.schema.json',
];

const SCHEMA_DIRECTORY = __DIR__ . '/../Fixtures/schemas';

function buildSchemaUrl(string $file): string
{
    return sprintf(
        'https://raw.githubusercontent.com/%s/%s/schema/%s',
        SPECIFICATION_REPOSITORY,
        SPECIFICATION_COMMIT,
        $file,
    );
}

/**
 * @return resource
 */
function createHttpContext()
{
    $http = ['timeout' => 30, 'ignore_errors' => false];

    // PHP's stream wrapper ignores HTTPS_PROXY, so proxied environments need it passed explicitly.
    $proxy = getenv('HTTPS_PROXY');
    if ($proxy === false || $proxy === '') {
        $proxy = getenv('https_proxy');
    }

    if (is_string($proxy) && $proxy !== '') {
        $http['proxy'] = preg_replace('#^https?://#', 'tcp://', $proxy);
        $http['request_fulluri'] = true;
    }

    return stream_context_create(['http' => $http]);
}

function downloadSchema(string $file): string
{
    $url = buildSchemaUrl($file);
    $content = file_get_contents($url, false, createHttpContext());

    if ($content === false) {
        throw new RuntimeException(sprintf('Could not download %s', $url));
    }

    try {
        json_decode($content, flags: JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        throw new RuntimeException(sprintf('%s is not valid JSON: %s', $url, $exception->getMessage()), 0, $exception);
    }

    return $content;
}

function updateSchemas(): int
{
    foreach (SCHEMA_FILES as $file) {
        file_put_contents(SCHEMA_DIRECTORY . '/' . $file, downloadSchema($file));
        fwrite(STDOUT, sprintf("updated  %s\n", $file));
    }

    fwrite(STDOUT, sprintf("Schemas match %s %s (%s).\n", SPECIFICATION_REPOSITORY, SPECIFICATION_TAG, SPECIFICATION_COMMIT));

    return 0;
}

function checkSchemas(): int
{
    $drifted = 0;

    foreach (SCHEMA_FILES as $file) {
        $path = SCHEMA_DIRECTORY . '/' . $file;
        $local = is_file($path) ? file_get_contents($path) : false;
        $matches = $local === downloadSchema($file);
        $drifted += $matches ? 0 : 1;

        fwrite($matches ? STDOUT : STDERR, sprintf("%s %s\n", $matches ? 'ok      ' : 'DIFFERS ', $file));
    }

    if ($drifted > 0) {
        fwrite(STDERR, sprintf(
            "%d schema file(s) differ from %s %s. Run `composer schemas:update`.\n",
            $drifted,
            SPECIFICATION_REPOSITORY,
            SPECIFICATION_TAG,
        ));

        return 1;
    }

    fwrite(STDOUT, sprintf("All schemas match %s %s.\n", SPECIFICATION_REPOSITORY, SPECIFICATION_TAG));

    return 0;
}

$command = $argv[1] ?? '';

exit(match ($command) {
    'update' => updateSchemas(),
    'check' => checkSchemas(),
    default => (static function (): int {
        fwrite(STDERR, "Usage: php tests/Build/schemas.php update|check\n");

        return 2;
    })(),
});
