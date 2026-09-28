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
 *   composer schemas:update        download the pinned files and overwrite the local copies
 *   composer schemas:check         exit 1 if a local copy differs from the pinned upstream file
 *   composer schemas:check-latest  exit 1 if the newest upstream release changes a schema
 *                                  or adds a spec version (run on a schedule in CI)
 *
 * Bump SPECIFICATION_TAG and SPECIFICATION_COMMIT together. The commit is
 * what gets downloaded, because a tag can be moved.
 */

const SPECIFICATION_REPOSITORY = 'CycloneDX/specification';
const SPECIFICATION_GIT_URL = 'https://github.com/CycloneDX/specification.git';
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

function buildSchemaUrl(string $file, string $commit): string
{
    return sprintf(
        'https://raw.githubusercontent.com/%s/%s/schema/%s',
        SPECIFICATION_REPOSITORY,
        $commit,
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

function downloadSchema(string $file, string $commit = SPECIFICATION_COMMIT): string
{
    $url = buildSchemaUrl($file, $commit);
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

/**
 * Tags are read with `git ls-remote` rather than the GitHub API, which is
 * rate-limited for unauthenticated requests.
 *
 * @return array{tag: string, commit: string}
 */
function resolveLatestRelease(): array
{
    $output = [];
    $exitCode = 0;
    exec(sprintf('git ls-remote --tags %s', escapeshellarg(SPECIFICATION_GIT_URL)), $output, $exitCode);

    if ($exitCode !== 0) {
        throw new RuntimeException(sprintf('git ls-remote failed for %s', SPECIFICATION_GIT_URL));
    }

    /** @var array<string, string> $commitsByTag */
    $commitsByTag = [];
    foreach ($output as $line) {
        if (preg_match('#^([0-9a-f]{40})\trefs/tags/(\d+(?:\.\d+)*)(\^\{\})?$#', $line, $match) !== 1) {
            continue;
        }

        $isPeeled = ($match[3] ?? '') !== '';
        // An annotated tag lists the tag object first and the commit it points to as `^{}`.
        if ($isPeeled || !array_key_exists($match[2], $commitsByTag)) {
            $commitsByTag[$match[2]] = $match[1];
        }
    }

    if ($commitsByTag === []) {
        throw new RuntimeException(sprintf('No release tags found in %s', SPECIFICATION_GIT_URL));
    }

    $tags = array_keys($commitsByTag);
    usort($tags, static fn (string $a, string $b): int => version_compare($b, $a));

    return ['tag' => $tags[0], 'commit' => $commitsByTag[$tags[0]]];
}

function schemaExists(string $file, string $commit): bool
{
    $headers = get_headers(buildSchemaUrl($file, $commit), false, createHttpContext());

    return is_array($headers) && preg_match('#^HTTP/\S+ 200#', $headers[0] ?? '') === 1;
}

/**
 * Candidate file for the spec version a release tag introduces, e.g. `1.8.1` → `bom-1.8.schema.json`.
 */
function buildSpecSchemaFileName(string $tag): string
{
    $parts = explode('.', $tag);

    return sprintf('bom-%s.%s.schema.json', $parts[0], $parts[1] ?? '0');
}

function writeStepSummary(string $markdown): void
{
    $summaryFile = getenv('GITHUB_STEP_SUMMARY');
    if (is_string($summaryFile) && $summaryFile !== '') {
        file_put_contents($summaryFile, $markdown . "\n", FILE_APPEND);
    }
}

function checkLatestRelease(): int
{
    $latest = resolveLatestRelease();

    if ($latest['commit'] === SPECIFICATION_COMMIT) {
        $message = sprintf('Pinned schemas are the latest %s release (%s).', SPECIFICATION_REPOSITORY, SPECIFICATION_TAG);
        fwrite(STDOUT, $message . "\n");
        writeStepSummary($message);

        return 0;
    }

    $changed = [];
    foreach (SCHEMA_FILES as $file) {
        $path = SCHEMA_DIRECTORY . '/' . $file;
        $local = is_file($path) ? file_get_contents($path) : false;
        if ($local !== downloadSchema($file, $latest['commit'])) {
            $changed[] = $file;
        }
    }

    $newSpecFile = buildSpecSchemaFileName($latest['tag']);
    $hasNewSpecVersion = !in_array($newSpecFile, SCHEMA_FILES, true) && schemaExists($newSpecFile, $latest['commit']);

    $lines = [
        sprintf('## %s %s is available (pinned: %s)', SPECIFICATION_REPOSITORY, $latest['tag'], SPECIFICATION_TAG),
        '',
    ];

    if ($hasNewSpecVersion) {
        $lines[] = sprintf('- **New spec version:** `%s`. Supporting it needs parser and entity work, not just a schema refresh.', $newSpecFile);
    }

    foreach ($changed as $file) {
        $lines[] = sprintf('- Changed upstream: `%s`', $file);
    }

    if ($changed === [] && !$hasNewSpecVersion) {
        $lines[] = '- All pinned schema files are identical in the new release. Bumping the pin is optional.';
    }

    $lines[] = '';
    $lines[] = 'To update, set in `tests/Build/schemas.php`:';
    $lines[] = '';
    $lines[] = '```php';
    $lines[] = sprintf("const SPECIFICATION_TAG = '%s';", $latest['tag']);
    $lines[] = sprintf("const SPECIFICATION_COMMIT = '%s';", $latest['commit']);
    $lines[] = '```';
    $lines[] = '';
    $lines[] = 'then run `composer schemas:update` and `composer test`.';

    $report = implode("\n", $lines);
    writeStepSummary($report);

    $hasDrift = $changed !== [] || $hasNewSpecVersion;
    fwrite($hasDrift ? STDERR : STDOUT, $report . "\n");

    return $hasDrift ? 1 : 0;
}

$command = $argv[1] ?? '';

exit(match ($command) {
    'update' => updateSchemas(),
    'check' => checkSchemas(),
    'check-latest' => checkLatestRelease(),
    default => (static function (): int {
        fwrite(STDERR, "Usage: php tests/Build/schemas.php update|check|check-latest\n");

        return 2;
    })(),
});
