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

namespace mteu\SbomParser\Index;

use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Entity\Component;

/**
 * BomComponentIndex.
 *
 * Stores per-instance traversal results in WeakMaps so they are released
 * automatically when the owning Bom is garbage-collected.
 *
 * @internal
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final class BomComponentIndex
{
    /** @var \WeakMap<Bom, list<Component>>|null */
    private static ?\WeakMap $flatComponents = null;

    /** @var \WeakMap<Bom, array<string, Component>>|null */
    private static ?\WeakMap $purlIndex = null;

    /**
     * @return list<Component>
     */
    public static function flatten(Bom $bom): array
    {
        $cache = self::$flatComponents ??= new \WeakMap();

        if ($cache->offsetExists($bom)) {
            return $cache[$bom];
        }

        $flat = iterator_to_array(self::walk($bom->components ?? []), false);
        $cache[$bom] = $flat;

        return $flat;
    }

    /**
     * @return array<string, Component>
     */
    public static function byPurl(Bom $bom): array
    {
        $cache = self::$purlIndex ??= new \WeakMap();

        if ($cache->offsetExists($bom)) {
            return $cache[$bom];
        }

        $index = [];
        foreach (self::flatten($bom) as $component) {
            if ($component->purl !== null && !array_key_exists($component->purl, $index)) {
                $index[$component->purl] = $component;
            }
        }

        $cache[$bom] = $index;

        return $index;
    }

    /**
     * Depth-first pre-order walk; the result is materialised lazily by
     * the caller via iterator_to_array, avoiding intermediate array copies.
     *
     * @param iterable<Component> $components
     * @return \Generator<int, Component>
     */
    private static function walk(iterable $components): \Generator
    {
        foreach ($components as $component) {
            yield $component;
            yield from self::walk($component->components ?? []);
        }
    }
}
