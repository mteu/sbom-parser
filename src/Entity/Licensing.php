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
 * Licensing based on CycloneDX 1.5 specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 * @codeCoverageIgnore
 */
final readonly class Licensing
{
    public function __construct(
        /** @var string[]|null */
        public ?array $altIds = null,
        public ?LicensingParty $licensor = null,
        public ?LicensingParty $licensee = null,
        public ?LicensingParty $purchaser = null,
        public ?string $purchaseOrder = null,
        /** @var LicenseType[]|null */
        public ?array $licenseTypes = null,
        public ?\DateTimeImmutable $lastRenewal = null,
        public ?\DateTimeImmutable $expiration = null,
    ) {
    }
}
