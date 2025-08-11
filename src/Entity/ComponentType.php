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
 * ComponentType enum based on CycloneDX 1.4+ specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
enum ComponentType: string
{
    case APPLICATION = 'application';
    case CONTAINER = 'container';
    case DATA = 'data';
    case DEVICE = 'device';
    case DEVICE_DRIVER = 'device-driver';
    case FIRMWARE = 'firmware';
    case FILE = 'file';
    case FRAMEWORK = 'framework';
    case LIBRARY = 'library';
    case MACHINE_LEARNING_MODEL = 'machine-learning-model';
    case OPERATING_SYSTEM = 'operating-system';
    case PLATFORM = 'platform';
}
