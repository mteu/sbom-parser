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

namespace mteu\SbomParser\Entity;

/**
 * CertificationLevel enum based on CycloneDX 1.7 specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
enum CertificationLevel: string
{
    case NONE = 'none';
    case FIPS_140_1_L1 = 'fips140-1-l1';
    case FIPS_140_1_L2 = 'fips140-1-l2';
    case FIPS_140_1_L3 = 'fips140-1-l3';
    case FIPS_140_1_L4 = 'fips140-1-l4';
    case FIPS_140_2_L1 = 'fips140-2-l1';
    case FIPS_140_2_L2 = 'fips140-2-l2';
    case FIPS_140_2_L3 = 'fips140-2-l3';
    case FIPS_140_2_L4 = 'fips140-2-l4';
    case FIPS_140_3_L1 = 'fips140-3-l1';
    case FIPS_140_3_L2 = 'fips140-3-l2';
    case FIPS_140_3_L3 = 'fips140-3-l3';
    case FIPS_140_3_L4 = 'fips140-3-l4';
    case CC_EAL1 = 'cc-eal1';
    case CC_EAL1_PLUS = 'cc-eal1+';
    case CC_EAL2 = 'cc-eal2';
    case CC_EAL2_PLUS = 'cc-eal2+';
    case CC_EAL3 = 'cc-eal3';
    case CC_EAL3_PLUS = 'cc-eal3+';
    case CC_EAL4 = 'cc-eal4';
    case CC_EAL4_PLUS = 'cc-eal4+';
    case CC_EAL5 = 'cc-eal5';
    case CC_EAL5_PLUS = 'cc-eal5+';
    case CC_EAL6 = 'cc-eal6';
    case CC_EAL6_PLUS = 'cc-eal6+';
    case CC_EAL7 = 'cc-eal7';
    case CC_EAL7_PLUS = 'cc-eal7+';
    case OTHER = 'other';
    case UNKNOWN = 'unknown';
}
