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
 * ExternalReferenceType enum based on CycloneDX 1.4+ specification.
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
enum ExternalReferenceType: string
{
    case ADVISORIES = 'advisories';
    case BOM = 'bom';
    case BUILD_META = 'build-meta';
    case BUILD_SYSTEM = 'build-system';
    case CHAT = 'chat';
    case DISTRIBUTION = 'distribution';
    case DISTRIBUTION_INTAKE = 'distribution-intake';
    case DOCUMENTATION = 'documentation';
    case DOWNLOAD = 'download';
    case EVIDENCE = 'evidence';
    case ISSUE_TRACKER = 'issue-tracker';
    case LICENSE = 'license';
    case LOG = 'log';
    case MAILING_LIST = 'mailing-list';
    case OTHER = 'other';
    case POAM = 'poam';
    case RELEASE_NOTES = 'release-notes';
    case RISK_ASSESSMENT = 'risk-assessment';
    case SOCIAL = 'social';
    case STATIC_ANALYSIS_REPORT = 'static-analysis-report';
    case SUPPORT = 'support';
    case VCS = 'vcs';
    case VULNERABILITY_ASSERTION = 'vulnerability-assertion';
    case WEBSITE = 'website';
}
