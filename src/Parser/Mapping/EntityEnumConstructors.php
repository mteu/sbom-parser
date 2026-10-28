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

namespace mteu\SbomParser\Parser\Mapping;

use CuyZ\Valinor\Mapper\Tree\Message\MessageBuilder;
use mteu\SbomParser\Entity\AggregateType;
use mteu\SbomParser\Entity\CertificationLevel;
use mteu\SbomParser\Entity\ComponentType;
use mteu\SbomParser\Entity\CryptoAssetType;
use mteu\SbomParser\Entity\CryptoFunction;
use mteu\SbomParser\Entity\CryptoMode;
use mteu\SbomParser\Entity\CryptoPadding;
use mteu\SbomParser\Entity\CryptographicPrimitive;
use mteu\SbomParser\Entity\DataFlow;
use mteu\SbomParser\Entity\DependencyType;
use mteu\SbomParser\Entity\ExecutionEnvironment;
use mteu\SbomParser\Entity\ExternalReferenceType;
use mteu\SbomParser\Entity\HashAlgorithm;
use mteu\SbomParser\Entity\ImplementationPlatform;
use mteu\SbomParser\Entity\LicenseAcknowledgement;
use mteu\SbomParser\Entity\LicenseType;
use mteu\SbomParser\Entity\LifecyclePhase;
use mteu\SbomParser\Entity\PatchType;
use mteu\SbomParser\Entity\PatentAssertionType;
use mteu\SbomParser\Entity\ReleaseType;
use mteu\SbomParser\Entity\Vulnerability\AffectedStatus;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisJustification;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisResponse;
use mteu\SbomParser\Entity\Vulnerability\ImpactAnalysisState;
use mteu\SbomParser\Entity\Vulnerability\Severity;

/**
 * Valinor picks a constructor by its declared return type, so each enum
 * needs a closure of its own. Every backed enum in {@see \mteu\SbomParser\Entity}
 * must be listed here.
 *
 * @internal
 *
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
final readonly class EntityEnumConstructors
{
    /**
     * @return list<pure-callable(string): \BackedEnum>
     */
    public function list(): array
    {
        return [
            static fn (string $value): AggregateType => AggregateType::tryFrom($value) ?? self::rejectUnknownValue(AggregateType::cases()),
            static fn (string $value): CertificationLevel => CertificationLevel::tryFrom($value) ?? self::rejectUnknownValue(CertificationLevel::cases()),
            static fn (string $value): ComponentType => ComponentType::tryFrom($value) ?? self::rejectUnknownValue(ComponentType::cases()),
            static fn (string $value): CryptoAssetType => CryptoAssetType::tryFrom($value) ?? self::rejectUnknownValue(CryptoAssetType::cases()),
            static fn (string $value): CryptoFunction => CryptoFunction::tryFrom($value) ?? self::rejectUnknownValue(CryptoFunction::cases()),
            static fn (string $value): CryptoMode => CryptoMode::tryFrom($value) ?? self::rejectUnknownValue(CryptoMode::cases()),
            static fn (string $value): CryptoPadding => CryptoPadding::tryFrom($value) ?? self::rejectUnknownValue(CryptoPadding::cases()),
            static fn (string $value): CryptographicPrimitive => CryptographicPrimitive::tryFrom($value) ?? self::rejectUnknownValue(CryptographicPrimitive::cases()),
            static fn (string $value): DataFlow => DataFlow::tryFrom($value) ?? self::rejectUnknownValue(DataFlow::cases()),
            static fn (string $value): DependencyType => DependencyType::tryFrom($value) ?? self::rejectUnknownValue(DependencyType::cases()),
            static fn (string $value): ExecutionEnvironment => ExecutionEnvironment::tryFrom($value) ?? self::rejectUnknownValue(ExecutionEnvironment::cases()),
            static fn (string $value): ExternalReferenceType => ExternalReferenceType::tryFrom($value) ?? self::rejectUnknownValue(ExternalReferenceType::cases()),
            static fn (string $value): HashAlgorithm => HashAlgorithm::tryFrom($value) ?? self::rejectUnknownValue(HashAlgorithm::cases()),
            static fn (string $value): ImplementationPlatform => ImplementationPlatform::tryFrom($value) ?? self::rejectUnknownValue(ImplementationPlatform::cases()),
            static fn (string $value): LicenseAcknowledgement => LicenseAcknowledgement::tryFrom($value) ?? self::rejectUnknownValue(LicenseAcknowledgement::cases()),
            static fn (string $value): LicenseType => LicenseType::tryFrom($value) ?? self::rejectUnknownValue(LicenseType::cases()),
            static fn (string $value): LifecyclePhase => LifecyclePhase::tryFrom($value) ?? self::rejectUnknownValue(LifecyclePhase::cases()),
            static fn (string $value): PatchType => PatchType::tryFrom($value) ?? self::rejectUnknownValue(PatchType::cases()),
            static fn (string $value): PatentAssertionType => PatentAssertionType::tryFrom($value) ?? self::rejectUnknownValue(PatentAssertionType::cases()),
            static fn (string $value): ReleaseType => ReleaseType::tryFrom($value) ?? self::rejectUnknownValue(ReleaseType::cases()),
            static fn (string $value): AffectedStatus => AffectedStatus::tryFrom($value) ?? self::rejectUnknownValue(AffectedStatus::cases()),
            static fn (string $value): ImpactAnalysisJustification => ImpactAnalysisJustification::tryFrom($value) ?? self::rejectUnknownValue(ImpactAnalysisJustification::cases()),
            static fn (string $value): ImpactAnalysisResponse => ImpactAnalysisResponse::tryFrom($value) ?? self::rejectUnknownValue(ImpactAnalysisResponse::cases()),
            static fn (string $value): ImpactAnalysisState => ImpactAnalysisState::tryFrom($value) ?? self::rejectUnknownValue(ImpactAnalysisState::cases()),
            static fn (string $value): Severity => Severity::tryFrom($value) ?? self::rejectUnknownValue(Severity::cases()),
        ];
    }

    /**
     * The error repeats the message Valinor gives for an unknown enum value,
     * so callers see the allowed values as before.
     *
     * It always throws. It is typed to return a case rather than `never`,
     * because PHPStan counts a call to a `never` function as a throw inside
     * the constructor closures, which the checked-exception rule forbids.
     *
     * @template T of \BackedEnum
     * @param list<T> $cases
     * @return T
     *
     * @pure
     */
    private static function rejectUnknownValue(array $cases): \BackedEnum
    {
        $allowedValues = [];
        foreach ($cases as $case) {
            $allowedValues[] = "'" . $case->value . "'";
        }

        throw MessageBuilder::newError('Value {source_value} does not match any of {allowed_values}.')
            ->withCode('invalid_enum_value')
            ->withParameter('allowed_values', implode(', ', $allowedValues))
            ->build();
    }
}
