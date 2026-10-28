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

namespace mteu\SbomParser\Tests\Unit\Parser\Mapping;

use CuyZ\Valinor\Mapper\Tree\Message\ErrorMessage;
use CuyZ\Valinor\Mapper\Tree\Message\HasParameters;
use mteu\SbomParser\Entity\ExternalReferenceType;
use mteu\SbomParser\Parser\Mapping\EntityEnumConstructors;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * @author Martin Adler <mteu@mailbox.org>
 * @license GPL-3.0-or-later
 */
#[CoversClass(EntityEnumConstructors::class)]
final class EntityEnumConstructorsTest extends TestCase
{
    #[Test]
    public function listHasOneConstructorForEveryBackedEnumInTheEntityNamespace(): void
    {
        $constructedEnums = array_map(
            static fn (callable $constructor): string => self::returnedClass($constructor),
            (new EntityEnumConstructors())->list(),
        );
        sort($constructedEnums);

        self::assertSame(self::backedEntityEnums(), $constructedEnums);
    }

    /**
     * @return \Generator<string, array{pure-callable(string): \BackedEnum, \BackedEnum}>
     */
    public static function everyCaseProvider(): \Generator
    {
        foreach ((new EntityEnumConstructors())->list() as $constructor) {
            $enum = self::returnedClass($constructor);
            \assert(is_subclass_of($enum, \BackedEnum::class));

            foreach ($enum::cases() as $case) {
                yield $enum . '::' . $case->name => [$constructor, $case];
            }
        }
    }

    /**
     * @param pure-callable(string): \BackedEnum $constructor
     */
    #[Test]
    #[DataProvider('everyCaseProvider')]
    public function constructorReturnsTheCaseOfItsValue(callable $constructor, \BackedEnum $case): void
    {
        self::assertSame($case, $constructor((string) $case->value));
    }

    #[Test]
    public function constructorRejectsAnUnknownValueAndListsTheAllowedOnes(): void
    {
        $error = $this->catchRejectionOf('telepathy');

        self::assertSame('Value {source_value} does not match any of {allowed_values}.', $error->body());
        self::assertInstanceOf(HasParameters::class, $error);
        self::assertStringStartsWith("'advisories', 'bom', 'build-meta',", $error->parameters()['allowed_values']);
        self::assertStringEndsWith("'vulnerability-assertion', 'website'", $error->parameters()['allowed_values']);
    }

    #[Test]
    public function constructorDoesNotMatchAValueInAnotherCase(): void
    {
        self::assertSame('Value {source_value} does not match any of {allowed_values}.', $this->catchRejectionOf('VCS')->body());
    }

    private function catchRejectionOf(string $externalReferenceType): ErrorMessage
    {
        try {
            $this->constructorFor(ExternalReferenceType::class)($externalReferenceType);
        } catch (\Throwable $error) {
            self::assertInstanceOf(ErrorMessage::class, $error);

            return $error;
        }

        self::fail(sprintf('Expected "%s" to be rejected.', $externalReferenceType));
    }

    /**
     * @param class-string<\BackedEnum> $enum
     * @return pure-callable(string): \BackedEnum
     */
    private function constructorFor(string $enum): callable
    {
        foreach ((new EntityEnumConstructors())->list() as $constructor) {
            if (self::returnedClass($constructor) === $enum) {
                return $constructor;
            }
        }

        self::fail(sprintf('No constructor for %s.', $enum));
    }

    private static function returnedClass(callable $constructor): string
    {
        $returnType = (new \ReflectionFunction(\Closure::fromCallable($constructor)))->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);

        return $returnType->getName();
    }

    /**
     * @return list<string>
     */
    private static function backedEntityEnums(): array
    {
        $entityDirectory = (string) realpath(__DIR__ . '/../../../../src/Entity');
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($entityDirectory, \FilesystemIterator::SKIP_DOTS));
        $enums = [];

        foreach ($files as $file) {
            \assert($file instanceof \SplFileInfo);
            $relativeName = substr($file->getPathname(), strlen($entityDirectory) + 1, -strlen('.php'));
            $class = 'mteu\\SbomParser\\Entity\\' . str_replace('/', '\\', $relativeName);

            if (enum_exists($class) && is_subclass_of($class, \BackedEnum::class)) {
                $enums[] = $class;
            }
        }
        sort($enums);

        return $enums;
    }
}
