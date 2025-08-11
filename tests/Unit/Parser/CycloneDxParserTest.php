<?php

declare(strict_types=1);

namespace mteu\SbomParser\Tests\Unit\Parser;

use mteu\SbomParser\Entity\Bom;
use mteu\SbomParser\Parser\CycloneDxParser;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

final class CycloneDxParserTest extends TestCase
{
    private CycloneDxParser $parser;

    protected function setUp(): void
    {
        parent::setUp();
        $this->parser = new CycloneDxParser();
    }

    #[Test]
    public function parserSucceedsInParsingAPerfectlyValidSbomJson(): void
    {
        $sbom = $this->parser->parseFromFile(dirname(__DIR__, ) . '/Fixtures/cdx.sbom.json');
        self::assertInstanceOf(Bom::class, $sbom);
    }
}
