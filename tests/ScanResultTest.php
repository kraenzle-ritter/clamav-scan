<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Tests;

use KraenzleRitter\ClamavScan\ScanResult;
use PHPUnit\Framework\TestCase;

final class ScanResultTest extends TestCase
{
    public function test_clean(): void
    {
        $result = ScanResult::clean('/a.txt');

        $this->assertTrue($result->isClean());
        $this->assertFalse($result->isInfected());
        $this->assertFalse($result->isError());
    }

    public function test_infected_carries_the_signature(): void
    {
        $result = ScanResult::infected('/a.exe', 'Win.Trojan.Fake');

        $this->assertTrue($result->isInfected());
        $this->assertSame('Win.Trojan.Fake', $result->signature);
    }

    public function test_to_array(): void
    {
        $this->assertSame(
            ['path' => '/a.iso', 'status' => 'error', 'signature' => null, 'message' => 'INSTREAM size limit exceeded.'],
            ScanResult::error('/a.iso', 'INSTREAM size limit exceeded.')->toArray(),
        );
    }
}
