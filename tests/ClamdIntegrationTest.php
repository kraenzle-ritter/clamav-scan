<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Tests;

use KraenzleRitter\ClamavScan\ClamdScanner;
use KraenzleRitter\ClamavScan\Eicar;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\TestCase;

/**
 * Against a real clamd, at CLAMD_SOCKET (e.g. tcp://127.0.0.1:3310).
 * Skipped when it is not set or clamd does not answer.
 */
#[Group('integration')]
final class ClamdIntegrationTest extends TestCase
{
    use WritesEicar;

    private ClamdScanner $scanner;

    private string $dir;

    protected function setUp(): void
    {
        $socket = getenv('CLAMD_SOCKET');
        if ($socket === false || $socket === '') {
            $this->markTestSkipped('CLAMD_SOCKET not set.');
        }

        $this->scanner = new ClamdScanner($socket, 60.0);
        if (! $this->scanner->isAvailable()) {
            $this->markTestSkipped("clamd does not answer at {$socket}.");
        }

        $this->dir = sys_get_temp_dir().'/clamav-scan-int-'.bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        if (isset($this->dir)) {
            array_map('unlink', glob($this->dir.'/*') ?: []);
            rmdir($this->dir);
        }
    }

    public function test_version(): void
    {
        $this->assertStringStartsWith('ClamAV ', (string) $this->scanner->version());
    }

    public function test_eicar_is_found(): void
    {
        $result = $this->scanner->scanStream($this->eicarStream(), 'eicar.com');

        $this->assertTrue($result->isInfected());
        $this->assertSame(Eicar::SIGNATURE, $result->signature);
    }

    public function test_the_eicar_file_on_disk_is_found(): void
    {
        $this->assertTrue($this->scanner->scan($this->eicarFile($this->dir.'/eicar.com'))->isInfected());
    }

    public function test_a_stream_over_the_size_limit_is_an_error(): void
    {
        // clamd's default StreamMaxLength is 100 MB; the CI and ddev setups keep it.
        // clamd stops reading part-way; its answer must still arrive.
        $stream = fopen('php://temp', 'r+b');
        $block = str_repeat("\0", 1024 * 1024);
        for ($i = 0; $i < 120; $i++) {
            fwrite($stream, $block);
        }
        rewind($stream);

        $result = $this->scanner->scanStream($stream, 'huge.bin');

        $this->assertTrue($result->isError());
        $this->assertStringContainsString('size limit exceeded', (string) $result->message);
    }

    public function test_a_clean_file(): void
    {
        file_put_contents($this->dir.'/letter.txt', 'Sehr geehrte Damen und Herren');

        $this->assertTrue($this->scanner->scan($this->dir.'/letter.txt')->isClean());
    }
}
