<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Tests;

use KraenzleRitter\ClamavScan\Eicar;
use KraenzleRitter\ClamavScan\Exception\ConnectionException;
use KraenzleRitter\ClamavScan\Exception\FileNotReadableException;
use KraenzleRitter\ClamavScan\FakeScanner;
use PHPUnit\Framework\TestCase;

final class FakeScannerTest extends TestCase
{
    use WritesEicar;

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/clamav-scan-fake-'.bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        array_map('unlink', glob($this->dir.'/*') ?: []);
        rmdir($this->dir);
    }

    private function file(string $name, string $content = 'x'): string
    {
        file_put_contents($this->dir.'/'.$name, $content);

        return $this->dir.'/'.$name;
    }

    public function test_files_are_clean_by_default(): void
    {
        $this->assertTrue((new FakeScanner)->scan($this->file('a.txt'))->isClean());
    }

    public function test_it_detects_eicar(): void
    {
        $result = (new FakeScanner)->scan($this->eicarFile($this->dir.'/eicar.com'));

        $this->assertTrue($result->isInfected());
        $this->assertSame(Eicar::SIGNATURE, $result->signature);
    }

    public function test_eicar_detection_can_be_turned_off(): void
    {
        $scanner = new FakeScanner(detectEicar: false);

        $this->assertTrue($scanner->scan($this->eicarFile($this->dir.'/eicar.com'))->isClean());
    }

    public function test_patterns_match_the_file_name_or_the_full_path(): void
    {
        $scanner = new FakeScanner(infected: ['*.exe' => 'Win.Trojan.Fake', '*/macro.docm' => 'Doc.Macro.Fake']);

        $this->assertSame('Win.Trojan.Fake', $scanner->scan($this->file('setup.exe'))->signature);
        $this->assertSame('Doc.Macro.Fake', $scanner->scan($this->file('macro.docm'))->signature);
        $this->assertTrue($scanner->scan($this->file('letter.pdf'))->isClean());
    }

    public function test_errors_by_pattern(): void
    {
        $result = (new FakeScanner(errors: ['*.iso' => 'INSTREAM size limit exceeded.']))->scan($this->file('disk.iso'));

        $this->assertTrue($result->isError());
        $this->assertSame('INSTREAM size limit exceeded.', $result->message);
    }

    public function test_it_records_what_it_scanned(): void
    {
        $scanner = new FakeScanner;
        $a = $this->file('a.txt');
        $b = $this->file('b.txt');

        $scanner->scan($a);
        $scanner->scan($b);

        $this->assertSame([$a, $b], $scanner->scanned());
    }

    public function test_an_unavailable_scanner_throws_like_a_missing_clamd(): void
    {
        $scanner = FakeScanner::unavailable();

        $this->assertFalse($scanner->isAvailable());
        $this->assertNull($scanner->version());

        $this->expectException(ConnectionException::class);
        $scanner->scan($this->file('a.txt'));
    }

    public function test_a_missing_file_throws(): void
    {
        $this->expectException(FileNotReadableException::class);

        (new FakeScanner)->scan($this->dir.'/missing.txt');
    }
}
