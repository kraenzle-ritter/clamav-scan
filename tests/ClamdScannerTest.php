<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Tests;

use KraenzleRitter\ClamavScan\ClamdScanner;
use KraenzleRitter\ClamavScan\Eicar;
use KraenzleRitter\ClamavScan\Exception\ConnectionException;
use KraenzleRitter\ClamavScan\Exception\FileNotReadableException;
use KraenzleRitter\ClamavScan\ScanStatus;
use PHPUnit\Framework\TestCase;

final class ClamdScannerTest extends TestCase
{
    use WritesEicar;

    private ?FakeClamd $clamd = null;

    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/clamav-scan-test-'.bin2hex(random_bytes(4));
        mkdir($this->dir);
    }

    protected function tearDown(): void
    {
        $this->clamd?->stop();
        array_map('unlink', glob($this->dir.'/*') ?: []);
        rmdir($this->dir);
    }

    private function scanner(string $mode = 'normal', int $maxLength = 1048576, float $timeout = 5.0, int $chunkSize = 65536): ClamdScanner
    {
        $this->clamd = FakeClamd::tcp($mode, $maxLength);

        return new ClamdScanner($this->clamd->address, $timeout, $chunkSize);
    }

    private function file(string $name, string $content): string
    {
        file_put_contents($this->dir.'/'.$name, $content);

        return $this->dir.'/'.$name;
    }

    public function test_it_is_available_when_clamd_answers_ping(): void
    {
        $this->assertTrue($this->scanner()->isAvailable());
    }

    public function test_it_reports_the_version(): void
    {
        $this->assertSame('ClamAV 1.4.3/27430/Fake clamd', $this->scanner()->version());
    }

    public function test_the_version_is_null_when_clamd_does_not_tell(): void
    {
        $scanner = $this->scanner('noversion');

        $this->assertTrue($scanner->isAvailable());
        $this->assertNull($scanner->version());
    }

    public function test_a_clean_file_is_clean(): void
    {
        $path = $this->file('letter.txt', 'Sehr geehrte Damen und Herren');

        $result = $this->scanner()->scan($path);

        $this->assertSame(ScanStatus::Clean, $result->status);
        $this->assertSame($path, $result->path);
        $this->assertNull($result->signature);
    }

    public function test_an_empty_file_is_clean(): void
    {
        $this->assertTrue($this->scanner()->scan($this->file('empty.txt', ''))->isClean());
    }

    public function test_eicar_is_infected(): void
    {
        $result = $this->scanner()->scanStream($this->eicarStream(), 'eicar.com');

        $this->assertTrue($result->isInfected());
        $this->assertSame(Eicar::SIGNATURE, $result->signature);
    }

    public function test_the_eicar_file_on_disk_is_infected(): void
    {
        $path = $this->eicarFile($this->dir.'/eicar.com');

        $result = $this->scanner()->scan($path);

        $this->assertTrue($result->isInfected());
        $this->assertSame($path, $result->path);
    }

    public function test_a_file_is_sent_in_several_chunks(): void
    {
        // EICAR at the end of a stream that takes many 1 KiB chunks.
        $stream = fopen('php://memory', 'r+b');
        fwrite($stream, str_repeat('a', 100_000).Eicar::string());
        rewind($stream);

        $result = $this->scanner(chunkSize: 1024)->scanStream($stream);

        $this->assertTrue($result->isInfected());
    }

    public function test_a_file_over_the_size_limit_is_an_error_not_clean(): void
    {
        $path = $this->file('huge.bin', str_repeat('a', 300_000));

        $result = $this->scanner(maxLength: 100_000, chunkSize: 8192)->scan($path);

        $this->assertTrue($result->isError());
        $this->assertSame('INSTREAM size limit exceeded.', $result->message);
    }

    public function test_an_unexpected_answer_is_an_error(): void
    {
        $result = $this->scanner('garbage')->scan($this->file('a.txt', 'a'));

        $this->assertTrue($result->isError());
        $this->assertStringContainsString('stream: who knows', (string) $result->message);
    }

    public function test_it_speaks_over_a_unix_socket(): void
    {
        $this->clamd = FakeClamd::unix();
        $scanner = new ClamdScanner($this->clamd->address, 5.0);

        $this->assertTrue($scanner->isAvailable());
        $this->assertTrue($scanner->scanStream($this->eicarStream())->isInfected());
    }

    public function test_a_bare_path_is_a_unix_socket(): void
    {
        $this->assertSame('unix:///run/clamav/clamd.ctl', (new ClamdScanner('/run/clamav/clamd.ctl'))->socket());
    }

    public function test_it_is_not_available_when_nothing_listens(): void
    {
        $scanner = new ClamdScanner('unix://'.$this->dir.'/nothing.sock', 1.0);

        $this->assertFalse($scanner->isAvailable());
        $this->assertNull($scanner->version());
    }

    public function test_scanning_without_clamd_throws(): void
    {
        $scanner = new ClamdScanner('unix://'.$this->dir.'/nothing.sock', 1.0);

        $this->expectException(ConnectionException::class);

        $scanner->scan($this->file('a.txt', 'a'));
    }

    public function test_a_connection_closed_without_answer_throws(): void
    {
        $scanner = $this->scanner('silent');

        $this->assertFalse($scanner->isAvailable());

        $this->expectException(ConnectionException::class);
        $scanner->scan($this->file('a.txt', 'a'));
    }

    public function test_no_answer_within_the_timeout_throws(): void
    {
        $scanner = $this->scanner('hang', timeout: 0.5);

        $this->expectException(ConnectionException::class);
        $this->expectExceptionMessage('did not answer within 0.5 s');

        $scanner->scan($this->file('a.txt', 'a'));
    }

    public function test_a_missing_file_throws(): void
    {
        $this->expectException(FileNotReadableException::class);

        (new ClamdScanner('unix://'.$this->dir.'/nothing.sock'))->scan($this->dir.'/missing.txt');
    }

    public function test_a_stream_can_be_scanned(): void
    {
        $result = $this->scanner()->scanStream($this->eicarStream(), 'upload.bin');

        $this->assertTrue($result->isInfected());
        $this->assertSame('upload.bin', $result->path);
    }

    public function test_chunk_size_must_be_positive(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new ClamdScanner(chunkSize: 0);
    }
}
