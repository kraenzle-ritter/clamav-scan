<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Tests;

/**
 * Runs tests/Fixtures/fake-clamd.php in its own process for the length of a
 * test.
 */
final class FakeClamd
{
    /** @var resource */
    private $process;

    public readonly string $address;

    private function __construct(string $address, string $mode, int $maxLength)
    {
        $process = proc_open(
            [PHP_BINARY, __DIR__.'/Fixtures/fake-clamd.php', $address, $mode, (string) $maxLength],
            [1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        if ($process === false) {
            throw new \RuntimeException('Cannot start fake clamd.');
        }
        $this->process = $process;

        $line = fgets($pipes[1]);
        if ($line === false) {
            $this->stop();
            throw new \RuntimeException('Fake clamd did not start: '.stream_get_contents($pipes[2]));
        }
        $this->address = trim($line);
    }

    public static function tcp(string $mode = 'normal', int $maxLength = 1048576): self
    {
        return new self('tcp://127.0.0.1:0', $mode, $maxLength);
    }

    public static function unix(string $mode = 'normal', int $maxLength = 1048576): self
    {
        $path = sys_get_temp_dir().'/clamav-scan-'.bin2hex(random_bytes(4)).'.sock';

        return new self('unix://'.$path, $mode, $maxLength);
    }

    public function stop(): void
    {
        proc_terminate($this->process, 9);
        proc_close($this->process);

        if (str_starts_with($this->address ?? '', 'unix://')) {
            @unlink(substr($this->address, strlen('unix://')));
        }
    }
}
