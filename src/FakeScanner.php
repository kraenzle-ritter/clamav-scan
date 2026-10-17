<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan;

use KraenzleRitter\ClamavScan\Exception\ConnectionException;
use KraenzleRitter\ClamavScan\Exception\FileNotReadableException;

/**
 * A scanner for tests, without clamd.
 *
 * Reports files as infected when their path matches a pattern (fnmatch, on
 * the full path or the file name), and files that contain the EICAR test
 * string. Records every path it was asked to scan.
 */
final class FakeScanner implements Scanner
{
    /** @var list<string> */
    private array $scanned = [];

    /**
     * @param  array<string, string>  $infected  pattern => signature
     * @param  array<string, string>  $errors  pattern => message
     */
    public function __construct(
        private readonly array $infected = [],
        private readonly array $errors = [],
        private readonly bool $available = true,
        private readonly bool $detectEicar = true,
    ) {}

    /**
     * A scanner that cannot be reached, as when clamd is not running.
     */
    public static function unavailable(): self
    {
        return new self(available: false);
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    public function version(): ?string
    {
        return $this->available ? 'FakeScanner' : null;
    }

    public function scan(string $path): ScanResult
    {
        if (! $this->available) {
            throw new ConnectionException('FakeScanner is unavailable.');
        }
        if (! is_file($path) || ! is_readable($path)) {
            throw FileNotReadableException::forPath($path);
        }

        $this->scanned[] = $path;

        if (($message = $this->match($path, $this->errors)) !== null) {
            return ScanResult::error($path, $message);
        }
        if (($signature = $this->match($path, $this->infected)) !== null) {
            return ScanResult::infected($path, $signature);
        }
        if ($this->detectEicar && Eicar::isIn((string) file_get_contents($path))) {
            return ScanResult::infected($path, Eicar::SIGNATURE);
        }

        return ScanResult::clean($path);
    }

    /**
     * @return list<string>
     */
    public function scanned(): array
    {
        return $this->scanned;
    }

    /**
     * @param  array<string, string>  $patterns
     */
    private function match(string $path, array $patterns): ?string
    {
        foreach ($patterns as $pattern => $value) {
            if (fnmatch($pattern, $path) || fnmatch($pattern, basename($path))) {
                return $value;
            }
        }

        return null;
    }
}
