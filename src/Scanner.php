<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan;

use KraenzleRitter\ClamavScan\Exception\ConnectionException;
use KraenzleRitter\ClamavScan\Exception\FileNotReadableException;

/**
 * Checks files for malware.
 *
 * A scan of one file ends in a result — clean, infected or error. When the
 * scanner itself cannot be reached, `scan()` throws instead: that is not a
 * verdict on the file, and callers decide for themselves whether to skip or
 * fail (agate: `virus_scan` reports `skipped` unless a scan is required).
 */
interface Scanner
{
    /**
     * Whether the scanner answers. Never throws.
     */
    public function isAvailable(): bool;

    /**
     * Engine and signature version, e.g. `ClamAV 1.4.3/27430/Thu Oct 16
     * 08:30:00 2026`; null when the scanner does not answer or does not
     * tell (clamd with `EnableVersionCommand no`).
     */
    public function version(): ?string;

    /**
     * @throws FileNotReadableException when the file does not exist or cannot be read
     * @throws ConnectionException when the scanner cannot be reached or drops the connection
     */
    public function scan(string $path): ScanResult;
}
