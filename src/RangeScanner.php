<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan;

use KraenzleRitter\ClamavScan\Exception\ConnectionException;
use KraenzleRitter\ClamavScan\Exception\FileNotReadableException;

/**
 * A scanner that can check part of a file: a file larger than clamd scans
 * (2 GB at most) is scanned in overlapping parts.
 *
 * A part is weaker evidence than the whole file. clamd sees the bytes, not
 * the format: signatures by byte pattern are found, those anchored at the
 * end of the file or tied to its structure (an archive's directory, a PDF's
 * objects) and hashes of the whole file are not. Record a file scanned so
 * as scanned in parts, not as clean.
 */
interface RangeScanner extends Scanner
{
    /**
     * Scan `$length` bytes of the file from `$offset` (fewer where the file
     * ends first).
     *
     * @throws FileNotReadableException when the file does not exist or cannot be read
     * @throws ConnectionException when the scanner cannot be reached or drops the connection
     */
    public function scanRange(string $path, int $offset, int $length): ScanResult;
}
