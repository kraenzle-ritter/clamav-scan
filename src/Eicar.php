<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan;

/**
 * The EICAR anti-virus test file: harmless, and detected by every scanner.
 *
 * The string is put together at runtime, so that this source file is not
 * itself flagged by a scanner on a developer's machine or in a repository.
 */
final class Eicar
{
    /**
     * The name ClamAV gives it. Built into the engine since ClamAV 0.101;
     * older signature databases called it Win.Test.EICAR_HDB-1.
     */
    public const SIGNATURE = 'Eicar-Test-Signature';

    public static function string(): string
    {
        return 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$'.'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
    }

    /**
     * Writes the test file and returns its path.
     */
    public static function writeTo(string $path): string
    {
        file_put_contents($path, self::string());

        return $path;
    }

    public static function isIn(string $content): bool
    {
        return str_contains($content, self::string());
    }
}
