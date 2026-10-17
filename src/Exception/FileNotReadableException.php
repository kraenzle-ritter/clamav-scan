<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Exception;

final class FileNotReadableException extends ClamavScanException
{
    public static function forPath(string $path): self
    {
        return new self("File not found or not readable: {$path}");
    }
}
