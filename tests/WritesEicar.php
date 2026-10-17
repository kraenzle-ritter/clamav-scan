<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Tests;

use KraenzleRitter\ClamavScan\Eicar;

/**
 * The EICAR file on disk, or a skipped test where the operating system takes
 * it away: macOS XProtect blocks and deletes it as soon as it is written.
 * Tests that only need the bytes send them from memory instead.
 */
trait WritesEicar
{
    private function eicarFile(string $path): string
    {
        Eicar::writeTo($path);

        if (@file_get_contents($path) !== Eicar::string()) {
            @unlink($path);
            $this->markTestSkipped('The EICAR file was removed or blocked by a local virus scanner (e.g. macOS XProtect).');
        }

        return $path;
    }

    /**
     * @return resource
     */
    private function eicarStream()
    {
        $stream = fopen('php://memory', 'r+b');
        assert($stream !== false);
        fwrite($stream, Eicar::string());
        rewind($stream);

        return $stream;
    }
}
