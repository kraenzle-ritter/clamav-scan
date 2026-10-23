<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan;

use KraenzleRitter\ClamavScan\Exception\ConnectionException;
use KraenzleRitter\ClamavScan\Exception\FileNotReadableException;

/**
 * Talks to clamd over a Unix or TCP socket.
 *
 * Files are sent with `zINSTREAM`, so clamd never needs to read them itself:
 * no shared paths between containers, no file permissions for the clamav
 * user. Every call opens its own connection; clamd closes it after one
 * command.
 *
 * Protocol: commands prefixed with `z` end in a NUL byte, and so does the
 * answer. `INSTREAM` takes chunks of a 4-byte length in network byte order
 * followed by the data, and a chunk of length zero to end the stream.
 */
final class ClamdScanner implements RangeScanner
{
    public const DEFAULT_SOCKET = 'unix:///var/run/clamav/clamd.ctl';

    private readonly string $socket;

    /** @var int<1, max> */
    private readonly int $chunkSize;

    /**
     * @param  string  $socket  `unix:///path/to/clamd.ctl`, `tcp://host:3310`, or a bare path
     * @param  float  $timeout  seconds to connect, and to wait for each read or write
     * @param  int  $chunkSize  bytes per INSTREAM chunk
     */
    public function __construct(
        string $socket = self::DEFAULT_SOCKET,
        private readonly float $timeout = 30.0,
        int $chunkSize = 65536,
    ) {
        if ($chunkSize < 1) {
            throw new \InvalidArgumentException('Chunk size must be at least 1 byte.');
        }

        $this->chunkSize = $chunkSize;

        $this->socket = str_starts_with($socket, '/') ? 'unix://'.$socket : $socket;
    }

    public function socket(): string
    {
        return $this->socket;
    }

    public function isAvailable(): bool
    {
        try {
            return $this->command('PING') === 'PONG';
        } catch (ConnectionException) {
            return false;
        }
    }

    /**
     * Null also when clamd refuses the command: Debian and Ubuntu ship
     * ClamAV 1.5 with `EnableVersionCommand no`, and clamd then answers
     * `COMMAND UNAVAILABLE`.
     */
    public function version(): ?string
    {
        try {
            $answer = $this->command('VERSION');
        } catch (ConnectionException) {
            return null;
        }

        return str_starts_with($answer, 'ClamAV ') ? $answer : null;
    }

    public function scan(string $path): ScanResult
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw FileNotReadableException::forPath($path);
        }

        $file = @fopen($path, 'rb');
        if ($file === false) {
            throw FileNotReadableException::forPath($path);
        }

        try {
            return $this->scanStream($file, $path);
        } finally {
            fclose($file);
        }
    }

    public function scanRange(string $path, int $offset, int $length): ScanResult
    {
        if ($offset < 0 || $length < 1) {
            throw new \InvalidArgumentException('A range needs an offset of at least 0 and a length of at least 1 byte.');
        }
        if (! is_file($path) || ! is_readable($path)) {
            throw FileNotReadableException::forPath($path);
        }

        $file = @fopen($path, 'rb');
        if ($file === false || fseek($file, $offset) !== 0) {
            throw FileNotReadableException::forPath($path);
        }

        try {
            return $this->scanStream($file, $path, $length);
        } finally {
            fclose($file);
        }
    }

    /**
     * Scans whatever the stream yields from its current position to its end,
     * or the next `$length` bytes of it.
     *
     * @param  resource  $stream
     * @param  string  $path  what the result names; the stream itself has no path
     * @param  int|null  $length  at most this many bytes; null: to the end
     *
     * @throws ConnectionException
     */
    public function scanStream($stream, string $path = 'stream', ?int $length = null): ScanResult
    {
        $connection = $this->connect();

        try {
            if (! $this->write($connection, "zINSTREAM\0")) {
                throw new ConnectionException("clamd at {$this->socket} closed the connection before the scan.");
            }

            $left = $length;
            while (! feof($stream) && ($left === null || $left > 0)) {
                $chunk = fread($stream, $left === null ? $this->chunkSize : max(1, min($this->chunkSize, $left)));
                if ($chunk === false) {
                    throw FileNotReadableException::forPath($path);
                }
                if ($chunk === '') {
                    continue;
                }
                if ($left !== null) {
                    $left -= strlen($chunk);
                }

                if (! $this->write($connection, pack('N', strlen($chunk)).$chunk)) {
                    // clamd stops reading when the stream exceeds StreamMaxLength;
                    // its answer says so.
                    return $this->parseScanAnswer($path, $this->read($connection));
                }
            }

            $this->write($connection, pack('N', 0));

            return $this->parseScanAnswer($path, $this->read($connection));
        } finally {
            fclose($connection);
        }
    }

    /**
     * @throws ConnectionException
     */
    private function command(string $command): string
    {
        $connection = $this->connect();

        try {
            if (! $this->write($connection, "z{$command}\0")) {
                throw new ConnectionException("clamd at {$this->socket} closed the connection.");
            }

            return $this->read($connection);
        } finally {
            fclose($connection);
        }
    }

    private function parseScanAnswer(string $path, string $answer): ScanResult
    {
        if ($answer === 'stream: OK') {
            return ScanResult::clean($path);
        }

        if (preg_match('/^stream: (.+) FOUND$/', $answer, $match) === 1) {
            return ScanResult::infected($path, $match[1]);
        }

        if (str_ends_with($answer, ' ERROR')) {
            return ScanResult::error($path, substr($answer, 0, -strlen(' ERROR')));
        }

        return ScanResult::error($path, "Unexpected answer from clamd: {$answer}");
    }

    /**
     * @return resource
     *
     * @throws ConnectionException
     */
    private function connect()
    {
        $connection = @stream_socket_client($this->socket, $errno, $error, $this->timeout);
        if ($connection === false) {
            throw new ConnectionException("Cannot connect to clamd at {$this->socket}: {$error}", (int) $errno);
        }

        $seconds = (int) floor($this->timeout);
        stream_set_timeout($connection, $seconds, (int) (($this->timeout - $seconds) * 1_000_000));

        return $connection;
    }

    /**
     * @param  resource  $connection
     */
    private function write($connection, string $data): bool
    {
        while ($data !== '') {
            $written = @fwrite($connection, $data);
            if ($written === false || $written === 0) {
                return false;
            }
            $data = substr($data, $written);
        }

        return true;
    }

    /**
     * Reads up to the NUL byte that ends every answer to a `z` command.
     *
     * @param  resource  $connection
     *
     * @throws ConnectionException
     */
    private function read($connection): string
    {
        $answer = '';

        while (! str_contains($answer, "\0")) {
            $data = @fread($connection, 4096);

            if (stream_get_meta_data($connection)['timed_out']) {
                throw new ConnectionException("clamd at {$this->socket} did not answer within {$this->timeout} s.");
            }
            if ($data === false || $data === '') {
                if (feof($connection)) {
                    break;
                }

                continue;
            }

            $answer .= $data;
        }

        $answer = trim(strstr($answer, "\0", true) ?: $answer);
        if ($answer === '') {
            throw new ConnectionException("clamd at {$this->socket} closed the connection without an answer.");
        }

        return $answer;
    }
}
