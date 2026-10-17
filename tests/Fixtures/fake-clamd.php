<?php

declare(strict_types=1);

/**
 * A stand-in for clamd that speaks just enough of its protocol for the tests:
 * zPING, zVERSION and zINSTREAM.
 *
 * Usage: php fake-clamd.php <address> <mode> [max-length]
 *   address     tcp://127.0.0.1:0 (any free port) or unix:///path/to.sock
 *   mode        normal  — answers like clamd
 *               silent  — reads the command, closes without an answer
 *               hang    — reads the command, never answers
 *               garbage — answers INSTREAM with something unexpected
 *               noversion — VERSION disabled (EnableVersionCommand no, the
 *                           Debian/Ubuntu default since ClamAV 1.5)
 *   max-length  StreamMaxLength in bytes (default 1048576)
 *
 * Prints the address it listens on, then serves until killed.
 */

use KraenzleRitter\ClamavScan\Eicar;

require __DIR__.'/../../vendor/autoload.php';

[, $address, $mode] = $argv + [null, 'tcp://127.0.0.1:0', 'normal'];
$maxLength = (int) ($argv[3] ?? 1048576);

$server = stream_socket_server($address, $errno, $error);
if ($server === false) {
    fwrite(STDERR, "Cannot listen on {$address}: {$error}\n");
    exit(1);
}

echo str_starts_with($address, 'unix://')
    ? $address
    : 'tcp://'.stream_socket_get_name($server, false);
echo "\n";
fflush(STDOUT);

/**
 * @param  resource  $connection
 */
function readExactly($connection, int $length): ?string
{
    $data = '';
    while (strlen($data) < $length) {
        $chunk = fread($connection, $length - strlen($data));
        if ($chunk === false || ($chunk === '' && feof($connection))) {
            return null;
        }
        $data .= $chunk;
    }

    return $data;
}

/**
 * @param  resource  $connection
 */
function readCommand($connection): ?string
{
    $command = '';
    while (! str_ends_with($command, "\0")) {
        $byte = fread($connection, 1);
        if ($byte === false || $byte === '') {
            return null;
        }
        $command .= $byte;
    }

    return rtrim($command, "\0");
}

/**
 * @param  resource  $connection
 */
function instream($connection, int $maxLength): string
{
    $data = '';
    while (true) {
        $header = readExactly($connection, 4);
        if ($header === null) {
            return '';
        }
        $length = unpack('N', $header)[1];
        if ($length === 0) {
            break;
        }
        if (strlen($data) + $length > $maxLength) {
            return 'INSTREAM size limit exceeded. ERROR';
        }
        $data .= readExactly($connection, $length) ?? '';
    }

    return Eicar::isIn($data) ? 'stream: '.Eicar::SIGNATURE.' FOUND' : 'stream: OK';
}

while (true) {
    $connection = @stream_socket_accept($server, -1);
    if ($connection === false) {
        continue;
    }

    $command = readCommand($connection);

    if ($mode === 'silent') {
        fclose($connection);

        continue;
    }
    if ($mode === 'hang') {
        sleep(60);
        fclose($connection);

        continue;
    }

    $answer = match ($command) {
        'zPING' => 'PONG',
        'zVERSION' => $mode === 'noversion' ? 'COMMAND UNAVAILABLE' : 'ClamAV 1.4.3/27430/Fake clamd',
        'zINSTREAM' => $mode === 'garbage' ? 'stream: who knows' : instream($connection, $maxLength),
        default => 'UNKNOWN COMMAND',
    };

    fwrite($connection, $answer."\0");
    fclose($connection);
}
