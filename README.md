# kraenzle-ritter/clamav-scan

Scans files for malware with ClamAV. Used by agate (SIP preparation) and
Anton (archival description), so that both check uploads the same way and
against the same clamd.

The package is a small client for clamd. It sends each file over a Unix or
TCP socket with `zINSTREAM`, so clamd never has to read the file itself: no
shared paths between containers, no file permissions for the clamav user.
It has no dependencies beyond PHP 8.2 and does not depend on Laravel; each
application binds it in its own way.

## Use

```php
use KraenzleRitter\ClamavScan\ClamdScanner;

$scanner = new ClamdScanner('unix:///var/run/clamav/clamd.ctl'); // or tcp://clamav:3310

if (! $scanner->isAvailable()) {
    // clamd is not running: skip, or fail if a scan is required
}

$result = $scanner->scan('/path/to/file.pdf');

$result->isClean();      // true
$result->isInfected();   // with $result->signature, e.g. Eicar-Test-Signature
$result->isError();      // clamd answered but could not check the file, see $result->message
```

A scan ends in one of three results:

| Status | Meaning |
|---|---|
| `clean` | clamd found nothing |
| `infected` | clamd found a signature; `signature` names it |
| `error` | clamd answered but did not check the file, e.g. `INSTREAM size limit exceeded.` Not clean. |

When clamd cannot be reached, does not answer within the timeout or closes
the connection without an answer, `scan()` throws a `ConnectionException`.
That is not a verdict on the file. A missing or unreadable file throws a
`FileNotReadableException`.

`version()` returns engine and signature version
(`ClamAV 1.4.3/27430/Thu Oct 16 08:30:00 2026`); record it with the result.

`scanStream($stream, $name)` scans an open stream, e.g. an upload that is
not on disk yet.

### Options

```php
new ClamdScanner(
    socket: 'tcp://clamav:3310',  // unix://…, tcp://…, or a bare path
    timeout: 30.0,                // seconds, to connect and per read/write
    chunkSize: 65536,             // bytes per INSTREAM chunk
);
```

## Tests in your application

`FakeScanner` needs no clamd. It reports files as infected or as errors by
pattern (fnmatch on the full path or the file name), and finds the EICAR
test string in a file's content:

```php
use KraenzleRitter\ClamavScan\FakeScanner;

$scanner = new FakeScanner(
    infected: ['*/virus.exe' => 'Win.Trojan.Fake'],
    errors: ['*.iso' => 'INSTREAM size limit exceeded.'],
);

$scanner->scanned();            // every path it was asked to scan
FakeScanner::unavailable();     // behaves like a clamd that is not running
```

Prefer patterns over EICAR files on disk. **macOS XProtect blocks and
deletes an EICAR file as soon as it is written**, also in a ddev project
whose files live on the Mac. `Eicar::string()` gives the bytes for a stream.

## clamd

clamd keeps its signatures in memory: plan for **1–1.5 GB of RAM**, briefly
twice that while it reloads them unless `ConcurrentDatabaseReload no` is
set. `freshclam` keeps the signatures up to date.

- Debian/Ubuntu: `apt install clamav-daemon clamav-freshclam`; the socket is
  `/var/run/clamav/clamd.ctl`. The web server user needs access to it
  (group `clamav`), or use `TCPSocket 3310` with `TCPAddr 127.0.0.1`.
- `StreamMaxLength` (default 100 MB) caps what clamd accepts over
  `INSTREAM`. Larger files come back as `error`. Set it to the largest file
  you expect, e.g. `StreamMaxLength 4000M`.
- **`MaxFileSize` and `MaxScanSize` (defaults 100 MB and 400 MB): beyond
  them clamd stops scanning and answers `OK`.** Raise them together with
  `StreamMaxLength`, and set `AlertExceedsMax yes`, so that a file clamd
  did not scan fully comes back as infected with
  `Heuristics.Limits.Exceeded.*` instead of clean.
- Docker: `clamav/clamav-debian` (amd64 and arm64; `clamav/clamav` is
  amd64 only). It runs freshclam itself and listens on port 3310.

## Development

```bash
composer install
composer test        # unit tests against a fake clamd in a separate process
composer analyse
```

The integration tests run against a real clamd when `CLAMD_SOCKET` is set:

```bash
docker run -d --name clamd -p 127.0.0.1:3310:3310 clamav/clamav-debian:1.4
# wait a minute or two until the signatures are loaded
CLAMD_SOCKET=tcp://127.0.0.1:3310 composer test
```

## License

MIT
