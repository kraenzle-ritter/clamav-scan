<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan\Exception;

/**
 * clamd cannot be reached, does not answer in time or closes the connection
 * without an answer.
 */
final class ConnectionException extends ClamavScanException {}
