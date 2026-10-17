<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan;

enum ScanStatus: string
{
    case Clean = 'clean';
    case Infected = 'infected';

    /**
     * The scanner answered but could not check the file, e.g. because it
     * exceeds `StreamMaxLength`. Not clean.
     */
    case Error = 'error';
}
