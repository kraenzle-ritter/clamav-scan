<?php

declare(strict_types=1);

namespace KraenzleRitter\ClamavScan;

final readonly class ScanResult
{
    private function __construct(
        public string $path,
        public ScanStatus $status,
        public ?string $signature = null,
        public ?string $message = null,
    ) {}

    public static function clean(string $path): self
    {
        return new self($path, ScanStatus::Clean);
    }

    public static function infected(string $path, string $signature): self
    {
        return new self($path, ScanStatus::Infected, signature: $signature);
    }

    public static function error(string $path, string $message): self
    {
        return new self($path, ScanStatus::Error, message: $message);
    }

    public function isClean(): bool
    {
        return $this->status === ScanStatus::Clean;
    }

    public function isInfected(): bool
    {
        return $this->status === ScanStatus::Infected;
    }

    public function isError(): bool
    {
        return $this->status === ScanStatus::Error;
    }

    /**
     * @return array{path: string, status: string, signature: ?string, message: ?string}
     */
    public function toArray(): array
    {
        return [
            'path' => $this->path,
            'status' => $this->status->value,
            'signature' => $this->signature,
            'message' => $this->message,
        ];
    }
}
