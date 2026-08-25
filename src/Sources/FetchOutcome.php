<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

/**
 * Outcome of one raw HTTP fetch. State only — JSON-safe. `status === 0`
 * marks a transport-level failure; `error` carries the coarse cause.
 */
final readonly class FetchOutcome
{
    public function __construct(
        public int $status,
        public string $body,
        /** @var array<string, string> lowercase header name → first value */
        public array $headers = [],
        public ?string $protocolVersion = null,
        public ?string $error = null,
    ) {
    }

    public function ok(): bool
    {
        return $this->status >= 200 && $this->status < 400;
    }

    public function isTransportFailure(): bool
    {
        return $this->status === 0;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
