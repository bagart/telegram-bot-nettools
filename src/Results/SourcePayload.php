<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Results;

/**
 * Payload returned by a single upstream source. State only — JSON-safe by
 * construction (scalar-only tree in $fields).
 */
final readonly class SourcePayload
{
    /**
     * @param  array<string, mixed>  $fields  scalar-only tree; no closures,
     *                                        no nested objects
     */
    public function __construct(
        public string $sourceName,
        public float $latencyMs = 0.0,
        public array $fields = [],
    ) {
    }
}
