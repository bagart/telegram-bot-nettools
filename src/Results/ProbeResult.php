<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Results;

/**
 * Probe outcome stored in cache. State only — no closures, no behavior.
 * JSON round-trip ({@see toArray()} / {@see fromArray()}) must stay lossless;
 * enforced by contract tests (platform cache-purity rule).
 */
final readonly class ProbeResult
{
    /**
     * @param  list<string>  $degradedSources  sources that failed or were
     *                                         skipped — rendered as warning
     *                                         lines, never silent
     * @param  array<string, mixed>  $payload  probe-specific data, scalar-only tree
     */
    public function __construct(
        public string $probe,
        public int $fetchedAt,
        public int $latencyMs,
        public array $degradedSources = [],
        public array $payload = [],
    ) {
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'probe' => $this->probe,
            'fetched_at' => $this->fetchedAt,
            'latency_ms' => $this->latencyMs,
            'degraded_sources' => $this->degradedSources,
            'payload' => $this->payload,
        ];
    }

    /**
     * @param  array<string, mixed>  $data
     *
     * @throws \InvalidArgumentException on malformed input
     */
    public static function fromArray(array $data): self
    {
        foreach (['probe', 'fetched_at', 'latency_ms'] as $required) {
            if (! array_key_exists($required, $data)) {
                throw new \InvalidArgumentException("ProbeResult payload missing '{$required}'");
            }
        }

        return new self(
            probe: (string) $data['probe'],
            fetchedAt: (int) $data['fetched_at'],
            latencyMs: (int) $data['latency_ms'],
            degradedSources: array_values((array) ($data['degraded_sources'] ?? [])),
            payload: (array) ($data['payload'] ?? []),
        );
    }

    public function withTiming(int $fetchedAt, int $latencyMs): self
    {
        return new self($this->probe, $fetchedAt, $latencyMs, $this->degradedSources, $this->payload);
    }

    /** @param list<string> $degradedSources */
    public function withDegradedSources(array $degradedSources): self
    {
        return new self($this->probe, $this->fetchedAt, $this->latencyMs, $degradedSources, $this->payload);
    }

    public function ageSeconds(int $now): int
    {
        return max(0, $now - $this->fetchedAt);
    }

    public function isFresh(int $ttlSeconds, int $now): bool
    {
        return $ttlSeconds > 0 && $this->ageSeconds($now) < $ttlSeconds;
    }
}
