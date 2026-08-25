<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\TelegramBotNettools\Contracts\FetcherContract;
use BAGArt\TelegramBotNettools\Sources\FetchOutcome;

/**
 * Scripted FetcherContract for feature tests. Entries:
 *   - string body → 200 with that body
 *   - '@refused'|'@timeout'|'@tls' → transport failure outcome
 *   - array{status?, body?, headers?, protocolVersion?} → explicit outcome
 * Unscripted URLs answer 404.
 */
final class FakeProbeFetcher implements FetcherContract
{
    /** @var array<string, string|array<string, mixed>> */
    private array $scripted = [];

    /** @param array<string, string|array<string, mixed>> $entries */
    public function __construct(array $entries = [])
    {
        $this->scripted = $entries;
    }

    public function script(string $url, string|array $entry): self
    {
        $this->scripted[$url] = $entry;

        return $this;
    }

    public function fetch(string $url, string $method, int $timeoutSeconds, array $headers = [], array $curlOptions = []): FetchOutcome
    {
        $entry = $this->scripted[$this->normalize($url)] ?? null;

        if ($entry === null) {
            return new FetchOutcome(status: 404, body: 'not found', headers: [], protocolVersion: '1.1');
        }

        if (is_string($entry)) {
            return match ($entry) {
                '@refused' => new FetchOutcome(status: 0, body: '', error: 'refused'),
                '@timeout' => new FetchOutcome(status: 0, body: '', error: 'timeout'),
                '@tls' => new FetchOutcome(status: 0, body: '', error: 'tls'),
                default => new FetchOutcome(status: 200, body: $entry, headers: [], protocolVersion: '1.1'),
            };
        }

        return new FetchOutcome(
            status: (int) ($entry['status'] ?? 200),
            body: (string) ($entry['body'] ?? ''),
            headers: (array) ($entry['headers'] ?? []),
            protocolVersion: (string) ($entry['protocolVersion'] ?? '1.1'),
        );
    }

    private function normalize(string $url): string
    {
        return preg_replace('/\?.*$/', '', $url) ?? $url;
    }
}
