<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\ASKClient\Contracts\Client\ApiClientContract;
use BAGArt\ASKClient\Dto\ASKHttpRequest;
use BAGArt\TelegramBotNettools\Contracts\FetcherContract;

/**
 * Platform-backed {@see FetcherContract}: the bot setup's generic,
 * rate-limited, Fiber-aware API client. Single hop only — redirect chains are
 * the probe's job (per-hop timing + SSRF re-checks stay visible).
 */
final class PlatformFetcher implements FetcherContract
{
    public function __construct(private readonly ApiClientContract $client)
    {
    }

    public function fetch(string $url, string $method, int $timeoutSeconds, array $headers = [], array $curlOptions = []): FetchOutcome
    {
        try {
            $response = $this->client->request(new ASKHttpRequest(
                url: $url,
                method: $method,
                headers: $headers === [] ? ['Accept' => '*/*'] : $headers,
                curlOptions: [
                    CURLOPT_CONNECTTIMEOUT => min($timeoutSeconds, 5),
                    CURLOPT_TIMEOUT => $timeoutSeconds,
                    CURLOPT_SSL_VERIFYPEER => true,
                    CURLOPT_FOLLOWLOCATION => false,
                    ...$curlOptions,
                ],
                requestName: 'nettools:'.(parse_url($url, PHP_URL_HOST) ?: 'http'),
            ));
        } catch (\Throwable $exception) {
            return new FetchOutcome(status: 0, body: '', error: self::classify($exception));
        }

        /** @var array<string, string> $headers */
        $headers = [];
        foreach ($response->getHeaders() as $name => $values) {
            $first = is_array($values) ? ($values[0] ?? null) : $values;
            if (is_string($first)) {
                $headers[strtolower($name)] = $first;
            }
        }

        return new FetchOutcome(
            status: $response->getStatusCode(),
            body: (string) $response->getBody(),
            headers: $headers,
            protocolVersion: $response->getProtocolVersion(),
        );
    }

    private static function classify(\Throwable $exception): string
    {
        $message = mb_strtolower($exception->getMessage());

        return match (true) {
            str_contains($message, 'timed out'), str_contains($message, 'timeout') => 'timeout',
            str_contains($message, 'refused') => 'refused',
            str_contains($message, 'ssl'), str_contains($message, 'certificate'), str_contains($message, 'tls') => 'tls',
            default => 'other',
        };
    }
}
