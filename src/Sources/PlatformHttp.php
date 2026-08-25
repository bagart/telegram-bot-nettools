<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\ASKClient\Contracts\Client\ApiClientContract;
use BAGArt\ASKClient\Dto\ASKHttpRequest;
use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;
use BAGArt\TelegramBotNettools\Support\HttpHopGuard;

/**
 * Platform-backed {@see SourceHttpContract}: the bot setup's generic,
 * rate-limited, Fiber-aware API client (bounded-blocking per RFC §4.5 D1 —
 * sync await inside the kernel Fiber suspends it, outside it busy-pumps).
 *
 * Follows up to two 3xx hops manually so behavior is identical across
 * guzzle/curl-multi/ask-socket transports (only curl honors FOLLOWLOCATION
 * natively). Each hop re-passes the SSRF verdict for the new host and denies
 * https→http downgrades; a blocked or failed hop surfaces as null — a
 * degraded upstream signal, never an exception path.
 */
final class PlatformHttp implements SourceHttpContract
{
    private const int MAX_REDIRECT_HOPS = 2;

    public function __construct(
        private readonly ApiClientContract $client,
        private readonly HttpHopGuard $hopGuard = new HttpHopGuard(),
    ) {
    }

    public function getJson(string $url, int $timeoutSeconds): ?array
    {
        $hops = 0;

        while (true) {
            $response = $this->client->request(new ASKHttpRequest(
                url: $url,
                method: 'GET',
                headers: ['Accept' => 'application/rdap+json, application/json'],
                curlOptions: [
                    CURLOPT_CONNECTTIMEOUT => min($timeoutSeconds, 5),
                    CURLOPT_TIMEOUT => $timeoutSeconds,
                    CURLOPT_SSL_VERIFYPEER => true,
                ],
                requestName: 'nettools:'.(parse_url($url, PHP_URL_HOST) ?: 'http'),
            ));

            $status = $response->getStatusCode();

            if ($status >= 300 && $status < 400 && $hops < self::MAX_REDIRECT_HOPS) {
                $location = $response->getHeaderLine('Location');
                $target = $location === '' ? null : $this->redirectTarget($url, $location);

                if ($target !== null) {
                    if (($this->hopGuard->approve($target, parse_url($url, PHP_URL_SCHEME)))['reason'] !== null) {
                        return null;
                    }

                    $url = $target;
                    $hops++;

                    continue;
                }
            }

            if ($status < 200 || $status >= 300) {
                return null;
            }

            return $this->decodeBody((string) $response->getBody());
        }
    }

    private function redirectTarget(string $currentUrl, string $location): ?string
    {
        if ($location === '') {
            return null;
        }

        if (str_starts_with($location, 'https://') || str_starts_with($location, 'http://')) {
            return $location;
        }

        $parts = parse_url($currentUrl);
        if (! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        return $parts['scheme'].'://'.$parts['host'].'/'.$location;
    }

    /**
     * Accepts both top-level JSON objects and lists: crt.sh `output=json`
     * and certspotter issuances answer with bare arrays.
     *
     * @return array<string, mixed>|list<mixed>|null
     */
    private function decodeBody(string $body): ?array
    {
        if ($body === '' || ! in_array($body[0], ['{', '['], true)) {
            return null;
        }

        try {
            /** @var array<string, mixed>|list<mixed>|false|null $decoded */
            $decoded = json_decode($body, true, 64, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }
}
