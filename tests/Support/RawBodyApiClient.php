<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\ASKClient\Contracts\Client\ApiClientContract;
use BAGArt\ASKClient\Dto\ASKHttpRequest;
use BAGArt\ASKClient\Dto\ASKHttpResponse;
use BAGArt\AsyncKernel\Contracts\ASKPromiseContract;

/**
 * ApiClientContract double returning RAW string bodies — exercises the
 * production PlatformHttp decode path exactly as wire responses arrive
 * (top-level JSON arrays included), unlike the pre-decoded FakeHttpSource.
 *
 * Entry shapes:
 *  - string                 → 200 with that body
 *  - array{status, body, headers} → explicit outcome (redirect fixtures)
 */
final class RawBodyApiClient implements ApiClientContract
{
    /** @var list<string> */
    public array $requestedUrls = [];

    /** @param array<string, string|array{status?: int, body?: string, headers?: array<string, string>}> $byUrl */
    public function __construct(private readonly array $byUrl = [])
    {
    }

    public function request(ASKHttpRequest $request): ASKHttpResponse
    {
        $this->requestedUrls[] = $request->url;

        $entry = $this->byUrl[$request->url] ?? '';

        if (is_string($entry)) {
            return ASKHttpResponse::fromString($entry);
        }

        return ASKHttpResponse::fromString(
            (string) ($entry['body'] ?? ''),
            (int) ($entry['status'] ?? 200),
            headers: (array) ($entry['headers'] ?? []),
        );
    }

    public function requestAsync(ASKHttpRequest $request): ASKPromiseContract
    {
        throw new \LogicException('async transport not used in tests');
    }

    public function tickable(): array
    {
        return [];
    }
}
