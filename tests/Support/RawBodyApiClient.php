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
 */
final class RawBodyApiClient implements ApiClientContract
{
    /** @param array<string, string> $byUrl url → raw response body */
    public function __construct(private readonly array $byUrl = [])
    {
    }

    public function request(ASKHttpRequest $request): ASKHttpResponse
    {
        return ASKHttpResponse::fromString($this->byUrl[$request->url] ?? '');
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
