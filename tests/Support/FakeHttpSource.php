<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;

/**
 * Scripted HTTP source: returns canned JSON payloads per URL (exact match),
 * recording every request for assertions.
 */
final class FakeHttpSource implements SourceHttpContract
{
    /** @var list<string> */
    public array $requestedUrls = [];

    /** @var array<string, array<string, mixed>> */
    private array $scripted = [];

    /** @param array<string, array<string, mixed>> $byUrl url => decoded JSON body */
    public function __construct(array $byUrl = [])
    {
        foreach ($byUrl as $url => $body) {
            $this->script($url, $body);
        }
    }

    public function script(string $url, array $body): self
    {
        $this->scripted[$url] = $body;

        return $this;
    }

    public function getJson(string $url, int $timeoutSeconds): ?array
    {
        $this->requestedUrls[] = $url;

        return $this->scripted[$url] ?? null;
    }
}
