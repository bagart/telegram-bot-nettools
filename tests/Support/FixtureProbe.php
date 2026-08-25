<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\NxDomainException;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

final class FixtureProbe implements NettoolsProbeContract
{
    public function __construct(
        private readonly int $ttl,
    ) {
    }

    public function name(): string
    {
        return 'fixture';
    }

    public function ttlSeconds(): int
    {
        return $this->ttl;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        throw new NxDomainException($target->host);
    }
}
