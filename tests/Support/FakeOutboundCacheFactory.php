<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\AsyncKernel\Wrappers\ASKCacheWrapper;
use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBot\Outbound\Adapters\KernelCacheAdapter;

/**
 * Platform KernelCacheAdapter over in-memory primitives — same serial-section
 * incrementWithTtl semantics as single-process production.
 */
final class FakeOutboundCacheFactory
{
    public static function create(): OutboundCacheContract
    {
        return new KernelCacheAdapter(
            new ASKCacheWrapper(new ArrayCache()),
            new FakeLocker(),
        );
    }
}
