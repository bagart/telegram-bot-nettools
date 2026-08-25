<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\AsyncKernel\Contracts\ASKLockerContract;

final class FakeLocker implements ASKLockerContract
{
    /** @var array<string, string|null> lockKey => owner */
    private array $locks = [];

    public function acquire(string $key): bool
    {
        if (array_key_exists($key, $this->locks)) {
            return false;
        }
        $this->locks[$key] = null;

        return true;
    }

    public function release(string $key): void
    {
        unset($this->locks[$key]);
    }

    public function acquireWithTtl(string $key, int $ttlSec, ?string $owner = null): bool
    {
        if (array_key_exists($key, $this->locks)) {
            return false;
        }
        $this->locks[$key] = $owner;

        return true;
    }

    public function releaseWithOwner(string $key, ?string $owner = null): void
    {
        if (! array_key_exists($key, $this->locks)) {
            return;
        }
        if ($owner !== null && $this->locks[$key] !== null && $this->locks[$key] !== $owner) {
            return;
        }
        unset($this->locks[$key]);
    }

    public function isLocked(string $key): bool
    {
        return array_key_exists($key, $this->locks);
    }

    /** @internal test helper: force a foreign lock */
    public function forceLock(string $key, string $owner): void
    {
        $this->locks[$key] = $owner;
    }
}
