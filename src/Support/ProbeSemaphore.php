<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\AsyncKernel\Contracts\ASKLockerContract;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\SemaphoreBusyException;

/**
 * Global heavy-probe semaphore (RFC D1): one blocking probe at a time per
 * worker instance. TTL = cap + grace, so a crashed holder cannot deadlock it;
 * contended callers get an instant "busy, retry in ~Ns" — never queued.
 */
final class ProbeSemaphore
{
    private const string KEY = 'tg-nettools:heavy';

    private const int GRACE_SECONDS = 5;

    private ?string $owner = null;

    public function __construct(
        private readonly ASKLockerContract $locker,
    ) {
    }

    /**
     * @param  int  $capSeconds  worst-case probe wall time (its hard cap)
     *
     * @throws SemaphoreBusyException
     */
    public function acquire(int $capSeconds): void
    {
        $this->owner ??= bin2hex(random_bytes(8));

        $ttl = max(1, $capSeconds) + self::GRACE_SECONDS;

        if (! $this->locker->acquireWithTtl(self::KEY, $ttl, $this->owner)) {
            throw new SemaphoreBusyException($ttl);
        }
    }

    /** Idempotent — safe to call in a finally block without prior acquire. */
    public function release(): void
    {
        if ($this->owner === null) {
            return;
        }

        $this->locker->releaseWithOwner(self::KEY, $this->owner);
        $this->owner = null;
    }
}
