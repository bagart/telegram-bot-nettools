<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\TargetRepositoryContract;
use BAGArt\TelegramBotNettools\NettoolsSettings;

/**
 * Target-memory orchestration (RFC §3.7): auto-capture after successful
 * probes, habit bumping, LRU eviction with pinned exemption. Storage is the
 * repository seam — Eloquent in production, in-memory in tests.
 */
final class TargetMemoryService
{
    public function __construct(
        private readonly TargetRepositoryContract $repository,
        private readonly NettoolsSettings $settings,
    ) {
    }

    /** Auto-capture + habit delta; no-ops when memory/auto-capture disabled. */
    public function recordUse(int|string|null $userId, string $host, string $probe): void
    {
        if (! $this->settings->memoryEnabled || $userId === null) {
            return;
        }

        $id = (int) $userId;
        $this->repository->upsert($id, $host);
        $this->repository->bumpHabit($id, $host, $probe);
        $this->repository->evictBeyond($id, $this->settings->maxTargets);
    }

    /**
     * Probe buttons for a target context menu: user's habits first (by count),
     * then the default order.
     *
     * @param  list<string>  $defaultOrder
     * @return list<string>
     */
    public function rankedProbes(int|string|null $userId, string $host, array $defaultOrder): array
    {
        if ($userId === null || ! $this->settings->memoryEnabled) {
            return $defaultOrder;
        }

        $habits = [];
        foreach ($this->repository->forUser((int) $userId) as $row) {
            if ($row['host'] === $host) {
                $habits = $row['habits'];
                break;
            }
        }

        arsort($habits);

        $ranked = [];
        foreach (array_keys(array_filter($habits)) as $probe) {
            if (in_array($probe, $defaultOrder, true)) {
                $ranked[] = $probe;
            }
        }

        return [...$ranked, ...array_diff($defaultOrder, $ranked)];
    }

    /** @return list<array{host:string,label:?string,pinned:bool,use_count:int,last_used_at:?int}> */
    public function list(int|string $userId): array
    {
        return array_map(static fn (array $r): array => [
            'host' => $r['host'],
            'label' => $r['label'],
            'pinned' => $r['pinned'],
            'use_count' => $r['use_count'],
            'last_used_at' => $r['last_used_at'],
        ], $this->repository->forUser((int) $userId));
    }

    public function pin(int|string $userId, string $host, bool $pinned): void
    {
        $this->repository->setPinned((int) $userId, $host, $pinned);
    }

    public function forget(int|string $userId, string $host): void
    {
        $this->repository->forget((int) $userId, $host);
    }

    public function clearAll(int|string $userId): void
    {
        $this->repository->clearAll((int) $userId);
    }
}
