<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts;

/**
 * Storage seam for target memory (RFC §3.7). Production binds the Eloquent
 * repository; tests bind an in-memory one. All habit/usage mutations are
 * single-user operations keyed by (user_id, host).
 */
interface TargetRepositoryContract
{
    /** Insert-or-update last_used_at + use_count+1. Returns true when created. */
    public function upsert(int $userId, string $host): bool;

    /** Atomic habits.{probe} +1 (JSON delta). */
    public function bumpHabit(int $userId, string $host, string $probe): void;

    public function setLabel(int $userId, string $host, ?string $label): void;

    public function setPinned(int $userId, string $host, bool $pinned): void;

    public function forget(int $userId, string $host): void;

    public function clearAll(int $userId): void;

    /**
     * LRU eviction: unpinned targets beyond $cap evicted oldest-first.
     *
     * @return list<string> evicted hosts
     */
    public function evictBeyond(int $userId, int $cap): array;

    /**
     * @return list<array{host: string, label: ?string, pinned: bool, use_count: int, habits: array<string, int>, last_used_at: ?int}>
     */
    public function forUser(int $userId): array;
}
