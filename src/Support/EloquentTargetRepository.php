<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\TargetRepositoryContract;
use BAGArt\TelegramBotNettools\Models\TgNettoolsTarget;

/**
 * Eloquent-backed repository (production binding). Habit deltas use a single
 * SQL UPDATE with json_set-style arithmetic via the model's casts — kept
 * race-safe by row-level uniqueness on (user_id, host).
 */
final class EloquentTargetRepository implements TargetRepositoryContract
{
    public function upsert(int $userId, string $host): bool
    {
        /** @var TgNettoolsTarget|null $row */
        $row = TgNettoolsTarget::query()->where('user_id', $userId)->where('host', $host)->first();

        if ($row === null) {
            TgNettoolsTarget::query()->create([
                'user_id' => $userId,
                'host' => $host,
                'use_count' => 1,
                'habits' => [],
                'last_used_at' => \Illuminate\Support\Carbon::now(),
            ]);

            return true;
        }

        $row->use_count += 1;
        $row->last_used_at = \Illuminate\Support\Carbon::now();
        $row->save();

        return false;
    }

    public function bumpHabit(int $userId, string $host, string $probe): void
    {
        /** @var TgNettoolsTarget|null $row */
        $row = TgNettoolsTarget::query()->where('user_id', $userId)->where('host', $host)->first();
        if ($row === null) {
            return;
        }

        $habits = (array) $row->habits;
        $habits[$probe] = ((int) ($habits[$probe] ?? 0)) + 1;
        $row->habits = $habits;
        $row->save();
    }

    public function setLabel(int $userId, string $host, ?string $label): void
    {
        TgNettoolsTarget::query()
            ->where('user_id', $userId)->where('host', $host)
            ->update(['label' => $label]);
    }

    public function setPinned(int $userId, string $host, bool $pinned): void
    {
        TgNettoolsTarget::query()
            ->where('user_id', $userId)->where('host', $host)
            ->update(['pinned' => $pinned]);
    }

    public function forget(int $userId, string $host): void
    {
        TgNettoolsTarget::query()
            ->where('user_id', $userId)->where('host', $host)
            ->delete();
    }

    public function clearAll(int $userId): void
    {
        TgNettoolsTarget::query()->where('user_id', $userId)->delete();
    }

    public function evictBeyond(int $userId, int $cap): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, TgNettoolsTarget> $rows */
        $rows = TgNettoolsTarget::query()
            ->where('user_id', $userId)
            ->orderByDesc('pinned')
            ->orderBy('last_used_at')
            ->get();

        if ($rows->count() <= $cap) {
            return [];
        }

        $excess = $rows->slice($cap)->filter(static fn (TgNettoolsTarget $row): bool => ! $row->pinned);

        foreach ($excess as $row) {
            $row->delete();
        }

        return $excess->pluck('host')->all();
    }

    public function forUser(int $userId): array
    {
        /** @var \Illuminate\Database\Eloquent\Collection<int, TgNettoolsTarget> $rows */
        $rows = TgNettoolsTarget::query()
            ->where('user_id', $userId)
            ->orderByDesc('last_used_at')
            ->get();

        return $rows
            ->map(static fn (TgNettoolsTarget $row): array => [
                'host' => $row->host,
                'label' => $row->label,
                'pinned' => (bool) $row->pinned,
                'use_count' => (int) $row->use_count,
                'habits' => (array) $row->habits,
                'last_used_at' => $row->last_used_at?->getTimestamp(),
            ])
            ->all();
    }
}
