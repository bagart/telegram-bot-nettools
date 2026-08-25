<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\TargetRepositoryContract;

/**
 * In-memory repository for tests and cache-only deployments; mirrors the
 * Eloquent repository semantics (upsert, pinned-exempt LRU eviction).
 */
final class InMemoryTargetRepository implements TargetRepositoryContract
{
    /** @var array<int, array<string, array{host:string,label:?string,pinned:bool,use_count:int,habits:array<string,int>,last_used_at:?int}>> */
    public array $rows = [];

    public function upsert(int $userId, string $host): bool
    {
        if (! isset($this->rows[$userId][$host])) {
            $this->rows[$userId][$host] = [
                'host' => $host,
                'label' => null,
                'pinned' => false,
                'use_count' => 0,
                'habits' => [],
                'last_used_at' => null,
            ];
        }

        $row = &$this->rows[$userId][$host];

        $created = $row['use_count'] === 0;
        $row['use_count']++;
        $row['last_used_at'] = time();

        return $created;
    }

    public function bumpHabit(int $userId, string $host, string $probe): void
    {
        if (! isset($this->rows[$userId][$host])) {
            return;
        }

        $habits = $this->rows[$userId][$host]['habits'];
        $habits[$probe] = ((int) ($habits[$probe] ?? 0)) + 1;
        $this->rows[$userId][$host]['habits'] = $habits;
    }

    public function setLabel(int $userId, string $host, ?string $label): void
    {
        if (isset($this->rows[$userId][$host])) {
            $this->rows[$userId][$host]['label'] = $label;
        }
    }

    public function setPinned(int $userId, string $host, bool $pinned): void
    {
        if (isset($this->rows[$userId][$host])) {
            $this->rows[$userId][$host]['pinned'] = $pinned;
        }
    }

    public function forget(int $userId, string $host): void
    {
        unset($this->rows[$userId][$host]);
    }

    public function clearAll(int $userId): void
    {
        unset($this->rows[$userId]);
    }

    public function evictBeyond(int $userId, int $cap): array
    {
        $rows = $this->rows[$userId] ?? [];

        usort($rows, static fn (array $a, array $b): int => [$b['pinned'], $a['last_used_at'] ?? 0]
            <=> [$a['pinned'], $b['last_used_at'] ?? 0]);

        $evicted = [];
        foreach (array_slice($rows, $cap) as $row) {
            if ($row['pinned']) {
                continue;
            }
            unset($this->rows[$userId][$row['host']]);
            $evicted[] = $row['host'];
        }

        return $evicted;
    }

    public function forUser(int $userId): array
    {
        $rows = array_values($this->rows[$userId] ?? []);

        usort($rows, static fn (array $a, array $b): int => ($b['last_used_at'] ?? 0) <=> ($a['last_used_at'] ?? 0));

        return array_map(static fn (array $r): array => [
            ...$r,
            'habits' => $r['habits'],
        ], $rows);
    }
}
