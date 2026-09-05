<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Web;

use BAGArt\TelegramBotMenu\Contracts\TgResourceProviderContract;
use BAGArt\TelegramBotMenu\Manifest\EffectiveRole;
use BAGArt\TelegramBotMenu\Support\TgResourceItem;
use BAGArt\TelegramBotMenu\Support\TgResourceMeta;
use BAGArt\TelegramBotMenu\Support\TgResourcePage;
use BAGArt\TelegramBotMenu\Support\TgResourceQuery;
use BAGArt\TelegramBotMenu\Support\TgResourceSelection;
use BAGArt\TelegramBotMenu\Support\TgUiContext;
use BAGArt\TelegramBotNettools\Contracts\TargetRepositoryContract;

/**
 * Target-memory resource provider (menu_integration.md M-4, closes G6): the
 * per-user target memory behind the hub's generic picker sheet. Scoping is
 * normative (D39): every read and every validate() verdict is filtered by
 * $context->user — a target owned by another Telegram user never leaks.
 */
final readonly class NettoolsTargetsResource implements TgResourceProviderContract
{
    public function __construct(
        private TargetRepositoryContract $targets,
    ) {}

    public static function domain(): string
    {
        return 'nettools.targets';
    }

    public static function meta(): TgResourceMeta
    {
        return new TgResourceMeta(
            title: 'Probe targets',
            icon: '🎯',
            minRole: EffectiveRole::Member,
            pagination: true,
            sortable: true,
        );
    }

    public function search(TgResourceQuery $query, TgUiContext $context): TgResourcePage
    {
        $rows = $this->targets->forUser($context->user->id);

        $q = mb_strtolower($query->q);
        $items = [];

        foreach ($rows as $row) {
            if ($q !== '' && ! str_contains(mb_strtolower($row['host'].' '.strval($row['label'] ?? '')), $q)) {
                continue;
            }

            $items[] = new TgResourceItem(
                id: $row['host'],
                label: $row['label'] ?? $row['host'],
                hint: sprintf('%d uses%s', $row['use_count'], $row['pinned'] ? ' · pinned' : ''),
                icon: $row['pinned'] ? '📌' : null,
            );
        }

        usort($items, static fn (TgResourceItem $a, TgResourceItem $b) => strcasecmp($a->label, $b->label));

        $cursor = intval($query->cursor ?? 0);
        $page = array_slice($items, $cursor, $query->limit);
        $next = ($cursor + $query->limit) < count($items)
            ? strval($cursor + $query->limit)
            : null;

        return new TgResourcePage($page, $next);
    }

    public function validate(array $ids, TgUiContext $context): TgResourceSelection
    {
        $owned = [];

        foreach ($this->targets->forUser($context->user->id) as $row) {
            $owned[$row['host']] = true;
        }

        $verdicts = [];

        foreach ($ids as $id) {
            $verdicts[$id] = isset($owned[$id])
                ? ['valid' => true]
                : ['valid' => false, 'reason' => 'Not in your target memory.'];
        }

        return new TgResourceSelection($verdicts);
    }
}
