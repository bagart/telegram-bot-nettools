<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * Target memory row (RFC §3.7): one host per user with habit counters.
 *
 * @property int $id
 * @property int $user_id
 * @property string $host
 * @property string|null $label
 * @property bool $pinned
 * @property int $use_count
 * @property array<string, int> $habits
 * @property \Illuminate\Support\Carbon|null $last_used_at
 */
final class TgNettoolsTarget extends Model
{
    protected $table = 'tg_nettools_targets';

    protected $fillable = [
        'user_id',
        'host',
        'label',
        'pinned',
        'use_count',
        'habits',
        'last_used_at',
    ];

    protected $casts = [
        'pinned' => 'boolean',
        'use_count' => 'integer',
        'habits' => 'array',
        'last_used_at' => 'datetime',
    ];
}
