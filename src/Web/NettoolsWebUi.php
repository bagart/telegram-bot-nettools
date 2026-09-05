<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Web;

use BAGArt\TelegramBotMenu\Contracts\TgSettingsFormContract;
use BAGArt\TelegramBotMenu\Contracts\TgWebUiContract;
use BAGArt\TelegramBotMenu\Manifest\TgWebUiManifest;
use BAGArt\TelegramBotMenu\Manifest\UiAudience;
use BAGArt\TelegramBotMenu\Manifest\UiEntry;
use BAGArt\TelegramBotMenu\Manifest\UiField;
use BAGArt\TelegramBotMenu\Manifest\UiGroup;
use BAGArt\TelegramBotMenu\Manifest\UiKind;
use BAGArt\TelegramBotNettools\NettoolsModule;
use InvalidArgumentException;

/**
 * Menu-hub surface for nettools (menu_integration.md M-4): the per-chat UI
 * overlay keys — exactly the raw keys {@see \BAGArt\TelegramBotNettools\Support\ChatSettings}
 * persists — exposed as a §8.3 schema form. Engine toggles (recon/portscan/…)
 * stay in config('tg-nettools') until the enablement-settings seam lands
 * (G2/task 25 territory), so this form is deliberately overlay-only.
 */
final class NettoolsWebUi implements TgSettingsFormContract, TgWebUiContract
{
    public const array DETAIL_MODE_OPTIONS = ['compact', 'full'];

    public static function manifest(): TgWebUiManifest
    {
        return new TgWebUiManifest(
            moduleId: NettoolsModule::ID,
            title: 'Nettools',
            icon: '🛰',
            kind: UiKind::Tool,
            minAudience: UiAudience::User,
            description: 'Network probe toolkit for the chat',
            entry: UiEntry::schema([
                UiGroup::of('chat_ui', 'Chat output', [
                    UiField::enum('detail_mode', 'Probe report detail', options: [
                        ['value' => 'compact', 'label' => 'Compact'],
                        ['value' => 'full', 'label' => 'Full'],
                    ], default: 'compact'),
                    UiField::bool('heavy_confirm', 'Confirm heavy probes', default: true),
                    UiField::bool('auto_capture', 'Auto-capture results to target memory', default: true),
                ]),
            ]),
            sortKey: 'nettools',
            memberReadVisible: true,
        );
    }

    /** @return array<string, array<string, string>> */
    public static function translations(): array
    {
        return [
            'en' => [
                'nettools' => 'Nettools',
                'chat_ui' => 'Chat output',
                'detail_mode' => 'Probe report detail',
                'heavy_confirm' => 'Confirm heavy probes',
                'auto_capture' => 'Auto-capture results to target memory',
            ],
            'ru' => [
                'nettools' => 'Неттулзы',
                'chat_ui' => 'Вывод в чате',
                'detail_mode' => 'Детальность отчётов',
                'heavy_confirm' => 'Подтверждение тяжёлых проверок',
                'auto_capture' => 'Автосохранение результатов в память целей',
            ],
        ];
    }

    /**
     * Normalizes onto the ChatSettings overlay raw keys; anything else
     * (engine toggles, quotas) is rejected rather than silently mirrored.
     *
     * @param array<string, mixed> $raw
     * @return array<string, mixed>
     */
    public function validate(array $raw): array
    {
        $patch = [];

        if (array_key_exists('detail_mode', $raw)) {
            $mode = $raw['detail_mode'];
            if (! is_string($mode) || ! in_array($mode, self::DETAIL_MODE_OPTIONS, true)) {
                throw new InvalidArgumentException('detail_mode must be one of: '.implode(', ', self::DETAIL_MODE_OPTIONS));
            }
            $patch['detail_mode'] = $mode;
        }

        foreach (['heavy_confirm', 'auto_capture'] as $key) {
            if (array_key_exists($key, $raw)) {
                $value = $raw[$key];
                if (! is_bool($value)) {
                    if ($value === 'true' || $value === '1') {
                        $value = true;
                    } elseif ($value === 'false' || $value === '0') {
                        $value = false;
                    } else {
                        throw new InvalidArgumentException($key.' must be a boolean');
                    }
                }
                $patch[$key] = $value;
            }
        }

        return $patch;
    }

    public function isConfigured(array $settings): bool
    {
        return true;
    }
}
