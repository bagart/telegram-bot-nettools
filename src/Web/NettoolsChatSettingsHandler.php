<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Web;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotMenu\Contracts\TgWebApiHandlerContract;
use BAGArt\TelegramBotMenu\Manifest\ChatScope;
use BAGArt\TelegramBotMenu\Manifest\EffectiveRole;
use BAGArt\TelegramBotMenu\Support\TgWebApiRoute;
use BAGArt\TelegramBotMenu\Support\TgWebRequest;
use BAGArt\TelegramBotMenu\Support\TgWebResponse;
use BAGArt\TelegramBotNettools\Support\ChatSettings;

/**
 * webApi seam for the per-chat nettools overlay (menu_integration.md M-4):
 * the §8.3 hub settings writer persists bot-level module_settings, but these
 * keys are chat-scoped cache state, so they travel through a custom route
 * pair backed by {@see ChatSettings} — the same store the processors read.
 */
final readonly class NettoolsChatSettingsHandler implements TgWebApiHandlerContract
{
    public function __construct(private ?OutboundCacheContract $cache = null)
    {
    }
    /** @return list<TgWebApiRoute> */
    public static function routes(): array
    {
        return [
            new TgWebApiRoute('GET', 'chat-settings', EffectiveRole::Member, chatScope: ChatScope::Required),
            new TgWebApiRoute('PUT', 'chat-settings/apply', EffectiveRole::Admin, chatScope: ChatScope::Required),
        ];
    }

    public function handle(TgWebRequest $request, array $path): TgWebResponse
    {
        $context = $request->context;
        $chat = $context->chat;

        if ($path === ['chat-settings'] && $chat !== null) {
            return TgWebResponse::ok($this->settings()->raw($chat->id));
        }

        if (($path === ['chat-settings'] || $path === ['chat-settings', 'apply']) && $chat === null) {
            return TgWebResponse::error('chat_required', 'These settings apply to a chat.', 403, $request->requestId);
        }

        if ($path === ['chat-settings', 'apply']) {
            $patch = (new NettoolsWebUi())->validate($request->payload);
            $settings = $this->settings();
            if (isset($patch['detail_mode'])) {
                $settings->setDetailMode($chat->id, $patch['detail_mode']);
            }
            if (isset($patch['heavy_confirm'])) {
                $settings->setHeavyConfirm($chat->id, $patch['heavy_confirm']);
            }
            if (isset($patch['auto_capture'])) {
                $settings->setAutoCapture($chat->id, $patch['auto_capture']);
            }

            return TgWebResponse::ok($settings->raw($chat->id));
        }

        return TgWebResponse::error('not_found', 'Unknown nettools route.', 404, $request->requestId);
    }

    private function settings(): ChatSettings
    {
        // The dispatcher constructs handlers with no dependencies; resolve
        // the cache contract lazily from the container (tests pass it in).
        return ChatSettings::of($this->cache ?? app(OutboundCacheContract::class));
    }
}
