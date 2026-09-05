<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Web;

use BAGArt\TelegramBotMenu\Contracts\TgWebApiHandlerContract;
use BAGArt\TelegramBotMenu\Manifest\ChatScope;
use BAGArt\TelegramBotMenu\Manifest\EffectiveRole;
use BAGArt\TelegramBotMenu\Support\TgWebApiRoute;
use BAGArt\TelegramBotMenu\Support\TgWebRequest;
use BAGArt\TelegramBotMenu\Support\TgWebResponse;
use BAGArt\TelegramBotNettools\Contracts\TargetRepositoryContract;

/**
 * Read-only dashboard data for the hub (menu_integration.md M-4): the
 * caller's target memory. Identity comes ONLY from the injected TgUiContext
 * (G9). The dispatcher constructs handlers with no arguments (§8.4 contract
 * freeze), so the container-resolved repository is fetched lazily at
 * request time. Mutations (forget/pin/label) stay in the in-chat /nt panel
 * until the module's write surface is designed.
 */
final readonly class NettoolsUiHandler implements TgWebApiHandlerContract
{
    /** @return list<TgWebApiRoute> */
    public static function routes(): array
    {
        return [
            new TgWebApiRoute('GET', 'targets', EffectiveRole::Member, chatScope: ChatScope::Optional),
        ];
    }

    public function handle(TgWebRequest $request, array $path): TgWebResponse
    {
        if ($path !== ['targets']) {
            return TgWebResponse::error('not_found', 'Unknown nettools route.', 404, $request->requestId);
        }

        $items = app(TargetRepositoryContract::class)->forUser($request->context->user->id);

        return TgWebResponse::ok(['items' => $items]);
    }
}
