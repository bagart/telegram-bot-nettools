<?php

declare(strict_types=1);

use BAGArt\TelegramBotMenu\Manifest\ChatScope;
use BAGArt\TelegramBotMenu\Manifest\EffectiveRole;
use BAGArt\TelegramBotMenu\Support\BotRef;
use BAGArt\TelegramBotMenu\Support\ChatRef;
use BAGArt\TelegramBotMenu\Support\ModuleRef;
use BAGArt\TelegramBotMenu\Support\TgUiContext;
use BAGArt\TelegramBotMenu\Support\TgWebRequest;
use BAGArt\TelegramBotMenu\Support\UserRef;
use BAGArt\TelegramBotMenu\Testing\TgWebUiContractTest;
use BAGArt\TelegramBotNettools\Support\ChatSettings;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use BAGArt\TelegramBotNettools\Web\NettoolsChatSettingsHandler;
use BAGArt\TelegramBotNettools\Web\NettoolsWebUi;

/**
 * menu_integration.md M-4: the per-chat overlay schema and its custom
 * route pair — the only module surface whose settings are chat-scoped
 * cache state (ChatSettings) rather than enablement module_settings.
 */
it('satisfies the TgWebUiContract shape for the nettools module', function () {
    TgWebUiContractTest::assertContractShape(NettoolsWebUi::class, 'nettools');
});

it('maps schema keys onto the ChatSettings overlay raw keys via validate', function () {
    $patch = (new NettoolsWebUi())->validate([
        'detail_mode' => 'full',
        'heavy_confirm' => 'false',
        'auto_capture' => true,
    ]);

    expect($patch)->toBe([
        'detail_mode' => 'full',
        'heavy_confirm' => false,
        'auto_capture' => true,
    ]);
});

it('rejects unknown detail modes, non-boolean flags and unrelated keys', function () {
    $form = new NettoolsWebUi();

    expect(fn () => $form->validate(['detail_mode' => 'verbose']))
        ->toThrow(InvalidArgumentException::class)
        ->and(fn () => $form->validate(['heavy_confirm' => 'maybe']))
        ->toThrow(InvalidArgumentException::class)
        ->and($form->validate(['portscanEnabled' => true]))->toBe([]);
});

it('declares a member read route and an admin apply route', function () {
    $routes = NettoolsChatSettingsHandler::routes();

    expect($routes)->toHaveCount(2)
        ->and($routes[0]->method)->toBe('GET')
        ->and($routes[0]->path)->toBe('chat-settings')
        ->and($routes[0]->minRole)->toBe(EffectiveRole::Member)
        ->and($routes[1]->method)->toBe('PUT')
        ->and($routes[1]->path)->toBe('chat-settings/apply')
        ->and($routes[1]->minRole)->toBe(EffectiveRole::Admin);

    foreach ($routes as $route) {
        expect($route->chatScope)->toBe(ChatScope::Required);
    }
});

it('applies a validated patch into ChatSettings and answers with the overlay', function () {
    $cache = FakeOutboundCacheFactory::create();

    $handler = new NettoolsChatSettingsHandler($cache);
    $response = $handler->handle(nettoolsWebRequest(900, payload: [
        'detail_mode' => 'full',
        'auto_capture' => false,
    ]), ['chat-settings', 'apply']);

    expect($response->status)->toBe(200)
        ->and($response->body['data']['detail_mode'])->toBe('full')
        ->and($response->body['data']['auto_capture'])->toBeFalse()
        ->and($response->body['data']['heavy_confirm'])->toBeNull();

    // The same store the processors read — verify via a fresh ChatSettings.
    $raw = ChatSettings::of($cache)->raw(900);
    expect($raw['detail_mode'])->toBe('full')
        ->and($raw['auto_capture'])->toBeFalse();
});

it('answers 404 for unknown routes', function () {
    $response = (new NettoolsChatSettingsHandler())
        ->handle(nettoolsWebRequest(900), ['unknown']);

    expect($response->status)->toBe(404)
        ->and($response->body['error']['code'])->toBe('not_found');
});

it('refuses chatless requests even if the dispatcher is bypassed', function () {
    $handler = new NettoolsChatSettingsHandler();

    $read = $handler->handle(nettoolsWebRequest(null), ['chat-settings']);
    $apply = $handler->handle(nettoolsWebRequest(null), ['chat-settings', 'apply']);

    expect($read->status)->toBe(403)->and($read->body['error']['code'])->toBe('chat_required')
        ->and($apply->status)->toBe(403)->and($apply->body['error']['code'])->toBe('chat_required');
});

function nettoolsWebRequest(?int $chatId, array $payload = []): TgWebRequest
{
    $context = new TgUiContext(
        bot: new BotRef('7004', 'nettoolsbot'),
        chat: $chatId === null ? null : new ChatRef($chatId, 'Nettools HQ', 'supergroup'),
        module: new ModuleRef('nettools'),
        role: EffectiveRole::Admin,
        user: new UserRef(42, 'Admin', 'en'),
    );

    return new TgWebRequest(
        botId: '7004',
        tgUserId: 42,
        role: EffectiveRole::Admin,
        chatId: $chatId,
        locale: 'en',
        payload: $payload,
        requestId: 'req-1',
        context: $context,
    );
}
