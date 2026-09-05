<?php

declare(strict_types=1);

use BAGArt\TelegramBotMenu\Manifest\EffectiveRole;
use BAGArt\TelegramBotMenu\Support\BotRef;
use BAGArt\TelegramBotMenu\Support\ChatRef;
use BAGArt\TelegramBotMenu\Support\ModuleRef;
use BAGArt\TelegramBotMenu\Support\TgResourceQuery;
use BAGArt\TelegramBotMenu\Support\TgUiContext;
use BAGArt\TelegramBotMenu\Support\UserRef;
use BAGArt\TelegramBotNettools\Support\InMemoryTargetRepository;
use BAGArt\TelegramBotNettools\Web\NettoolsTargetsResource;

/**
 * menu_integration.md M-4: target-memory resource provider. Scoping is
 * normative (D39) — every verdict is filtered against $context->user.
 */
it('exposes a module-scoped resource domain and member-readable meta', function () {
    expect(NettoolsTargetsResource::domain())->toBe('nettools.targets')
        ->and(NettoolsTargetsResource::meta()->minRole)->toBe(EffectiveRole::Member);
});

it('searches only the context user targets', function () {
    $repo = new InMemoryTargetRepository;
    $repo->upsert(1, 'example.com');
    $repo->upsert(1, 'github.com');
    $repo->upsert(2, 'secret.internal');

    $provider = new NettoolsTargetsResource($repo);
    $page = $provider->search(new TgResourceQuery(q: ''), nettoolsContext(1));

    expect(array_map(static fn ($item) => $item->id, $page->items))
        ->toBe(['example.com', 'github.com']);
});

it('filters by query text across host and label', function () {
    $repo = new InMemoryTargetRepository;
    $repo->upsert(1, 'example.com');
    $repo->upsert(1, 'github.com');
    $repo->setPinned(1, 'github.com', true);
    $repo->setLabel(1, 'github.com', 'My repos');

    $provider = new NettoolsTargetsResource($repo);
    $page = $provider->search(new TgResourceQuery(q: 'repos'), nettoolsContext(1));

    expect(array_map(static fn ($item) => $item->id, $page->items))->toBe(['github.com']);
});

it('validates membership and rejects foreign hosts', function () {
    $repo = new InMemoryTargetRepository;
    $repo->upsert(1, 'example.com');
    $repo->upsert(2, 'secret.internal');

    $verdicts = (new NettoolsTargetsResource($repo))
        ->validate(['example.com', 'secret.internal'], nettoolsContext(1))
        ->verdicts;

    expect($verdicts['example.com']['valid'])->toBeTrue()
        ->and($verdicts['secret.internal']['valid'])->toBeFalse();
});

function nettoolsContext(int $userId): TgUiContext
{
    return new TgUiContext(
        bot: new BotRef('7004', 'nettoolsbot'),
        chat: new ChatRef(900, 'Nettools HQ', 'private'),
        module: new ModuleRef('nettools'),
        role: EffectiveRole::Member,
        user: new UserRef($userId, 'Member', 'en'),
    );
}
