<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools;

use BAGArt\TelegramBotNettools\Contracts\TargetRepositoryContract;
use BAGArt\TelegramBotNettools\Support\EloquentTargetRepository;
use Illuminate\Support\ServiceProvider;

final class TelegramBotNettoolsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/tg-nettools.php', 'tg-nettools');

        // Hub web surface (menu_integration.md M-4): the resource provider and
        // the webApi handler resolve the repository through this binding.
        $this->app->singleton(TargetRepositoryContract::class, EloquentTargetRepository::class);
    }

    public function boot(): void
    {
        // Target-memory migrations ship together with /my (Phase 2.7).
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }
}
