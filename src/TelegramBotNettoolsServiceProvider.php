<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools;

use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;

final class TelegramBotNettoolsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/tg-nettools.php', 'tg-nettools');

        // Composer-installed module discovery (config/telegram.php contract)
        $providers = (array) Config::get('telegram.modules_providers', []);
        Config::set('telegram.modules_providers', array_values(array_unique(array_merge(
            $providers,
            [NettoolsModule::class],
        ))));
    }

    public function boot(): void
    {
        // Target-memory migrations ship together with /my (Phase 2.7).
    }
}
