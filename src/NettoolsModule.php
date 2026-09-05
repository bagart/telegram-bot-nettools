<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools;

use BAGArt\TelegramBot\Modules\TgModuleCapability;
use BAGArt\TelegramBot\Modules\TgModuleContract;
use BAGArt\TelegramBot\Modules\TgModuleDescriptor;
use BAGArt\TelegramBot\Modules\TgModuleRegistrar;
use BAGArt\TelegramBotNettools\Web\NettoolsChatSettingsHandler;
use BAGArt\TelegramBotNettools\Web\NettoolsTargetsResource;
use BAGArt\TelegramBotNettools\Web\NettoolsUiHandler;
use BAGArt\TelegramBotNettools\Web\NettoolsWebUi;

/**
 * Nettools platform module: auditor/admin toolkit (whois/RDAP, DNS, geo/ASN,
 * ping/trace, TLS/mail/security audits, /report + /reco).
 *
 * Ships DISABLED per bot and fail-closed: on enablement-storage DB errors the
 * module is treated as disabled (RFC D4) — a stolen token must not gain a
 * network-reconnaissance surface by accident.
 *
 * All components are declared via #[TgCommand] attributes — this module is
 * the first production consumer of registerAttributed() (RFC Phase 0.5).
 */
final class NettoolsModule implements TgModuleContract
{
    public const string ID = 'nettools';

    public const string VERSION = '0.1.0';

    public static function descriptor(): TgModuleDescriptor
    {
        return new TgModuleDescriptor(
            id: self::ID,
            name: 'Nettools',
            version: self::VERSION,
            capabilities: [
                TgModuleCapability::Processor,
                TgModuleCapability::Command,
                TgModuleCapability::Ui,
            ],
            defaultEnabled: false,
            failClosed: true,
        );
    }

    public static function register(TgModuleRegistrar $registrar): void
    {
        $registrar->registerAttributed(self::class);
        // Hub web surface (menu_integration.md M-4): target-memory picker data,
        // read-only dashboard endpoints and the per-chat overlay schema. The
        // §8.3 form covers ChatSettings overlay keys only — engine toggles
        // stay in config('tg-nettools') until the enablement-settings seam.
        $registrar->webUi(NettoolsWebUi::class);
        $registrar->webApi(NettoolsUiHandler::class);
        $registrar->webApi(NettoolsChatSettingsHandler::class);
        $registrar->webResource(NettoolsTargetsResource::class);
    }
}
