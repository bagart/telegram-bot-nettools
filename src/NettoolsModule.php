<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools;

use BAGArt\TelegramBot\Modules\TgModuleCapability;
use BAGArt\TelegramBot\Modules\TgModuleContract;
use BAGArt\TelegramBot\Modules\TgModuleDescriptor;
use BAGArt\TelegramBot\Modules\TgModuleRegistrar;

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
            ],
            defaultEnabled: false,
            failClosed: true,
        );
    }

    public static function register(TgModuleRegistrar $registrar): void
    {
        $registrar->registerAttributed(self::class);
    }
}
