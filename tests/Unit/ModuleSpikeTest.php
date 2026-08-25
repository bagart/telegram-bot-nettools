<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBot\Modules\AttributedComponentsScanner;
use BAGArt\TelegramBot\Modules\TgCommandRegistry;
use BAGArt\TelegramBot\Modules\TypedModuleRegistrar;
use BAGArt\TelegramBot\Processing\TypeDTOProcessorRegistry;
use BAGArt\TelegramBotNettools\Commands\DnsCommand;
use BAGArt\TelegramBotNettools\Commands\NtCallbackRouter;
use BAGArt\TelegramBotNettools\Commands\NtCommand;
use BAGArt\TelegramBotNettools\Commands\QuotaCommand;
use BAGArt\TelegramBotNettools\Commands\WhoisCommand;
use BAGArt\TelegramBotNettools\NettoolsModule;
use PHPUnit\Framework\TestCase;

/**
 * Phase 0.5 framework spike: NettoolsModule::register() via
 * registerAttributed() must discover and register every attributed component
 * of the module's src/ tree.
 */
final class ModuleSpikeTest extends TestCase
{
    public function test_descriptor_ships_disabled_and_fail_closed(): void
    {
        $descriptor = NettoolsModule::descriptor();

        self::assertSame('nettools', $descriptor->id);
        self::assertFalse($descriptor->defaultEnabled);
        self::assertTrue($descriptor->failClosed);
    }

    public function test_attributed_scan_registers_commands_and_callback_router(): void
    {
        $commandRegistry = new TgCommandRegistry();
        $processorRegistry = new TypeDTOProcessorRegistry();

        $registrar = new TypedModuleRegistrar(
            processorRegistry: $processorRegistry,
            commandRegistry: $commandRegistry,
            attributedScanner: new AttributedComponentsScanner(cache: null),
        );

        NettoolsModule::register($registrar);

        self::assertTrue($commandRegistry->has('nt'));
        self::assertSame(NtCommand::class, $commandRegistry->processorOf('nt'));
        self::assertTrue($commandRegistry->has('quota'));
        self::assertSame(QuotaCommand::class, $commandRegistry->processorOf('quota'));
        self::assertTrue($commandRegistry->has('whois'));
        self::assertSame(WhoisCommand::class, $commandRegistry->processorOf('whois'));
        self::assertTrue($commandRegistry->has('dns'));
        self::assertSame(DnsCommand::class, $commandRegistry->processorOf('dns'));
    }

    public function test_command_names_parse_from_text(): void
    {
        self::assertSame('nt', TgCommandRegistry::parseCommandName('/nt'));
        self::assertSame('nt', TgCommandRegistry::parseCommandName('/nt@my_bot help'));
        self::assertSame('nthelp', TgCommandRegistry::parseCommandName('/nthelp'));
        self::assertNull(TgCommandRegistry::parseCommandName('plain text'));
    }

    public function test_module_ids_are_consistent(): void
    {
        self::assertSame(NettoolsModule::ID, NtCommand::moduleId());
        self::assertSame(NettoolsModule::ID, QuotaCommand::moduleId());
        self::assertSame(NettoolsModule::ID, WhoisCommand::moduleId());
        self::assertSame(NettoolsModule::ID, DnsCommand::moduleId());
        self::assertSame(NettoolsModule::ID, NtCallbackRouter::moduleId());
    }
}
