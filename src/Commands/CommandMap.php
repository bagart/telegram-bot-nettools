<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

/**
 * Single mapping of command name → repeatable probe-command class.
 * Shared by /r, the form continuation processor and the callback router
 * so every dispatch path resolves commands identically.
 */
final class CommandMap
{
    /** @var array<string, class-string<ProbeCommand>> */
    public const array MAP = [
        IpCommand::NAME => IpCommand::class,
        GeoCommand::NAME => GeoCommand::class,
        WhoisCommand::NAME => WhoisCommand::class,
        DnsCommand::NAME => DnsCommand::class,
        PingCommand::NAME => PingCommand::class,
        TraceCommand::NAME => TraceCommand::class,
        HttpCommand::NAME => HttpCommand::class,
        PortCommand::NAME => PortCommand::class,
        AsnCommand::NAME => AsnCommand::class,
        SubsCommand::NAME => SubsCommand::class,
        MailCommand::NAME => MailCommand::class,
        SslCommand::NAME => SslCommand::class,
        SecCommand::NAME => SecCommand::class,
        OsCommand::NAME => OsCommand::class,
        RecoCommand::NAME => RecoCommand::class,
        ReportCommand::NAME => ReportCommand::class,
    ];

    /** @return class-string<ProbeCommand>|null */
    public static function byName(string $command): ?string
    {
        return self::MAP[$command] ?? null;
    }
}
