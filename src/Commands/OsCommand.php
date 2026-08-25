<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\Probes\OsHeuristicProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\OsCard;
use Throwable;

/**
 * /os <host> (RFC §7.10): heuristic stack fingerprint from cached-or-fresh
 * ping TTLs, HTTP banner and TLS ALPN. Confidence labels mandatory. Weight 2.
 */
#[TgCommandAttribute(name: 'os')]
final class OsCommand extends ProbeCommand
{
    public const string NAME = 'os';

    public const int WEIGHT = 2;

    protected function featureEnabled(\BAGArt\TelegramBotNettools\NettoolsSettings $settings): bool
    {
        return $settings->activeEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        $s = $this->services;
        $ping = $s->pingProbe();
        $http = $s->httpProbe();
        $tls = new \BAGArt\TelegramBotNettools\Probes\SslProbe(\BAGArt\TelegramBotNettools\Probes\SslProbe::selfInspector());

        $signals = [
            static fn (NetTarget $t): ?array => self::safe(static fn (): ?array
                => OsHeuristicProbe::pingSignal($ping->probe($t, new ProbeOptions(timeoutSeconds: 3))->payload)),
            static fn (NetTarget $t): ?array => self::safe(static function () use ($http, $t): ?array {
                $payload = $http->probe($t, new ProbeOptions(timeoutSeconds: 4))->payload;

                return OsHeuristicProbe::httpBannerSignal(
                    isset($payload['server']) && is_string($payload['server']) ? $payload['server'] : null,
                    isset($payload['x_powered_by']) && is_string($payload['x_powered_by']) ? $payload['x_powered_by'] : null,
                );
            }),
            static fn (NetTarget $t): ?array => self::safe(static fn (): ?array
                => OsHeuristicProbe::tlsAlpnSignal((array) ($tls->probe($t, new ProbeOptions(timeoutSeconds: 3))->payload['alpn'] ?? []))),
        ];

        return [new OsHeuristicProbe($signals), new ProbeOptions(timeoutSeconds: 10)];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return OsCard::render($result, $chatId, time(), $hostLabel);
    }

    /** @return array{kind:string, guesses:list<array{family:string, detail:string}>}|null */
    private static function safe(\Closure $call): ?array
    {
        try {
            return $call();
        } catch (Throwable) {
            return null;
        }
    }
}
