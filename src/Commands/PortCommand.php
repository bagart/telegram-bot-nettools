<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\PortProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\PortCard;

/**
 * /port <host> <port> (RFC §7.14): single TCP reachability from outside —
 * open/closed/filtered + latency + banner excerpt. Rate-limited 20/h/user.
 * Weight 1.
 */
#[TgCommandAttribute(name: 'port')]
final class PortCommand extends ProbeCommand
{
    public const string NAME = 'port';

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->activeEnabled;
    }

    /** @return array{0: PortProbe, 1: ProbeOptions} */
    protected function probeFor(NetTarget $target): array
    {
        return [
            new PortProbe($this->port ?? 443),
            new ProbeOptions(timeoutSeconds: PortProbe::CONNECT_TIMEOUT_SECONDS),
        ];
    }

    protected function beforeRun(NetTarget $target, bool $confirmed, string $chatId): ?array
    {
        if ($this->port === null || $this->port < 1 || $this->port > 65535) {
            return [
                'text' => Messages::format('invalid_port', ['input' => (string) ($this->rawPort ?? '')]),
                'keyboard' => [],
            ];
        }

        if (! $this->services->rateLimiter()->hit(
            'port',
            $chatId,
            $this->callerUserId,
            $this->effSettings->portRatePerHour,
            3600,
        )) {
            return [
                'text' => Messages::format('port_rate_limited', [
                    'limit' => $this->effSettings->portRatePerHour,
                ]),
                'keyboard' => [],
            ];
        }

        return null;
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return PortCard::render($result, $chatId, time(), $hostLabel);
    }

    protected function parseArgs(string $argsRaw): string
    {
        [$host, $port] = array_pad(preg_split('/[\s:]+/', trim($argsRaw)) ?: [], 2, '');
        $this->rawPort = $port;
        $this->port = ctype_digit($port) && $port !== '' ? (int) $port : null;

        return trim($host);
    }

    protected ?int $port = null;

    protected ?string $rawPort = null;
}
