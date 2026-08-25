<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\ConfirmCard;
use BAGArt\TelegramBotNettools\Ui\TraceCard;

/**
 * /trace <host> (RFC §7.5): traceroute with ASN per hop, firewalled hops as
 * `* * *`, reached marker. Heavy op → confirmation card first (§3.8),
 * the [Run] callback re-enters execute() confirmed. Never cached. Weight 4.
 */
#[TgCommandAttribute(name: 'trace')]
final class TraceCommand extends ProbeCommand
{
    public const string NAME = 'trace';

    public const int WEIGHT = 4;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->activeEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            $this->services->traceProbe(),
            new ProbeOptions(timeoutSeconds: 15),
        ];
    }

    protected function beforeRun(NetTarget $target, bool $confirmed, string $chatId): ?array
    {
        if ($confirmed || ! $this->effSettings->heavyConfirm) {
            return null;
        }
        $ref = $this->services->targetRef()->remember($target->host, static::NAME);
        $this->services->formState()->set($chatId, null, [
            'flow' => 'confirm',
            'step' => 'run',
            'draft' => ['command' => static::NAME, 'ref' => $ref, 'host' => $target->host],
        ]);

        return ConfirmCard::render(static::NAME, (int) $chatId, static::WEIGHT, $target->host, $ref);
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return TraceCard::render($result, $chatId, time(), $hostLabel);
    }
}
