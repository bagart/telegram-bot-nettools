<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBot\TgApi\Methods\DTO\SendMessageDraftMethodDTO;
use BAGArt\TelegramBot\TgApi\Methods\Enum\ParseModeEnum;
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
        $draftId = random_int(1, PHP_INT_MAX);
        $state = ['lines' => [], 'lastAt' => 0.0];

        $pushDraft = function () use ($target, $draftId, &$state): void {
            try {
                $this->sender->send($this->activeBotConfig, new SendMessageDraftMethodDTO(
                    chatId: (int) $this->activeChatId,
                    draftId: $draftId,
                    text: TraceCard::draftText($target->host, $state['lines']),
                    parseMode: ParseModeEnum::HTML,
                ));
            } catch (\Throwable) {
                // Drafts are best-effort decoration; the final card always lands.
            }
        };

        $pushDraft();

        $onHop = function (array $hop) use (&$state, $pushDraft): void {
            $now = microtime(true);
            if ($now - $state['lastAt'] < 0.8) {
                return; // throttle the animated draft updates
            }
            $state['lastAt'] = $now;
            $state['lines'][] = self::formatProgressLine($hop);
            $pushDraft();
        };

        return [
            $this->services->traceProbe($onHop),
            new ProbeOptions(timeoutSeconds: 15),
        ];
    }

    /**
     * @param  array{n: int, ip: ?string, ms: list<float>, timeout: bool}  $hop
     */
    private static function formatProgressLine(array $hop): string
    {
        if ($hop['timeout']) {
            return str_pad((string) $hop['n'], 3).'* * *';
        }

        $rtts = implode('  ', array_map(static fn (float $ms): string => number_format($ms, 1).' ms', $hop['ms']));

        return str_pad((string) $hop['n'], 3).(string) $hop['ip'].'  '.$rtts;
    }

    protected function heavyCapSeconds(): ?int
    {
        return 15;
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
