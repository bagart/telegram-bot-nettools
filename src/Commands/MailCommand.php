<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\MailAuditProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\MailCard;

/**
 * /mail <domain> (§7.9): deliverability audit — MX sanity, SPF lookup
 * counter, DMARC grading, DKIM selectors, MTA-STS/TLS-RPT/BIMI.
 * `/mail --smtp <domain>` runs the live MX:25 EHLO/STARTTLS check
 * (capability-honest: blocked egress is reported as a host limitation,
 * never as a target failure). Weight 1; SMTP check ≤6/user/10min.
 */
#[TgCommandAttribute(name: 'mail')]
final class MailCommand extends ProbeCommand
{
    public const string NAME = 'mail';

    public const int WEIGHT = 1;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->auditEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            new MailAuditProbe(
                dns: new DnsClient($this->services->dnsTransport),
                resolvers: $this->services->resolvers(),
                timeoutSeconds: $this->effSettings->timeoutDns,
                smtpCheck: $this->smtpRequested ? self::smtpChecker() : null,
                fetcher: $this->services->fetcher,
            ),
            new ProbeOptions(timeoutSeconds: $this->effSettings->timeoutDns),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        $card = MailCard::render($result, $chatId, time(), $hostLabel);
        if (! isset($card['keyboard'][0])) {
            $card['keyboard'][0] = [];
        }
        $card['keyboard'][0][] = new Button('📡 SMTP check', CallbackGrammar::encode(
            'mailsmtp',
            $chatId,
            $this->services->targetRef()->remember($hostLabel, self::NAME),
        ));

        return $card;
    }

    protected function parseArgs(string $argsRaw): string
    {
        $trimmed = trim($argsRaw);
        $this->smtpRequested = str_starts_with(strtolower($trimmed), '--smtp');

        return ltrim(substr($this->smtpRequested ? substr($trimmed, 6) : $trimmed, 0));
    }

    /**
     * Pre-quota gate for `--smtp` runs: rate limit + live check rendered as
     * its own card (the DNS matrix is not needed to answer STARTTLS).
     *
     * @return array{text: string, keyboard: list<list<Button>>}|null
     */
    protected function beforeRun(NetTarget $target, bool $confirmed, string $chatId): ?array
    {
        if (! $this->smtpRequested) {
            return null;
        }

        if (! $this->services->rateLimiter()->hit('smtp', $chatId, $this->callerUserId, 6, 600)) {
            return ['text' => '⏳ SMTP check: max 6 per 10 minutes.', 'keyboard' => []];
        }

        $probe = new MailAuditProbe(
            dns: new DnsClient($this->services->dnsTransport),
            resolvers: $this->services->resolvers(),
            timeoutSeconds: $this->effSettings->timeoutDns,
        );
        $mx = $probe->primaryMxHost($target->host);

        if ($mx === null) {
            return ['text' => "❌ No reachable MX for {$target->host} — nothing to check.", 'keyboard' => []];
        }

        $outcome = self::smtpChecker()($mx);

        return [
            'text' => MailCard::smtpCheckText($target->host, $mx, $outcome),
            'keyboard' => [],
        ];
    }

    private bool $smtpRequested = false;

    /** @return \Closure(string): array{reachable:bool,starttls:bool,cert_days_left:?int,error:?string} */
    public static function smtpChecker(): \Closure
    {
        return static function (string $mxHost): array {
            $context = stream_context_create(['ssl' => ['capture_session_meta' => true, 'verify_peer' => false]]);
            $socket = @stream_socket_client(
                'tcp://'.$mxHost.':25',
                $errno,
                $errstr,
                3.0,
                STREAM_CLIENT_CONNECT,
                $context,
            );

            if ($socket === false) {
                // 101/110/113/111 — network unreachable / timeout / no route / refused
                $egressBlocked = in_array($errno, [101, 110, 111, 113], true);

                return [
                    'reachable' => false,
                    'starttls' => false,
                    'cert_days_left' => null,
                    'error' => $egressBlocked
                        ? "no TCP path to {$mxHost}:25 from this server (outbound :25 likely blocked by the provider)"
                        : "{$mxHost}:25 refused the connection",
                ];
            }

            stream_set_timeout($socket, 3);

            $banner = fgets($socket, 512);
            fwrite($socket, "EHLO nettools.probe\r\n");

            $ehlo = '';
            while (($line = fgets($socket, 512)) !== false && strlen($ehlo) < 4096) {
                $ehlo .= $line;
                if (isset($line[3]) && $line[3] === ' ') {
                    break;
                }
            }

            $starttls = stripos($ehlo, 'STARTTLS') !== false;

            $certDays = null;
            if ($starttls) {
                fwrite($socket, "STARTTLS\r\n");
                fgets($socket, 512);

                if (@stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                    $meta = stream_context_get_params($socket);
                    $peerCert = $meta['ssl']['peer_certificate'] ?? null;
                    if ($peerCert !== null) {
                        $parsed = openssl_x509_parse($peerCert);
                        $certDays = isset($parsed['validTo_time_t'])
                            ? (int) floor(($parsed['validTo_time_t'] - time()) / 86400)
                            : null;
                    }
                }
            }

            fwrite($socket, "QUIT\r\n");
            fclose($socket);

            return [
                'reachable' => is_string($banner),
                'starttls' => $starttls,
                'cert_days_left' => $certDays,
                'error' => null,
            ];
        };
    }
}
