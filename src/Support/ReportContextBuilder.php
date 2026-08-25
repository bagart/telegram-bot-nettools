<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Probes\MailAuditProbe;
use BAGArt\TelegramBotNettools\Probes\SslProbe;
use BAGArt\TelegramBotNettools\Probes\SecHeadersProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use Throwable;

/**
 * Assembles a ReportContext (probe name → ProbeResult) for /reco and /report
 * (RFC §4.4): shared resolution via the pipeline, every section through
 * ProbeCache single-flight, per-section failures degrade to absence — never
 * abort the whole report.
 */
final class ReportContextBuilder
{
    private const array SECTIONS = ['ip', 'dns', 'whois', 'ssl', 'sec', 'mail', 'http'];

    public function __construct(private readonly \BAGArt\TelegramBotNettools\NettoolsServices $services)
    {
    }

    /** @return array{results: array<string, ProbeResult>, degraded: list<string>, failed: list<string>} */
    public function build(NetTarget $target): array
    {
        $s = $this->services;
        $settings = $s->settings;

        $probes = [
            'ip' => [$s->geoProbe(), new ProbeOptions(timeoutSeconds: 3)],
            'dns' => [$s->dnsProbe(), new ProbeOptions(timeoutSeconds: $settings->timeoutDns)],
            'whois' => [$s->whoisProbe(), new ProbeOptions(timeoutSeconds: $settings->timeoutWhois43)],
            'ssl' => [new SslProbe(SslProbe::selfInspector()), new ProbeOptions(timeoutSeconds: $settings->timeoutHttpFetch)],
            'sec' => [new SecHeadersProbe($s->fetcher), new ProbeOptions(timeoutSeconds: $settings->timeoutHttpFetch)],
            'mail' => [new MailAuditProbe(new DnsClient($s->dnsTransport), $s->resolvers(), $settings->timeoutDns), new ProbeOptions(timeoutSeconds: $settings->timeoutDns)],
            'http' => [$s->httpProbe(), new ProbeOptions(timeoutSeconds: $settings->timeoutHttpFetch)],
        ];

        $results = [];
        $degraded = [];
        $failed = [];

        foreach (self::SECTIONS as $name) {
            [/* probe */, $options] = $probes[$name];

            try {
                if ($name === 'ip' && $target->ips === []) {
                    throw new \LogicException('no resolved IP for /ip section');
                }

                $probe = $probes[$name][0];
                $result = $s->probeCache->getOrSet(
                    $probe,
                    $target,
                    $options,
                    static fn (): ProbeResult => $probe->probe($target, $options),
                );
                $results[$name] = $result;

                foreach ((array) $result->degradedSources as $source) {
                    $degraded[] = "{$name}:{$source}";
                }
            } catch (Throwable $e) {
                $failed[] = $name.':'.\BAGArt\TelegramBotNettools\Support\ErrorLabel::of($e);
            }
        }

        return ['results' => $results, 'degraded' => $degraded, 'failed' => $failed];
    }
}
