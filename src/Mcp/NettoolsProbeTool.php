<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Mcp;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\NettoolsException;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\QuotaExceededException;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Probes\MailAuditProbe;
use BAGArt\TelegramBotNettools\Probes\SslProbe;
use BAGArt\TelegramBotNettools\Probes\SecHeadersProbe;
use BAGArt\TelegramBotNettools\Probes\SubsProbe;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\CtLogSource;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Tool;
use Laravel\Mcp\Server\Tools\Annotations\IsReadOnly;

/**
 * Read-only nettools surface for AI agents: one probe per call, flowing through
 * the same normalize → SSRF-guard → quota → probe-cache path as the bot
 * commands (RFC §4). Measurement probes (ping/trace/port) are intentionally
 * not exposed — they execute host binaries and bypass the HTTP-only MCP threat
 * model.
 */
#[IsReadOnly]
final class NettoolsProbeTool extends Tool
{
    private const array PROBES = ['ip', 'dns', 'whois', 'ssl', 'sec', 'mail', 'http', 'asn', 'subs'];

    private const string QUOTA_CHAT_ID = 'mcp';

    protected string $description = 'Run one read-only nettools probe (whois/dns/ip/asn/http/ssl/sec/mail/subs) for an AI agent. Same normalize -> SSRF-guard -> quota path as the bot commands.';

    public function __construct(private readonly NettoolsServices $services)
    {
    }

    public function schema(JsonSchema $schema): array
    {
        return [
            'probe' => $schema->string()
                ->description('Probe name. Allowed values: ip, dns, whois, ssl, sec, mail, http, asn, subs.'),
            'target' => $schema->string()
                ->description('Target domain or IP literal; resolved once through the SSRF-guard pipeline.'),
            'timeout_seconds' => $schema->integer()
                ->description('Per-probe timeout in seconds (optional, default 5).'),
        ];
    }

    public function handle(Request $request): Response
    {
        $probe = strtolower(trim((string) $request->get('probe', '')));

        if (! in_array($probe, self::PROBES, true)) {
            return Response::error('probe not available via MCP');
        }

        $targetInput = trim((string) $request->get('target', ''));

        try {
            $target = $this->services->targets->inspect($targetInput);
        } catch (NettoolsException $exception) {
            return Response::error($exception->userMessage());
        }

        try {
            $this->services->quota->charge(self::QUOTA_CHAT_ID, null, 1);
        } catch (QuotaExceededException $exception) {
            return Response::error($exception->userMessage());
        }

        $timeoutSeconds = $request->has('timeout_seconds')
            ? max(1, $request->integer('timeout_seconds'))
            : 5;

        [$probeInstance, $options] = $this->probeFor($probe, $timeoutSeconds);

        $result = $this->services->probeCache->getOrSet(
            $probeInstance,
            $target,
            $options,
            static fn (): ProbeResult => $probeInstance->probe($target, $options),
        );

        return Response::text(json_encode([
            'probe' => $probeInstance->name(),
            'target' => $targetInput,
            'payload' => $result->payload,
            'degraded_sources' => $result->degradedSources,
            'latency_ms' => $result->latencyMs,
        ], JSON_THROW_ON_ERROR));
    }

    /**
     * Probe factory mirroring the bot command wiring (services factories plus
     * the inline constructions from ReportContextBuilder/SubsCommand).
     *
     * @return array{0: NettoolsProbeContract, 1: ProbeOptions}
     */
    private function probeFor(string $probe, int $timeoutSeconds): array
    {
        $settings = $this->services->settings;

        return match ($probe) {
            'ip' => [$this->services->geoProbe(), new ProbeOptions(timeoutSeconds: $timeoutSeconds)],
            'dns' => [$this->services->dnsProbe(), new ProbeOptions(timeoutSeconds: $timeoutSeconds)],
            'whois' => [$this->services->whoisProbe(), new ProbeOptions(timeoutSeconds: $timeoutSeconds)],
            'ssl' => [new SslProbe(SslProbe::selfInspector()), new ProbeOptions(timeoutSeconds: $timeoutSeconds)],
            'sec' => [new SecHeadersProbe($this->services->fetcher), new ProbeOptions(timeoutSeconds: $timeoutSeconds)],
            'mail' => [
                new MailAuditProbe(new DnsClient($this->services->dnsTransport), $this->services->resolvers(), $settings->timeoutDns),
                new ProbeOptions(timeoutSeconds: $timeoutSeconds),
            ],
            'http' => [$this->services->httpProbe(), new ProbeOptions(timeoutSeconds: $timeoutSeconds)],
            'asn' => [$this->services->asnProbe(), new ProbeOptions(timeoutSeconds: $timeoutSeconds)],
            'subs' => [
                new SubsProbe(
                    new CtLogSource($this->services->http),
                    new DnsClient($this->services->dnsTransport),
                    $this->services->resolvers(),
                    $settings->timeoutDns,
                ),
                new ProbeOptions(flags: [SubsProbe::FLAG_BRUTE => false], timeoutSeconds: $timeoutSeconds),
            ],
        };
    }
}
