<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools;

use BAGArt\AsyncKernel\Contracts\ASKLockerContract;
use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBot\Outbound\Adapters\KernelCacheAdapter;
use BAGArt\TelegramBot\TgBotSetup;
use BAGArt\TelegramBotNettools\Contracts\FetcherContract;
use BAGArt\TelegramBotNettools\Contracts\MmdbContract;
use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Sources\DnsTransportContract;
use BAGArt\TelegramBotNettools\Sources\IpApiSource;
use BAGArt\TelegramBotNettools\Sources\MmdbReader;
use BAGArt\TelegramBotNettools\Sources\PlatformFetcher;
use BAGArt\TelegramBotNettools\Sources\PlatformHttp;
use BAGArt\TelegramBotNettools\Sources\Port43TransportContract;
use BAGArt\TelegramBotNettools\Sources\RipestatSource;
use BAGArt\TelegramBotNettools\Sources\StreamPort43Transport;
use BAGArt\TelegramBotNettools\Sources\UdpDnsTransport;
use BAGArt\TelegramBotNettools\Support\CapabilityDetector;
use BAGArt\TelegramBotNettools\Support\ProbeCache;
use BAGArt\TelegramBotNettools\Support\ProbeMetrics;
use BAGArt\TelegramBotNettools\Support\ProbeSemaphore;
use BAGArt\TelegramBotNettools\Support\QuotaLedger;
use BAGArt\TelegramBotNettools\Support\SourceBreaker;
use BAGArt\TelegramBotNettools\Support\TargetPipeline;

/**
 * Module service bundle assembled from the bot setup's kernel primitives.
 * Built per command via build() (TgBotSetup is not an app singleton).
 */
final readonly class NettoolsServices
{
    public function __construct(
        public OutboundCacheContract $cache,
        public ASKLockerContract $locker,
        public SourceHttpContract $http,
        public QuotaLedger $quota,
        public ProbeSemaphore $semaphore,
        public ProbeCache $probeCache,
        public CapabilityDetector $capabilities,
        public TargetPipeline $targets,
        public NettoolsSettings $settings,
        public FetcherContract $fetcher,
        public DnsTransportContract $dnsTransport,
        public Port43TransportContract $port43,
        public ?MmdbContract $mmdb = null,
        public ?SourceBreaker $breaker = null,
        public ?\Psr\Log\LoggerInterface $logger = null,
        public ?Contracts\TargetRepositoryContract $targetRepo = null,
    ) {
    }

    /**
     * Test/runtime factory with fully injectable primitives — no Laravel,
     * no platform transports. Production code must use fromSetup().
     */
    public static function forTests(
        OutboundCacheContract $cache,
        ASKLockerContract $locker,
        SourceHttpContract $http,
        ?NettoolsSettings $settings = null,
        ?\Psr\Log\LoggerInterface $logger = null,
        ?FetcherContract $fetcher = null,
        ?DnsTransportContract $dnsTransport = null,
        ?Port43TransportContract $port43 = null,
        ?MmdbContract $mmdb = null,
        ?TargetRepositoryContract $targetRepo = null,
    ): self {
        return new self(
            cache: $cache,
            locker: $locker,
            http: $http,
            quota: new QuotaLedger($cache),
            semaphore: new ProbeSemaphore($locker),
            probeCache: new ProbeCache($cache, $locker),
            capabilities: new CapabilityDetector($cache),
            targets: new TargetPipeline(),
            settings: $settings ?? new NettoolsSettings(),
            fetcher: $fetcher ?? throw new \InvalidArgumentException('forTests() requires an explicit fetcher'),
            dnsTransport: $dnsTransport ?? new UdpDnsTransport(),
            port43: $port43 ?? new StreamPort43Transport(),
            mmdb: $mmdb,
            breaker: new SourceBreaker($cache),
            logger: $logger,
            targetRepo: $targetRepo ?? new Support\InMemoryTargetRepository(),
        );
    }

    public static function fromSetup(TgBotSetup $setup): self
    {
        $cache = new KernelCacheAdapter($setup->cache, $setup->locker);

        return new self(
            cache: $cache,
            locker: $setup->locker,
            http: new PlatformHttp($setup->apiClient),
            quota: QuotaLedger::fromConfig($cache),
            semaphore: new ProbeSemaphore($setup->locker),
            probeCache: new ProbeCache($cache, $setup->locker),
            capabilities: new CapabilityDetector($cache),
            targets: new TargetPipeline(),
            settings: NettoolsSettings::fromConfig(),
            fetcher: new PlatformFetcher($setup->apiClient),
            dnsTransport: new UdpDnsTransport(),
            port43: new StreamPort43Transport(),
            mmdb: MmdbReader::fromConfig(),
            breaker: new SourceBreaker($cache),
            logger: $setup->logger,
            targetRepo: new Support\EloquentTargetRepository(),
        );
    }

    // ---- probe factories (single injection point for tests) ----

    public function whoisProbe(): Probes\WhoisProbe
    {
        return new Probes\WhoisProbe(
            $this->http,
            $this->cache,
            $this->port43,
            $this->breaker,
        );
    }

    public function dnsProbe(): Probes\DnsProbe
    {
        return new Probes\DnsProbe(
            client: new DnsClient($this->dnsTransport),
            resolvers: $this->resolvers(),
            breaker: $this->breaker,
        );
    }

    public function geoProbe(): Probes\GeoAsnProbe
    {
        return new Probes\GeoAsnProbe(
            ipApi: new IpApiSource($this->http),
            ripestat: new RipestatSource($this->http),
            dns: new DnsClient($this->dnsTransport),
            resolvers: $this->resolvers(),
            mmdb: $this->mmdb,
            breaker: $this->breaker,
        );
    }

    public function pingProbe(): Probes\PingProbe
    {
        return new Probes\PingProbe(capabilities: $this->capabilities, packets: $this->settings->pingPackets);
    }

    public function traceProbe(): Probes\TraceProbe
    {
        return new Probes\TraceProbe(capabilities: $this->capabilities, mmdb: $this->mmdb, maxHops: $this->settings->traceHops);
    }

    public function httpProbe(): Probes\HttpProbe
    {
        return new Probes\HttpProbe(fetcher: $this->fetcher);
    }

    public function asnProbe(): Probes\AsnProbe
    {
        return new Probes\AsnProbe(ripestat: new RipestatSource($this->http), port43: $this->port43, mmdb: $this->mmdb, breaker: $this->breaker);
    }

    // ---- interaction stores ----

    public function targetRef(): Support\TargetRef
    {
        return new Support\TargetRef($this->cache);
    }

    public function formState(): Support\FormState
    {
        return new Support\FormState($this->cache);
    }

    public function lastAction(): Support\LastAction
    {
        return new Support\LastAction($this->cache);
    }

    public function rateLimiter(): Support\RateLimiter
    {
        return new Support\RateLimiter($this->cache);
    }

    public function metrics(?\Psr\Log\LoggerInterface $logger = null): ProbeMetrics
    {
        return new ProbeMetrics($this->cache, $logger);
    }

    /** Per-chat settings overlay (RFC §3.5) over the global defaults. */
    public function chatSettings(): Support\ChatSettings
    {
        return Support\ChatSettings::of($this->cache);
    }

    public function memory(): Support\TargetMemoryService
    {
        return new Support\TargetMemoryService($this->targetRepo ?? new Support\InMemoryTargetRepository(), $this->settings);
    }

    /** @return list<string> */
    public function resolvers(): array
    {
        try {
            $configured = (array) config('tg-nettools.resolvers', ['1.1.1.1', '8.8.8.8']);
        } catch (\Throwable) {
            // No Laravel container (unit/feature harness): module defaults.
            $configured = ['1.1.1.1', '8.8.8.8'];
        }

        return array_values(array_filter(array_map(strval(...), $configured)));
    }

    /** @return list<list<string>> resolver groups for propagation diff */
    public function propagationServers(): array
    {
        return [$this->resolvers(), ['9.9.9.9', '208.67.222.222']];
    }
}
