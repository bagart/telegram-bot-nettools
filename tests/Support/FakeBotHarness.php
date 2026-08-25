<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\ASKClient\Contracts\Pipeline\ASKFutureContract;
use BAGArt\AsyncKernel\Contracts\ASKSchedulerContract;
use BAGArt\AsyncKernel\Wrappers\ASKCacheWrapper;
use BAGArt\AsyncKernel\Wrappers\ASKLogWrapper;
use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Configs\TgServiceConfig;
use BAGArt\TelegramBot\Contracts\ApiCommunication\TgBotApiDTOClientContract;
use BAGArt\TelegramBot\Contracts\ApiCommunication\TgBotApiTransportContract;
use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBot\Outbound\TgOutboundStats;
use BAGArt\TelegramBot\Processing\BotProcessorContext;
use BAGArt\TelegramBot\Processing\TypeDTOProcessorRegistry;
use BAGArt\TelegramBot\TgApi\Types\DTO\CallbackQueryTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\ChatTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\MessageTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\UserTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\Enum\ChatPropTypeEnum;
use BAGArt\TelegramBot\TgApiCaller;
use BAGArt\TelegramBot\TgBotSetup;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\NettoolsSettings;

/**
 * End-to-end command harness (RFC §12 feature layer): real processors over
 * in-memory caches, a capturing sender and scripted HTTP sources — zero
 * network, zero Laravel. Commands are constructed directly with the harness's
 * NettoolsServices (build() would need a live platform).
 */
final class FakeBotHarness
{
    public const string TOKEN = '1234567890:AAEhBOweik6ad9r_QXMENQjcrGbqCr4K-5c';

    public CapturingSender $sender;

    public OutboundCacheContract $cache;

    public FakeHttpSource $http;

    public NettoolsServices $services;

    public BotProcessorContext $context;

    /** @var list<string> structured log lines emitted through ProbeMetrics */
    public array $metricLines = [];

    private function __construct(NettoolsSettings $settings, FakeProbeFetcher $fetcher, FakeDnsTransport $dns, FakePort43Transport $port43)
    {
        $this->sender = new CapturingSender();
        $this->cache = FakeOutboundCacheFactory::create();
        $this->http = new FakeHttpSource();
        $logger = new ASKLogWrapper(null, ASKLogWrapper::LEVEL_ERROR);

        $this->services = NettoolsServices::forTests(
            cache: $this->cache,
            locker: new FakeLocker(),
            http: $this->http,
            settings: $settings,
            fetcher: $fetcher,
            dnsTransport: $dns,
            port43: $port43,
            logger: new class ($this) implements \Psr\Log\LoggerInterface {
                public function __construct(private readonly FakeBotHarness $harness)
                {
                }

                public function log(mixed $level, string|\Stringable $message, array $context = []): void
                {
                    if (str_contains($message, 'nettools.probe')) {
                        $this->harness->metricLines[] = $message;
                    }
                }

                public function emergency(string|\Stringable $message, array $context = []): void
                {
                    $this->log('emergency', $message, $context);
                }

                public function alert(string|\Stringable $message, array $context = []): void
                {
                    $this->log('alert', $message, $context);
                }

                public function critical(string|\Stringable $message, array $context = []): void
                {
                    $this->log('critical', $message, $context);
                }

                public function error(string|\Stringable $message, array $context = []): void
                {
                    $this->log('error', $message, $context);
                }

                public function warning(string|\Stringable $message, array $context = []): void
                {
                    $this->log('warning', $message, $context);
                }

                public function notice(string|\Stringable $message, array $context = []): void
                {
                    $this->log('notice', $message, $context);
                }

                public function info(string|\Stringable $message, array $context = []): void
                {
                    $this->log('info', $message, $context);
                }

                public function debug(string|\Stringable $message, array $context = []): void
                {
                    $this->log('debug', $message, $context);
                }
            },
        );

        $setup = $this->buildSetup($logger);
        $registry = new TypeDTOProcessorRegistry();

        $this->context = new BotProcessorContext(
            logger: $logger,
            tgSender: $this->sender,
            tgApiCaller: new TgApiCaller($this->sender, new \BAGArt\TelegramBot\ProcessingDispatcherRegistry(), new TgServiceConfig(), $logger),
            processorRegistry: $registry,
            serviceConfig: $setup->serviceConfig,
            botSetup: $setup,
        );
    }

    /**
     * @param  array<string, string|array<int|string, mixed>>  $httpBodies
     *                                                          'raw:<url>' → fetcher entry (string body / '@refused'…),
     *                                                          '<url>' → JSON source script (array)
     * @param  array<string, mixed>  $settings  NettoolsSettings::fromArray overrides
     */
    public static function create(array $httpBodies = [], array $settings = []): self
    {
        $harness = new self(
            NettoolsSettings::fromArray($settings),
            new FakeProbeFetcher(),
            new FakeDnsTransport(),
            new FakePort43Transport(),
        );

        foreach ($httpBodies as $url => $body) {
            if (str_starts_with($url, 'raw:')) {
                \assert($harness->services->fetcher instanceof FakeProbeFetcher);
                $harness->services->fetcher->script(substr($url, 4), $body);
            } else {
                $harness->http->script($url, (array) $body);
            }
        }

        return $harness;
    }

    public function botConfig(): TgBotConfig
    {
        return new TgBotConfig(token: self::TOKEN);
    }

    public function message(string $text, int $chatId = 100, ?int $userId = 42): MessageTypeDTO
    {
        return new MessageTypeDTO(
            messageId: random_int(1, PHP_INT_MAX),
            date: 1700000000,
            chat: new ChatTypeDTO(id: (string) $chatId, type: ChatPropTypeEnum::PRIVATE),
            from: $userId !== null ? new UserTypeDTO(id: (string) $userId, isBot: false, firstName: 'T') : null,
            text: $text,
        );
    }

    public function callback(string $data, int $chatId = 100, int $userId = 42): CallbackQueryTypeDTO
    {
        return new CallbackQueryTypeDTO(
            id: 'cbq-'.random_int(1, PHP_INT_MAX),
            from: new UserTypeDTO(id: (string) $userId, isBot: false, firstName: 'T'),
            chatInstance: 'ci',
            data: $data,
        );
    }

    /** @return list<string> */
    public function texts(): array
    {
        return $this->sender->texts();
    }

    public function lastText(): string
    {
        return $this->sender->lastText();
    }

    private function buildSetup(ASKLogWrapper $logger): TgBotSetup
    {
        $transport = new class () implements TgBotApiTransportContract {
            public function request(TgBotConfig $config, string $method, array $params = [], ?int $timeout = null, array $files = []): array
            {
                throw new \LogicException('transport not used in tests');
            }

            public function requestAsync(TgBotConfig $config, string $method, array $params = [], ?int $timeout = null, array $files = []): ASKFutureContract
            {
                throw new \LogicException('async transport not used in tests');
            }
        };

        $dtoClient = new class () implements TgBotApiDTOClientContract {
            public function request(TgBotConfig $botConfig, \BAGArt\TelegramBot\Contracts\TgApi\TgApiMethodDTOContract $dto, ?int $timeout = null): \BAGArt\TelegramBot\Http\Pure\TgApiResponse
            {
                throw new \LogicException('dto client not used in tests');
            }

            public function requestAsync(TgBotConfig $botConfig, \BAGArt\TelegramBot\Contracts\TgApi\TgApiMethodDTOContract $dto, ?int $timeout = null): \BAGArt\ASKClient\Contracts\Pipeline\ASKFutureContract
            {
                throw new \LogicException('async dto client not used in tests');
            }

            public function tickable(): array
            {
                return [];
            }
        };

        $scheduler = new class () implements ASKSchedulerContract {
            public function enqueue(\Fiber|\Closure $fiber): void
            {
            }

            public function tick(int $systemPressure): void
            {
            }

            public function pressure(): int
            {
                return 0;
            }

            public function isIdle(): bool
            {
                return true;
            }

            public function queueSize(): int
            {
                return 0;
            }
        };

        $queue = new \BAGArt\ASKClient\Queue\Adapters\InMemoryQueueAdapter();

        $apiClient = new class () implements \BAGArt\ASKClient\Contracts\Client\ApiClientContract {
            public function requestAsync(\BAGArt\ASKClient\Dto\ASKHttpRequest $request): \BAGArt\AsyncKernel\Contracts\ASKPromiseContract
            {
                throw new \LogicException('api client not used in tests');
            }

            public function request(\BAGArt\ASKClient\Dto\ASKHttpRequest $request): \BAGArt\ASKClient\Dto\ASKHttpResponse
            {
                throw new \LogicException('api client not used in tests');
            }

            public function tickable(): array
            {
                return [];
            }
        };

        return new TgBotSetup(
            logger: $logger,
            cache: new ASKCacheWrapper(new ArrayCache()),
            queue: $queue,
            locker: new FakeLocker(),
            transport: $transport,
            dtoClient: $dtoClient,
            tgApiCaller: new TgApiCaller($this->sender, new \BAGArt\TelegramBot\ProcessingDispatcherRegistry(), new TgServiceConfig(), $logger),
            processorRegistry: new TypeDTOProcessorRegistry(),
            processingStatistics: new \BAGArt\TelegramBot\ApiCommunication\Polling\ProcessingStatistics(),
            apiClient: $apiClient,
            processorScheduler: $scheduler,
            tgSender: $this->sender,
            outboundStats: new TgOutboundStats($this->cache),
            serviceConfig: new TgServiceConfig(),
        );
    }
}
