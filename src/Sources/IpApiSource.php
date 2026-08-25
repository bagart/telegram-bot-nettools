<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;

/**
 * ip-api.com free geo fallback (RFC §5.4: 45 req/min — quota + breaker keep
 * us far below). HTTP-only endpoint by design (free tier); the payload is
 * public infrastructure data, nothing sensitive is sent.
 */
final class IpApiSource
{
    public const string NAME = 'ip-api';

    private const string FIELDS = 'status,message,country,regionName,city,lat,lon,isp,org,as,asname,mobile,proxy,hosting,query';

    public function __construct(private readonly SourceHttpContract $http)
    {
    }

    /** @return array<string, mixed>|null null = unavailable → degraded note */
    public function fetch(string $ip): ?array
    {
        $body = $this->http->getJson(
            'http://ip-api.com/json/'.$ip.'?fields='.self::FIELDS,
            3,
        );

        if ($body === null || ($body['status'] ?? '') !== 'success') {
            return null;
        }

        return $body;
    }
}
