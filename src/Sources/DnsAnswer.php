<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Sources;

/**
 * Parsed DNS answer: state only (platform cache-purity rule). Records are
 * keyed by mnemonic type name with per-type minimal TTL for cache math.
 *
 * @param  array<string, list<string>>  $records  type name => values
 * @param  array<string, int>  $ttls  type name => minimal TTL seen
 */
final readonly class DnsAnswer
{
    public const int NOERROR = 0;

    public const int FORMERR = 1;

    public const int SERVFAIL = 2;

    public const int NXDOMAIN = 3;

    public const int NOTIMP = 4;

    public const int REFUSED = 5;

    public function __construct(
        public int $rcode,
        public bool $authoritative,
        public bool $dnssecAd,
        public array $records = [],
        public array $ttls = [],
        public bool $truncated = false,
    ) {
    }

    public function statusName(): string
    {
        return match ($this->rcode) {
            self::NOERROR => 'NOERROR',
            self::FORMERR => 'FORMERR',
            self::SERVFAIL => 'SERVFAIL',
            self::NXDOMAIN => 'NXDOMAIN',
            self::NOTIMP => 'NOTIMP',
            self::REFUSED => 'REFUSED',
            default => 'RCODE'.$this->rcode,
        };
    }
}
