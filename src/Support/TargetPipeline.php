<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\NxDomainException;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\TargetBlockedException;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;

/**
 * The single-resolution entry point every command goes through:
 * normalize → resolve once → SSRF verdict → immutable NetTarget.
 *
 * @throws InvalidTargetException parse/IDN failure
 * @throws NxDomainException no addresses for the host
 * @throws TargetBlockedException any resolved address is blocked
 */
final class TargetPipeline
{
    public function __construct(
        private readonly TargetNormalizer $normalizer = new TargetNormalizer(),
        private readonly DnsLookup $dnsLookup = new DnsLookup(),
        private readonly SsrfGuard $guard = new SsrfGuard(),
    ) {
    }

    public function inspect(string $rawInput): NetTarget
    {
        $input = $this->normalizer->normalize($rawInput);

        if ($input->isIp) {
            return new NetTarget(
                rawInput: $input->rawInput,
                host: $input->host,
                ips: [$input->host],
                isDomain: false,
                isIp: true,
                verdict: $this->verdictOrThrow([$input->host]),
            );
        }

        $ips = $this->dnsLookup->resolveIps($input->host);
        if ($ips === []) {
            throw new NxDomainException($input->host);
        }

        return new NetTarget(
            rawInput: $input->rawInput,
            host: $input->host,
            ips: $ips,
            isDomain: true,
            isIp: false,
            verdict: $this->verdictOrThrow($ips),
        );
    }

    /**
     * @param  list<string>  $ips
     */
    private function verdictOrThrow(array $ips): GuardVerdict
    {
        $verdict = GuardVerdict::allow();
        foreach ($ips as $ip) {
            $classified = $this->guard->classify($ip);
            if ($classified->isBlocked()) {
                throw new TargetBlockedException((string) $classified->reason);
            }
            if (! $verdict->allowed || $classified->label === null) {
                continue;
            }
            $verdict = GuardVerdict::allow($classified->label);
        }

        return $verdict;
    }
}
