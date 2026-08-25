<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts;

/**
 * Single-address-resolution seam (todo P1-1/P1-2): guards resolve a host
 * once through this contract so rebinding simulations can inject answers.
 */
interface DnsResolverContract
{
    /** @return list<string> resolved addresses; empty = no answers */
    public function resolveIps(string $host): array;
}
