<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Nettools i18n catalog (EN default)
|--------------------------------------------------------------------------
|
| Every user-facing string of the module lives here (RFC D9). Templates use
| {placeholder} tokens rendered by Messages::format(). A RU locale can be
| added later without code churn.
|
*/

return [
    'invalid_target' => '❌ Not a valid domain or IP: {input}',
    'target_blocked' => '🚫 Blocked: {reason} — private/reserved range',
    'nxdomain' => '🔍 NXDOMAIN — {host} does not exist. Check spelling?',
    'probe_timeout' => '⏳ {probe} timed out after {seconds}s at {step}',
    'upstream_unavailable' => '⚠️ Source {source} unavailable — showing partial results',
    'quota_exceeded' => '🪙 Daily quota used ({used}/{max}). Resets in {reset_in}. /quota',
    'semaphore_busy' => '⏱ Another heavy probe is running on this host, retry in ~{retry_in_seconds}s',
    'capability_missing' => '🧰 Unavailable on this host (missing {capability})',
];
