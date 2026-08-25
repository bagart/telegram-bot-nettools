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
    'nxdomain' => "🔍 {host} does not resolve (NXDOMAIN) — it looks unregistered. Double-check the spelling, or grab it from a registrar.",
    'probe_timeout' => '⏳ {probe} timed out after {seconds}s at {step}',
    'upstream_unavailable' => '⚠️ Source {source} unavailable — showing partial results',
    'quota_exceeded' => '🪙 Daily quota used ({used}/{max}). Resets in {reset_in}. /quota',
    'semaphore_busy' => '⏱ Another heavy probe is running on this host, retry in ~{retry_in_seconds}s',
    'capability_missing' => '🧰 Unavailable on this host (missing {capability})',
    'unexpected_error' => '⚠️ Something went wrong — please try again later.',
    'usage_target' => "Usage: /{command} <target>\n\n<i>&lt;target&gt;</i> = domain, IPv4/IPv6 or URL.",
    'usage_dns' => "Usage: /dns &lt;domain&gt; [type]\n\n<i>[type]</i> — optional single record type (A, AAAA, MX, NS, TXT, SOA, CAA…).",
    'usage_ping' => 'Usage: /ping &lt;domain or IP&gt;',
    'usage_trace' => "Usage: /trace &lt;domain or IP&gt;\n\nHeavier op: up to 15s, weight 4.",
    'usage_http' => 'Usage: /http &lt;domain or URL&gt;',
    'usage_port' => "Usage: /port &lt;domain or IP&gt; &lt;port&gt;\n\nSingle TCP reachability check (1–65535).",
    'usage_asn' => "Usage: /asn &lt;AS number or IP&gt;\n\nExamples: <code>/asn AS15169</code> · <code>/asn 8.8.8.8</code>",
    'repeat_empty' => 'Nothing to repeat yet — run a nettools command first.',
    'feature_disabled' => '🧪 This tool is disabled on this bot.',
    'confirm_heavy' => "{command} is a heavier operation (weight {weight}, up to ~{seconds}s).\nTarget: {target}",
    'port_rate_limited' => '🚦 Port-check limit reached ({limit}/hour). Try again later.',
    'invalid_port' => '❌ Invalid port: {input} — expected 1–65535.',
    'awaiting_target' => 'Send the target now (domain or IP).',
    'admin_gate_denied' => "🔒 /{command} is restricted to admin chats with the feature enabled.\n\n{usage}",
    'group_etiquette_tip' => '<i>Tip: in groups reply to a message or @mention the bot to run nettools commands.</i>',
    'ask_target' => '🎯 <b>/{command}</b> — send the target now (domain or IP).',
    'doctor_locked' => '🔒 /nt doctor is available in admin chats only.',
];
