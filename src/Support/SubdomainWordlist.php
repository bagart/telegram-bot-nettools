<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

/**
 * Bundled subdomain wordlist (RFC §7.6 + Appendix A, MVP subset of the
 * full ~3000-label list). The static $DEFAULT copy materializes lazily
 * from the DEFAULT_LIST constant on first class use.
 */
final class SubdomainWordlist
{
    /**
     * Default label list, ordered by observed frequency.
     *
     * @var list<string>
     */
    private const array DEFAULT_LIST = [
        'www', 'mail', 'ftp', 'api', 'dev', 'staging', 'vpn', 'ns1', 'ns2', 'cdn',
        'shop', 'admin', 'portal', 'app', 'beta', 'alpha', 'test', 'demo', 'blog', 'news',
        'status', 'docs', 'help', 'support', 'mail2', 'smtp', 'imap', 'pop', 'webmail', 'autodiscover',
        'cpanel', 'whm', 'git', 'jenkins', 'ci', 'cd', 'grafana', 'prometheus', 'kibana', 'elastic',
        'db', 'mysql', 'postgres', 'redis', 'cache', 'mq', 'rabbitmq', 'kafka', 'zookeeper', 'consul',
        'vault', 'auth', 'sso', 'login', 'account', 'accounts', 'dashboard', 'home', 'intranet', 'wiki',
        'confluence', 'jira', 'tracker', 'crm', 'erp', 'hr', 'sap', 'oracle', 'sharepoint', 'files',
        'share', 'nas', 'backup', 'old', 'new', 'v2', 'v1', 'm', 'mobile', 'img',
        'images', 'static', 'assets', 'media', 'video', 'videos', 'download', 'downloads', 'cloud', 'aws',
        'azure', 'gcp', 'k8s', 'kubernetes', 'docker', 'registry', 'harbor', 'nexus', 'sonar', 'nexus3',
        'sentry', 'sentry2', 'analytics', 'stats', 'metrics', 'monitor', 'monitoring', 'zabbix', 'nagios', 'logs',
        'syslog', 'splunk', 'es', 'elasticsearch', 'search', 'solr', 'sphinx', 'api-gateway', 'gateway', 'gw',
        'proxy', 'nginx', 'apache', 'haproxy', 'lb', 'lb01', 'lb02', 'edge', 'core', 'dmz',
        'fw', 'vpn2', 'ssl', 'ca', 'pki', 'ocsp', 'crl', 'whois', 'ripe', 'arin',
        'dig', 'ns', 'ns3', 'ns4', 'dns', 'dns1', 'dns2', 'dns3', 'mx', 'mx1',
        'mx2', 'relay', 'smtplib', 'sendgrid', 'mailgun', 'postmark', 'spf', 'dkim', 'dmarc', '_dmarc',
        'bimi', 'mta-sts', 'autotask', 'ticket', 'zendesk', 'intercom', 'freshdesk', 'tawk', 'crisp', 'chat',
        'bot', 'bots', 'ai', 'ml', 'llm', 'openai', 'anthropic',
    ];

    /**
     * Active wordlist used by the brute stage; tests/overrides may reassign
     * it, probes read it once per run.
     *
     * @var list<string>
     */
    public static array $DEFAULT = self::DEFAULT_LIST;
}
