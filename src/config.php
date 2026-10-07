<?php

/*
 * Configuration loading and validation.
 */

declare(strict_types=1);

const CONFIG_KEYS = [
    'base_url',
    'mail_from',
    'mail_from_name',
    'allowed_domains',
    'db_path',
    'secret_ttl',
    'token_ttl',
];

/**
 * Load the INI file at $path and return the validated configuration.
 * Any missing, unknown or malformed setting is fatal.
 *
 * @return array{base_url: string, mail_from: string,
 *     mail_from_name: string, allowed_domains: list<string>,
 *     db_path: string, secret_ttl: int, token_ttl: int}
 */
function config_load(string $path): array
{
    $ini = parse_ini_file($path, false, INI_SCANNER_TYPED);
    if ($ini === false) {
        throw new RuntimeException("cannot read configuration $path");
    }
    foreach (array_keys($ini) as $k) {
        if (!in_array($k, CONFIG_KEYS, true)) {
            throw new RuntimeException("unknown configuration key $k");
        }
    }

    $from = email_normalize($ini['mail_from'] ?? null);
    if ($from === null) {
        throw new RuntimeException('mail_from must be a valid address');
    }

    return [
        'base_url' => config_base_url($ini['base_url'] ?? null),
        'mail_from' => $from,
        'mail_from_name' => config_name($ini['mail_from_name'] ?? 'Sherpass'),
        'allowed_domains' => config_domains($ini['allowed_domains'] ?? null),
        'db_path' => config_path($ini['db_path'] ?? null),
        'secret_ttl' => config_ttl('secret_ttl', $ini['secret_ttl'] ?? null),
        'token_ttl' => config_ttl('token_ttl', $ini['token_ttl'] ?? null),
    ];
}

/*
 * The base URL is used to build every link sent by mail, so it must be
 * https. Plain http is only accepted for local testing.
 */
function config_base_url(mixed $v): string
{
    if (!is_string($v) || filter_var($v, FILTER_VALIDATE_URL) === false) {
        throw new RuntimeException('base_url must be a URL');
    }
    $u = parse_url($v);
    if ($u === false) {
        throw new RuntimeException('base_url must be a URL');
    }
    $scheme = strtolower($u['scheme'] ?? '');
    $host = strtolower($u['host'] ?? '');
    $local = in_array($host, ['localhost', '127.0.0.1', '[::1]'], true);
    if ($scheme !== 'https' && !($scheme === 'http' && $local)) {
        throw new RuntimeException('base_url must use https');
    }
    if (isset($u['user']) || isset($u['pass']) || isset($u['query']) ||
        isset($u['fragment'])) {
        throw new RuntimeException(
            'base_url must not contain credentials, query or fragment');
    }
    return rtrim($v, '/');
}

/*
 * The display name goes verbatim into a quoted From header, keep it to
 * printable ASCII without quotes or backslashes.
 */
function config_name(mixed $v): string
{
    if (!is_string($v) || preg_match('/^[\x20-\x7e]{1,64}$/', $v) !== 1 ||
        strpbrk($v, '"\\') !== false) {
        throw new RuntimeException('mail_from_name must be 1 to 64 ' .
            'printable ASCII characters without quotes or backslashes');
    }
    return $v;
}

/**
 * @return list<string>
 */
function config_domains(mixed $v): array
{
    if (is_string($v)) {
        $v = [$v];
    }
    if (!is_array($v) || count($v) === 0) {
        throw new RuntimeException('allowed_domains must list at least ' .
            'one domain');
    }
    $domains = [];
    foreach ($v as $d) {
        if (!is_string($d) || $d === '' || filter_var($d,
            FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            throw new RuntimeException('allowed_domains contains an ' .
                'invalid domain');
        }
        $domains[] = strtolower($d);
    }
    return $domains;
}

function config_path(mixed $v): string
{
    if (!is_string($v) || !str_starts_with($v, '/')) {
        throw new RuntimeException('db_path must be an absolute path');
    }
    return $v;
}

function config_ttl(string $name, mixed $v): int
{
    if (!is_int($v) || $v <= 0) {
        throw new RuntimeException("$name must be a positive number " .
            'of seconds');
    }
    return $v;
}
