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
    'ip_limit',
    'sender_limit',
    'recipient_limit',
    'recipient_delay',
    'mail_transport',
    'smtp_host',
    'smtp_port',
    'smtp_tls',
    'smtp_user',
    'smtp_password',
    'smtp_cafile',
    'smtp_tls_verify',
];

/* Upper bound of numeric settings, far from any overflow. */
const CONFIG_INT_MAX = 2147483647;

/**
 * Load the INI file at $path and return the validated configuration.
 * Any missing mandatory, unknown or malformed setting is fatal.
 *
 * @return array{base_url: string, mail_from: string,
 *     mail_from_name: string, allowed_domains: list<string>,
 *     db_path: string, secret_ttl: int, token_ttl: int, ip_limit: int,
 *     sender_limit: int, recipient_limit: int, recipient_delay: int,
 *     mail_transport: string, smtp_host: string, smtp_port: int,
 *     smtp_tls: string, smtp_user: string, smtp_password: string,
 *     smtp_cafile: string, smtp_tls_verify: bool}
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
        'secret_ttl' => config_int($ini, 'secret_ttl', 2592000, 1),
        'token_ttl' => config_int($ini, 'token_ttl', 1800, 1),
        'ip_limit' => config_int($ini, 'ip_limit', 30, 1),
        'sender_limit' => config_int($ini, 'sender_limit', 3, 1),
        'recipient_limit' => config_int($ini, 'recipient_limit', 3, 1),
        /* Limits are counted over an hour, longer delays would be lost. */
        'recipient_delay' => config_int($ini, 'recipient_delay', 60, 0,
            3600),
    ] + config_mail($ini);
}

/**
 * Mail transport settings. smtp_tls is tls, starttls or none, the latter
 * written off in the file. Certificate verification can only be turned
 * off for a server on the loopback interface.
 *
 * @param array<string, mixed> $ini
 * @return array{mail_transport: string, smtp_host: string, smtp_port: int,
 *     smtp_tls: string, smtp_user: string, smtp_password: string,
 *     smtp_cafile: string, smtp_tls_verify: bool}
 */
function config_mail(array $ini): array
{
    $transport = $ini['mail_transport'] ?? 'sendmail';
    if ($transport === 'sendmail') {
        return [
            'mail_transport' => 'sendmail',
            'smtp_host' => '',
            'smtp_port' => 0,
            'smtp_tls' => 'none',
            'smtp_user' => '',
            'smtp_password' => '',
            'smtp_cafile' => '',
            'smtp_tls_verify' => true,
        ];
    }
    if ($transport !== 'smtp') {
        throw new RuntimeException('mail_transport must be sendmail or smtp');
    }

    $host = $ini['smtp_host'] ?? null;
    if (!is_string($host) || (filter_var($host, FILTER_VALIDATE_DOMAIN,
        FILTER_FLAG_HOSTNAME) === false &&
        filter_var($host, FILTER_VALIDATE_IP) === false)) {
        throw new RuntimeException('smtp_host must be a host name or an ' .
            'IP address');
    }

    $tls = $ini['smtp_tls'] ?? 'tls';
    if ($tls === false || $tls === 'off') {
        $tls = 'none';
    }
    if (!in_array($tls, ['tls', 'starttls', 'none'], true)) {
        throw new RuntimeException('smtp_tls must be tls, starttls or off');
    }
    $port = config_int($ini, 'smtp_port',
        ['tls' => 465, 'starttls' => 587, 'none' => 25][$tls], 1, 65535);

    $user = $ini['smtp_user'] ?? '';
    $pass = $ini['smtp_password'] ?? '';
    if (!is_string($user) || preg_match('/[\x00-\x1f\x7f]/', $user) === 1) {
        throw new RuntimeException('smtp_user must be a quoted string ' .
            'without control characters');
    }
    if (!is_string($pass) || str_contains($pass, "\0")) {
        throw new RuntimeException('smtp_password must be a string, put ' .
            'it between single quotes');
    }
    if (($user === '') !== ($pass === '')) {
        throw new RuntimeException('smtp_user and smtp_password must be ' .
            'set together');
    }
    if ($user !== '' && $tls === 'none') {
        throw new RuntimeException('smtp_user requires smtp_tls, ' .
            'credentials are never sent in clear');
    }

    $cafile = $ini['smtp_cafile'] ?? '';
    if (!is_string($cafile) || ($cafile !== '' &&
        (!str_starts_with($cafile, '/') || !is_readable($cafile)))) {
        throw new RuntimeException('smtp_cafile must be the absolute path ' .
            'of a readable file');
    }

    $verify = $ini['smtp_tls_verify'] ?? true;
    if (!is_bool($verify)) {
        throw new RuntimeException('smtp_tls_verify must be on or off');
    }
    if (!$verify && !config_loopback($host)) {
        throw new RuntimeException('smtp_tls_verify can only be off for ' .
            'localhost, 127.0.0.0/8 or ::1');
    }

    return [
        'mail_transport' => 'smtp',
        'smtp_host' => $host,
        'smtp_port' => $port,
        'smtp_tls' => $tls,
        'smtp_user' => $user,
        'smtp_password' => $pass,
        'smtp_cafile' => $cafile,
        'smtp_tls_verify' => $verify,
    ];
}

function config_loopback(string $host): bool
{
    if (strtolower($host) === 'localhost') {
        return true;
    }
    $ip = @inet_pton($host);
    return $ip !== false && (strlen($ip) === 4 ? $ip[0] === "\x7f" :
        $ip === inet_pton('::1'));
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

/**
 * Return the integer setting $name, or $default if it is not set.
 *
 * @param array<string, mixed> $ini
 */
function config_int(array $ini, string $name, int $default, int $min,
    int $max = CONFIG_INT_MAX): int
{
    if (!array_key_exists($name, $ini)) {
        return $default;
    }
    $v = $ini[$name];
    if (!is_int($v) || $v < $min || $v > $max) {
        throw new RuntimeException("$name must be an integer between " .
            "$min and $max");
    }
    return $v;
}
