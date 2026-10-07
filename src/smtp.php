<?php

/*
 * Minimal SMTP client, one message per connection. The connection is
 * either TLS from the start or upgraded with STARTTLS, which is then
 * mandatory, or plain for a local relay. Certificates are verified unless
 * this is turned off for a loopback server, and credentials never go over
 * a connection without TLS.
 */

declare(strict_types=1);

const SMTP_TIMEOUT = 30;
const SMTP_CRYPTO = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT |
    STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
const SMTP_LINE_MAX = 1024;
const SMTP_LINES_MAX = 100;

/**
 * Deliver $msg, a complete message with CRLF line endings, from $from to
 * $to. Throws RuntimeException on any failure.
 *
 * @param array{base_url: string, smtp_host: string, smtp_port: int,
 *     smtp_tls: string, smtp_user: string, smtp_password: string,
 *     smtp_cafile: string, smtp_tls_verify: bool} $cfg
 */
function smtp_send(array $cfg, string $from, string $to, string $msg): void
{
    $host = $cfg['smtp_host'];
    $ssl = [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'allow_self_signed' => false,
        'peer_name' => $host,
        'crypto_method' => SMTP_CRYPTO,
    ];
    if ($cfg['smtp_cafile'] !== '') {
        $ssl['cafile'] = $cfg['smtp_cafile'];
    }
    if (!$cfg['smtp_tls_verify']) {
        $ssl['verify_peer'] = false;
        $ssl['verify_peer_name'] = false;
        $ssl['allow_self_signed'] = true;
    }
    $v6 = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
    $addr = $v6 ? "[$host]" : $host;
    $scheme = $cfg['smtp_tls'] === 'tls' ? 'tls' : 'tcp';

    $errors = [];
    $fp = smtp_warnings($errors, fn() => stream_socket_client(
        "$scheme://$addr:{$cfg['smtp_port']}", $errno, $errstr,
        SMTP_TIMEOUT, STREAM_CLIENT_CONNECT,
        stream_context_create(['ssl' => $ssl])));
    if ($fp === false) {
        throw smtp_error("cannot connect to $host", $errors);
    }
    try {
        stream_set_timeout($fp, SMTP_TIMEOUT);
        smtp_session($fp, $cfg, $from, $to, $msg);
    } finally {
        fclose($fp);
    }
}

/**
 * @param resource $fp
 * @param array{base_url: string, smtp_tls: string, smtp_user: string,
 *     smtp_password: string} $cfg
 */
function smtp_session($fp, array $cfg, string $from, string $to,
    string $msg): void
{
    $helo = smtp_helo($cfg['base_url']);
    smtp_read($fp, 'greeting', [220]);
    $ext = smtp_cmd($fp, "EHLO $helo", 'EHLO', [250]);

    if ($cfg['smtp_tls'] === 'starttls') {
        if (!in_array('STARTTLS', smtp_keywords($ext), true)) {
            throw new RuntimeException('smtp: server does not offer ' .
                'STARTTLS');
        }
        smtp_cmd($fp, 'STARTTLS', 'STARTTLS', [220]);
        /*
         * Anything already buffered was sent in clear and must not be
         * taken as coming from the TLS session.
         */
        if (stream_get_meta_data($fp)['unread_bytes'] !== 0) {
            throw new RuntimeException('smtp: data sent before TLS ' .
                'negotiation');
        }
        $errors = [];
        if (smtp_warnings($errors, fn() => stream_socket_enable_crypto($fp,
            true, SMTP_CRYPTO)) !== true) {
            throw smtp_error('TLS negotiation failed', $errors);
        }
        $ext = smtp_cmd($fp, "EHLO $helo", 'EHLO', [250]);
    }

    if ($cfg['smtp_user'] !== '') {
        smtp_auth($fp, $ext, $cfg['smtp_user'], $cfg['smtp_password']);
    }
    smtp_cmd($fp, "MAIL FROM:<$from>", 'MAIL FROM', [250]);
    smtp_cmd($fp, "RCPT TO:<$to>", 'RCPT TO', [250, 251]);
    smtp_cmd($fp, 'DATA', 'DATA', [354]);
    if (!str_ends_with($msg, "\r\n")) {
        $msg .= "\r\n";
    }
    if (str_starts_with($msg, '.')) {
        $msg = '.' . $msg;
    }
    smtp_write($fp, str_replace("\r\n.", "\r\n..", $msg) . ".\r\n");
    smtp_read($fp, 'message', [250]);

    /* The message is accepted, a failing QUIT does not matter. */
    try {
        smtp_cmd($fp, 'QUIT', 'QUIT', [221]);
    } catch (RuntimeException) {
    }
}

/**
 * @param resource $fp
 * @param list<string> $ext
 */
function smtp_auth($fp, array $ext, string $user, string $pass): void
{
    $mechs = [];
    foreach (array_slice($ext, 1) as $line) {
        $w = explode(' ', strtoupper(trim($line)));
        if ($w[0] === 'AUTH') {
            $mechs = array_slice($w, 1);
        }
    }
    if (in_array('PLAIN', $mechs, true)) {
        smtp_cmd($fp, 'AUTH PLAIN ' . base64_encode("\0$user\0$pass"),
            'AUTH', [235]);
    } elseif (in_array('LOGIN', $mechs, true)) {
        smtp_cmd($fp, 'AUTH LOGIN', 'AUTH', [334]);
        smtp_cmd($fp, base64_encode($user), 'AUTH', [334]);
        smtp_cmd($fp, base64_encode($pass), 'AUTH', [235]);
    } else {
        throw new RuntimeException('smtp: server offers neither AUTH ' .
            'PLAIN nor AUTH LOGIN');
    }
}

/*
 * Send $line and read the reply. $what names the step in errors, so
 * that credentials never end up in a log.
 *
 * @param resource $fp
 * @param list<int> $codes
 * @return list<string>
 */
function smtp_cmd($fp, string $line, string $what, array $codes): array
{
    smtp_write($fp, "$line\r\n");
    return smtp_read($fp, $what, $codes);
}

/**
 * Read a possibly multiline reply, return its text lines.
 *
 * @param resource $fp
 * @param list<int> $codes
 * @return list<string>
 */
function smtp_read($fp, string $what, array $codes): array
{
    $lines = [];
    do {
        $line = @fgets($fp, SMTP_LINE_MAX);
        if ($line === false) {
            $why = stream_get_meta_data($fp)['timed_out'] ? 'timeout' :
                'connection closed';
            throw new RuntimeException("smtp: $why waiting for $what reply");
        }
        if (preg_match('/^(\d{3})(?:([ -])([^\r\n]*))?\r?\n$/', $line,
            $m) !== 1) {
            throw new RuntimeException("smtp: malformed $what reply");
        }
        $code = (int)$m[1];
        $more = ($m[2] ?? '') === '-';
        $lines[] = $m[3] ?? '';
        if (count($lines) > SMTP_LINES_MAX) {
            throw new RuntimeException("smtp: $what reply too long");
        }
    } while ($more);
    if (!in_array($code, $codes, true)) {
        throw new RuntimeException("smtp: $what failed: $code " .
            smtp_clean(end($lines)));
    }
    return $lines;
}

/**
 * @param resource $fp
 */
function smtp_write($fp, string $data): void
{
    while ($data !== '') {
        $n = @fwrite($fp, $data);
        if ($n === false || $n === 0) {
            throw new RuntimeException('smtp: write failed');
        }
        $data = substr($data, $n);
    }
}

/**
 * Extension keywords of an EHLO reply, the first line is the greeting.
 *
 * @param list<string> $ext
 * @return list<string>
 */
function smtp_keywords(array $ext): array
{
    $kw = [];
    foreach (array_slice($ext, 1) as $line) {
        $kw[] = strtoupper(strtok($line, ' ') ?: '');
    }
    return $kw;
}

/*
 * Name to announce in EHLO: the host of base_url, as an address literal
 * if it is an IP address.
 */
function smtp_helo(string $base_url): string
{
    $host = trim((string)parse_url($base_url, PHP_URL_HOST), '[]');
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return "[$host]";
    }
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        return "[IPv6:$host]";
    }
    return $host;
}

/*
 * Run $fn and collect the warnings it raises into $errors. The reason
 * of a TLS failure is only given that way, spread over several warnings.
 *
 * @param list<string> $errors
 */
function smtp_warnings(array &$errors, callable $fn): mixed
{
    set_error_handler(function (int $no, string $msg) use (&$errors): bool {
        $errors[] = $msg;
        return true;
    });
    try {
        return $fn();
    } finally {
        restore_error_handler();
    }
}

/**
 * @param list<string> $errors
 */
function smtp_error(string $what, array $errors): RuntimeException
{
    $why = $errors === [] ? 'unknown error' : implode('; ', $errors);
    return new RuntimeException("smtp: $what: " . smtp_clean($why));
}

/*
 * Server text goes to the log, keep it short and printable.
 */
function smtp_clean(string $s): string
{
    return substr((string)preg_replace('/[^\x20-\x7e]/', '?', $s), 0, 400);
}
