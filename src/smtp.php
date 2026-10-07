<?php

/*
 * Minimal SMTP client, one message per connection. The connection is
 * either TLS from the start or upgraded with STARTTLS, which is then
 * mandatory, or plain for a relay on the loopback interface. Certificates
 * are verified unless this is turned off for a loopback server, and
 * credentials never go over a connection without TLS.
 */

declare(strict_types=1);

/*
 * Seconds for the whole dialogue. PHP bounds the connection and each TLS
 * handshake by the same value on its own.
 */
const SMTP_TIMEOUT = 30;
const SMTP_CRYPTO = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT |
    STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT;
const SMTP_LINE_MAX = 1024;
const SMTP_LINES_MAX = 100;

/*
 * A connection: the stream, what was read but not used yet and the time
 * by which the dialogue must be over.
 */
final class SmtpConn
{
    public string $buf = '';

    /**
     * @param resource $fp
     */
    public function __construct(public $fp, public float $end)
    {
    }
}

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
    /* RFC 6066 does not allow an address as server name. */
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        $ssl['SNI_enabled'] = false;
    }
    if (!$cfg['smtp_tls_verify']) {
        $ssl['verify_peer'] = false;
        $ssl['verify_peer_name'] = false;
        $ssl['allow_self_signed'] = true;
    }
    /*
     * localhost is taken as loopback, so it must not be looked up: in a
     * chroot without /etc/hosts, the resolver would ask DNS for it.
     */
    $addr = strtolower($host) === 'localhost' ? '127.0.0.1' : $host;
    if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $addr = "[$addr]";
    }
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
        smtp_session(new SmtpConn($fp, microtime(true) + SMTP_TIMEOUT),
            $cfg, $from, $to, $msg);
    } finally {
        fclose($fp);
    }
}

/**
 * @param array{base_url: string, smtp_tls: string, smtp_user: string,
 *     smtp_password: string} $cfg
 */
function smtp_session(SmtpConn $c, array $cfg, string $from, string $to,
    string $msg): void
{
    $helo = smtp_helo($cfg['base_url']);
    smtp_read($c, 'greeting', [220]);
    $ext = smtp_ext(smtp_cmd($c, "EHLO $helo", 'EHLO', [250]));

    if ($cfg['smtp_tls'] === 'starttls') {
        if (!isset($ext['STARTTLS'])) {
            throw new RuntimeException('smtp: server does not offer ' .
                'STARTTLS');
        }
        smtp_cmd($c, 'STARTTLS', 'STARTTLS', [220]);
        /*
         * Anything already buffered was sent in clear and must not be
         * taken as coming from the TLS session.
         */
        if ($c->buf !== '' ||
            stream_get_meta_data($c->fp)['unread_bytes'] !== 0) {
            throw new RuntimeException('smtp: data sent before TLS ' .
                'negotiation');
        }
        $errors = [];
        if (smtp_warnings($errors, fn() => stream_socket_enable_crypto(
            $c->fp, true, SMTP_CRYPTO)) !== true) {
            throw smtp_error('TLS negotiation failed', $errors);
        }
        $ext = smtp_ext(smtp_cmd($c, "EHLO $helo", 'EHLO', [250]));
    }

    if ($cfg['smtp_user'] !== '') {
        smtp_auth($c, $ext, $cfg['smtp_user'], $cfg['smtp_password']);
    }
    smtp_cmd($c, "MAIL FROM:<$from>", 'MAIL FROM', [250]);
    smtp_cmd($c, "RCPT TO:<$to>", 'RCPT TO', [250, 251]);
    smtp_cmd($c, 'DATA', 'DATA', [354]);
    if (!str_ends_with($msg, "\r\n")) {
        $msg .= "\r\n";
    }
    if (str_starts_with($msg, '.')) {
        $msg = '.' . $msg;
    }
    smtp_write($c, str_replace("\r\n.", "\r\n..", $msg) . ".\r\n");
    smtp_read($c, 'message', [250]);

    /* The message is accepted, a failing QUIT does not matter. */
    try {
        smtp_cmd($c, 'QUIT', 'QUIT', [221]);
    } catch (RuntimeException) {
    }
}

/**
 * @param array<string, list<string>> $ext
 */
function smtp_auth(SmtpConn $c, array $ext, string $user, string $pass): void
{
    $mechs = $ext['AUTH'] ?? [];
    if (in_array('PLAIN', $mechs, true)) {
        /*
         * RFC 4954: the credentials go on a line of their own when they
         * would make the command longer than the 512 octets of SMTP.
         */
        $resp = base64_encode("\0$user\0$pass");
        if (strlen("AUTH PLAIN $resp\r\n") <= 512) {
            smtp_cmd($c, "AUTH PLAIN $resp", 'AUTH', [235]);
        } else {
            smtp_cmd($c, 'AUTH PLAIN', 'AUTH', [334]);
            smtp_cmd($c, $resp, 'AUTH', [235]);
        }
    } elseif (in_array('LOGIN', $mechs, true)) {
        smtp_cmd($c, 'AUTH LOGIN', 'AUTH', [334]);
        smtp_cmd($c, base64_encode($user), 'AUTH', [334]);
        smtp_cmd($c, base64_encode($pass), 'AUTH', [235]);
    } else {
        throw new RuntimeException('smtp: server offers neither AUTH ' .
            'PLAIN nor AUTH LOGIN');
    }
}

/*
 * Send $line and read the reply. $what names the step in errors, so
 * that credentials never end up in a log.
 *
 * @param list<int> $codes
 * @return list<string>
 */
function smtp_cmd(SmtpConn $c, string $line, string $what,
    array $codes): array
{
    smtp_write($c, "$line\r\n");
    return smtp_read($c, $what, $codes);
}

/**
 * Read a possibly multiline reply, return its text lines.
 *
 * @param list<int> $codes
 * @return list<string>
 */
function smtp_read(SmtpConn $c, string $what, array $codes): array
{
    $lines = [];
    do {
        $line = smtp_line($c, $what);
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

/*
 * Read one line. On a socket fread() returns after a single read, so the
 * deadline holds however slowly the server sends.
 */
function smtp_line(SmtpConn $c, string $what): string
{
    while (($i = strpos($c->buf, "\n")) === false) {
        if (strlen($c->buf) >= SMTP_LINE_MAX) {
            throw new RuntimeException("smtp: $what reply line too long");
        }
        smtp_deadline($c, "waiting for $what reply");
        $data = @fread($c->fp, 8192);
        if ($data === false || $data === '') {
            $why = stream_get_meta_data($c->fp)['timed_out'] ? 'timeout' :
                'connection closed';
            throw new RuntimeException("smtp: $why waiting for $what reply");
        }
        $c->buf .= $data;
    }
    $line = substr($c->buf, 0, $i + 1);
    $c->buf = substr($c->buf, $i + 1);
    return $line;
}

function smtp_write(SmtpConn $c, string $data): void
{
    while ($data !== '') {
        smtp_deadline($c, 'writing');
        $n = @fwrite($c->fp, $data);
        if ($n === false || $n === 0) {
            throw new RuntimeException('smtp: write failed');
        }
        $data = substr($data, $n);
    }
}

/*
 * Give the next stream operation only the time left in the dialogue.
 */
function smtp_deadline(SmtpConn $c, string $what): void
{
    $left = $c->end - microtime(true);
    if ($left <= 0) {
        throw new RuntimeException("smtp: timeout $what");
    }
    stream_set_timeout($c->fp, (int)$left, (int)(fmod($left, 1) * 1e6));
}

/**
 * Extensions of an EHLO reply, whose first line is the greeting: each
 * keyword with its parameters, in upper case.
 *
 * @param list<string> $lines
 * @return array<string, list<string>>
 */
function smtp_ext(array $lines): array
{
    $ext = [];
    foreach (array_slice($lines, 1) as $line) {
        $w = preg_split('/ +/', strtoupper(trim($line)), -1,
            PREG_SPLIT_NO_EMPTY);
        if ($w !== false && $w !== []) {
            $ext[$w[0]] = array_slice($w, 1);
        }
    }
    return $ext;
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
