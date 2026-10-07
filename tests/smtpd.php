<?php

/*
 * SMTP server used by the tests. It handles one connection at a time,
 * stores each message as a numbered file in a directory and logs the
 * commands it receives, credentials masked.
 *
 * usage: php smtpd.php mode port cert key maildir log [user pass [mechs]]
 *
 * mode is tls for TLS from the start, starttls or none. mechs lists the
 * AUTH mechanisms offered, "PLAIN LOGIN" by default. "ready" is printed
 * once the server listens.
 */

declare(strict_types=1);

if ($argc < 7) {
    fwrite(STDERR, "usage: smtpd.php mode port cert key maildir log " .
        "[user pass [mechs]]\n");
    exit(1);
}
[, $mode, $port, $cert, $key, $dir, $log] = $argv;
$user = $argv[7] ?? '';
$pass = $argv[8] ?? '';
$mechs = $argv[9] ?? 'PLAIN LOGIN';

$ssl = ['local_cert' => $cert, 'local_pk' => $key];
$scheme = $mode === 'tls' ? 'tls' : 'tcp';
$srv = stream_socket_server("$scheme://127.0.0.1:$port", $errno, $errstr,
    STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
    stream_context_create(['ssl' => $ssl]));
if ($srv === false) {
    fwrite(STDERR, "smtpd: $errstr\n");
    exit(1);
}
@mkdir($dir);
echo "ready\n";

for (;;) {
    /* Fails when a client rejects the certificate, that is expected. */
    $c = @stream_socket_accept($srv, 3600);
    if ($c === false) {
        continue;
    }
    stream_set_timeout($c, 10);
    session($c, $mode, $ssl, $user, $pass, $mechs, $dir, $log);
    fclose($c);
}

/**
 * @param resource $c
 * @param array<string, string> $ssl
 */
function session($c, string $mode, array $ssl, string $user, string $pass,
    string $mechs, string $dir, string $log): void
{
    $tls = $mode === 'tls';
    $authed = false;
    logline($log, $tls ? 'TLS' : 'PLAIN');
    out($c, '220 localhost test');
    while (($line = fgets($c)) !== false) {
        $line = rtrim($line, "\r\n");
        $verb = strtoupper(strtok($line, ' ') ?: '');
        logline($log, $verb === 'AUTH' ? 'AUTH ' .
            strtoupper(explode(' ', $line)[1] ?? '') : $line);
        switch ($verb) {
        case 'EHLO':
            out($c, '250-localhost');
            if ($mode === 'starttls' && !$tls) {
                out($c, '250-STARTTLS');
            }
            if ($user !== '' && $tls) {
                out($c, "250-AUTH $mechs");
            }
            out($c, '250 HELP');
            break;
        case 'STARTTLS':
            if ($mode !== 'starttls' || $tls) {
                out($c, '503 not now');
                break;
            }
            out($c, '220 go ahead');
            foreach ($ssl as $k => $v) {
                stream_context_set_option($c, 'ssl', $k, $v);
            }
            if (!@stream_socket_enable_crypto($c, true,
                STREAM_CRYPTO_METHOD_TLS_SERVER)) {
                return;
            }
            $tls = true;
            logline($log, 'TLS');
            break;
        case 'AUTH':
            $authed = auth($c, $line, $user, $pass, $mechs, $log);
            out($c, $authed ? '235 ok' : '535 bad credentials');
            break;
        case 'MAIL':
            out($c, $user !== '' && !$authed ? '530 auth first' : '250 ok');
            break;
        case 'RCPT':
            out($c, '250 ok');
            break;
        case 'DATA':
            out($c, '354 go ahead');
            $msg = '';
            while (($l = fgets($c)) !== false && $l !== ".\r\n") {
                $msg .= str_starts_with($l, '.') ? substr($l, 1) : $l;
            }
            $n = count(glob("$dir/*") ?: []) + 1;
            file_put_contents("$dir/$n", $msg);
            out($c, '250 queued');
            break;
        case 'QUIT':
            out($c, '221 bye');
            return;
        default:
            out($c, '500 unknown command');
        }
    }
}

/**
 * @param resource $c
 */
function auth($c, string $line, string $user, string $pass,
    string $mechs, string $log): bool
{
    $w = explode(' ', $line);
    $mech = strtoupper($w[1] ?? '');
    if (!in_array($mech, explode(' ', $mechs), true)) {
        return false;
    }
    if ($mech === 'PLAIN') {
        $resp = $w[2] ?? null;
        if ($resp === null) {
            logline($log, 'AUTH PLAIN without initial response');
            out($c, '334 ');
            $resp = rtrim((string)fgets($c), "\r\n");
        }
        return base64_decode($resp, true) === "\0$user\0$pass";
    }
    out($c, '334 VXNlcm5hbWU6');
    $u = base64_decode(rtrim((string)fgets($c), "\r\n"), true);
    out($c, '334 UGFzc3dvcmQ6');
    $p = base64_decode(rtrim((string)fgets($c), "\r\n"), true);
    return $u === $user && $p === $pass;
}

/**
 * @param resource $c
 */
function out($c, string $s): void
{
    fwrite($c, "$s\r\n");
}

function logline(string $log, string $s): void
{
    file_put_contents($log, "$s\n", FILE_APPEND);
}
