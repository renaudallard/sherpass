<?php

/*
 * HTML pages. Every dynamic value goes through h().
 */

declare(strict_types=1);

function h(string $s): string
{
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5,
        'UTF-8');
}

function duration(int $s): string
{
    foreach ([86400 => 'day', 3600 => 'hour', 60 => 'minute'] as $n => $u) {
        if ($s % $n === 0) {
            $s = intdiv($s, $n);
            return $s . ' ' . $u . ($s === 1 ? '' : 's');
        }
    }
    return $s . ' second' . ($s === 1 ? '' : 's');
}

function respond(int $status, string $title, string $body): void
{
    http_response_code($status);
    header_remove('X-Powered-By');
    header('Content-Type: text/html; charset=UTF-8');
    header("Content-Security-Policy: default-src 'none'; " .
        "style-src 'self'; form-action 'self'; frame-ancestors 'none'; " .
        "base-uri 'none'");
    header('Referrer-Policy: no-referrer');
    header('X-Content-Type-Options: nosniff');
    header('X-Robots-Tag: noindex, nofollow');
    header('Cache-Control: no-store');
    $title = h($title);
    $page = <<<HTML
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>$title - Sherpass</title>
        <link rel="stylesheet" href="style.css">
        </head>
        <body>
        <main>
        <h1>$title</h1>
        $body
        </main>
        </body>
        </html>

        HTML;
    /*
     * With a length the client knows when the page is complete, even if
     * the script goes on and no php-fpm can end the request early.
     */
    header('Content-Length: ' . strlen($page));
    echo $page;
}

function view_error(string $msg): string
{
    return $msg === '' ? '' : '<p class="error">' . h($msg) . "</p>\n";
}

function view_message(string $msg): string
{
    return '<p>' . h($msg) . "</p>\n";
}

function view_start(string $error = '', string $email = ''): string
{
    $err = view_error($error);
    $email = h($email);
    $emax = EMAIL_MAX;
    return <<<HTML
        $err<p>Enter your address. You will receive a link to share a
        password.</p>
        <form method="post" action="./">
        <label for="email">Your address</label>
        <input type="email" id="email" name="email" value="$email"
         maxlength="$emax" autocomplete="email" required autofocus>
        <button type="submit">Continue</button>
        </form>
        HTML;
}

function view_start_sent(string $email, string $ttl): string
{
    $email = h($email);
    $ttl = h($ttl);
    return <<<HTML
        <p>A mail has been sent to <strong>$email</strong>. Open the link
        it contains within $ttl to share your password.</p>
        HTML;
}

/*
 * A textarea drops the first newline of its content, so one is always
 * emitted to keep a leading newline of the secret.
 */
function view_compose(string $v, string $sender, string $error = '',
    string $secret = '', string $rcpt = ''): string
{
    $err = view_error($error);
    $v = h($v);
    $sender = h($sender);
    $secret = h($secret);
    $rcpt = h($rcpt);
    $max = SECRET_MAX;
    $emax = EMAIL_MAX;
    return <<<HTML
        $err<p>Sharing as <strong>$sender</strong>.</p>
        <form method="post" action="./">
        <input type="hidden" name="v" value="$v">
        <label for="secret">Password</label>
        <textarea id="secret" name="secret" maxlength="$max" required
         autocomplete="off" autocapitalize="off" spellcheck="false">
        $secret</textarea>
        <label for="rcpt">Recipient address</label>
        <input type="email" id="rcpt" name="rcpt" value="$rcpt"
         maxlength="$emax" autocomplete="off" required>
        <button type="submit">Share</button>
        </form>
        HTML;
}

function view_share(string $url, string $rcpt, string $expires): string
{
    $url = h($url);
    $rcpt = h($rcpt);
    $expires = h($expires);
    return <<<HTML
        <p>Send this link to the recipient:</p>
        <pre class="box">$url</pre>
        <p>Anyone can open it, but only <strong>$rcpt</strong> can display
        the password, after confirming the address by mail. The password
        can be displayed once and expires on $expires.</p>
        <p class="muted">The link is not stored on the server. If you lose
        it, share the password again.</p>
        HTML;
}

function view_claim(string $s, string $error = ''): string
{
    $err = view_error($error);
    $s = h($s);
    $emax = EMAIL_MAX;
    return <<<HTML
        $err<p>A password is waiting for its recipient. Enter your address
        to receive a link to display it.</p>
        <form method="post" action="./">
        <input type="hidden" name="s" value="$s">
        <label for="email">Your address</label>
        <input type="email" id="email" name="email" maxlength="$emax"
         autocomplete="email" required autofocus>
        <button type="submit">Continue</button>
        </form>
        HTML;
}

function view_claim_sent(string $ttl): string
{
    $ttl = h($ttl);
    return <<<HTML
        <p>If this address is the recipient of the password, a mail has
        been sent to it. Open the link it contains within $ttl.</p>
        <p class="muted">No mail? Check the address and try again.</p>
        HTML;
}

function view_reveal(string $s, string $r, string $sender): string
{
    $s = h($s);
    $r = h($r);
    $sender = h($sender);
    return <<<HTML
        <p><strong>$sender</strong> has shared a password with you.</p>
        <p>It can be displayed only once. It is deleted from the server
        right after.</p>
        <p class="error">Press the button only once and wait for the page.
        A second press would only show that the link has been used, and
        the password would be lost.</p>
        <form method="post" action="./">
        <input type="hidden" name="s" value="$s">
        <input type="hidden" name="r" value="$r">
        <button type="submit">Display the password</button>
        </form>
        HTML;
}

/*
 * As with textarea, the newline after <pre> keeps a leading newline of
 * the secret.
 */
function view_secret(string $secret, string $sender): string
{
    $secret = h($secret);
    $sender = h($sender);
    return <<<HTML
        <p>Password shared by <strong>$sender</strong>:</p>
        <pre class="box">
        $secret</pre>
        <p>It is deleted from the server as soon as this page has been
        sent and cannot be displayed again. Copy it before leaving this
        page.</p>
        HTML;
}
