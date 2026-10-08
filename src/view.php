<?php

/*
 * HTML pages. Every dynamic value goes through h().
 */

declare(strict_types=1);

/*
 * Seconds a displayed password stays on screen. style.css hides it after
 * the same time, keep both equal.
 */
const SECRET_SHOWN = 300;

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

function utc(int $t): string
{
    return gmdate('Y-m-d H:i', $t) . ' UTC';
}

/*
 * With $refresh, the browser replaces the page with the start page after
 * that many seconds.
 */
function respond(int $status, string $title, string $body,
    int $refresh = 0): void
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
    $meta = $refresh > 0 ?
        "<meta http-equiv=\"refresh\" content=\"$refresh;url=./\">\n" : '';
    $page = <<<HTML
        <!doctype html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        $meta<title>$title - Sherpass</title>
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
        $err<p>Enter your email address. You will receive a link to share a
        password.</p>
        <form method="post" action="./">
        <label for="email">Your email address</label>
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

/**
 * Lifetimes a sender can pick: the usual ones shorter than secret_ttl,
 * then secret_ttl itself, the default.
 *
 * @return list<int>
 */
function lifetimes(int $max): array
{
    $usual = array_filter([3600, 86400, 604800, 2592000],
        fn(int $t): bool => $t < $max);
    return [...$usual, $max];
}

/*
 * A textarea drops the first newline of its content, so one is always
 * emitted to keep a leading newline of the secret. The form is sent as
 * multipart: PHP writes an urlencoded body of 16k or more, which a long
 * password can make, to a temporary file, but not a multipart one.
 */
function view_compose(string $v, string $sender, int $max_ttl, int $ttl,
    string $error = '', string $secret = '', string $rcpt = '',
    bool $notify = false): string
{
    $err = view_error($error);
    $v = h($v);
    $sender = h($sender);
    $secret = h($secret);
    $rcpt = h($rcpt);
    $max = SECRET_MAX;
    $emax = EMAIL_MAX;
    $ttls = '';
    foreach (lifetimes($max_ttl) as $t) {
        $sel = $t === $ttl ? ' selected' : '';
        $ttls .= "<option value=\"$t\"$sel>" . h(duration($t)) .
            "</option>\n";
    }
    $checked = $notify ? ' checked' : '';
    return <<<HTML
        $err<p>Sharing as <strong>$sender</strong>.</p>
        <form method="post" action="./" enctype="multipart/form-data">
        <input type="hidden" name="v" value="$v">
        <label for="secret">Password</label>
        <textarea id="secret" name="secret" maxlength="$max" required
         autocomplete="off" autocapitalize="off" spellcheck="false">
        $secret</textarea>
        <p class="muted">Up to $max characters, enough for a PEM
        certificate with its key and passphrase.</p>
        <label for="rcpt">Recipient email address</label>
        <input type="email" id="rcpt" name="rcpt" value="$rcpt"
         maxlength="$emax" autocomplete="off" required>
        <label for="ttl">Delete it if not displayed within</label>
        <select id="ttl" name="ttl">
        $ttls</select>
        <label class="check"><input type="checkbox" name="notify"
         value="1"$checked> Mail me when the password is displayed</label>
        <button type="submit">Share</button>
        </form>
        HTML;
}

function view_share(string $url, string $rcpt, string $expires,
    bool $notify): string
{
    $url = h($url);
    $rcpt = h($rcpt);
    $expires = h($expires);
    $told = $notify ? ' You will get another one when the password is ' .
        'displayed.' : '';
    return <<<HTML
        <p>Send this link to the recipient:</p>
        <pre class="box">$url</pre>
        <p>Anyone can open it, but only <strong>$rcpt</strong> can display
        the password, after entering the code mailed to that email address.
        The password can be displayed once and expires on $expires.</p>
        <p class="muted">You will get a mail with a link to delete the
        password before it is displayed.$told</p>
        <p class="muted">The share link is not stored on the server. If you
        lose it, share the password again.</p>
        HTML;
}

function view_cancel(string $c, string $expires): string
{
    $c = h($c);
    $expires = h($expires);
    return <<<HTML
        <p>This password has not been displayed yet. It expires on
        $expires. Delete it to make its share link stop working.</p>
        <form method="post" action="./">
        <input type="hidden" name="c" value="$c">
        <button type="submit">Delete the password</button>
        </form>
        HTML;
}

function view_claim(string $s, string $error = '',
    string $code_error = ''): string
{
    $err = view_error($error);
    $code = view_code($s, $code_error);
    $s = h($s);
    $emax = EMAIL_MAX;
    return <<<HTML
        $err<p>A password is waiting for its recipient. Enter your email
        address to receive a code that displays it.</p>
        <form method="post" action="./">
        <input type="hidden" name="s" value="$s">
        <label for="email">Your email address</label>
        <input type="email" id="email" name="email" maxlength="$emax"
         autocomplete="email" required autofocus>
        <button type="submit">Continue</button>
        </form>
        <h2>Received a code?</h2>
        $code
        HTML;
}

/*
 * Shown whether the address matched or not, so it has to explain why no
 * mail may come even for the right one.
 */
function view_claim_sent(string $s, int $ttl, int $limit,
    int $delay): string
{
    $code = view_code($s);
    $ttl = h(duration($ttl));
    $rate = $limit === 1 ? 'once' : "$limit times";
    $rate .= ' an hour' . ($delay > 0 ? ', ' . duration($delay) . ' apart' :
        '');
    $rate = h($rate);
    return <<<HTML
        <p>If this is the recipient's email address, a code has been mailed
        to it, within the limits below. Enter it here within $ttl.</p>
        $code
        <p class="muted">No mail? Check the email address and your spam
        folder.
        A code is sent at most $rate, and each new one replaces the
        previous one. If you leave this page, open the share link again to
        enter the code.</p>
        HTML;
}

/*
 * Sending the code displays and deletes the password: a second press
 * would get the answer for a used code, and the browser shows that one.
 */
function view_code(string $s, string $error = ''): string
{
    $err = view_error($error);
    $s = h($s);
    return <<<HTML
        <form method="post" action="./">
        <input type="hidden" name="s" value="$s">
        $err<label for="r">Code from the mail</label>
        <input type="text" id="r" name="r" maxlength="200"
         autocomplete="one-time-code" autocapitalize="off" spellcheck="false"
         required>
        <p class="error">Press the button only once and wait for the page.
        A second press would only show that the code has been used, and
        the password would be lost.</p>
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
    $shown = h(duration(SECRET_SHOWN));
    return <<<HTML
        <p>Password shared by <strong>$sender</strong>:</p>
        <pre class="box secret">
        $secret</pre>
        <p>It is deleted from the server as soon as this page has been
        sent and cannot be displayed again. Copy it now: it disappears
        from this page after $shown.</p>
        HTML;
}
