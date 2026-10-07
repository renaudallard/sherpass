<?php

/*
 * Sherpass: share one password with one person.
 *
 * GET  /             ask the sender address
 * POST / email       mail a sender link (?v=)
 * GET  /?v=          ask the password and the recipient
 * POST / v           store the secret, show the share link (?s=)
 * GET  /?s=          ask the recipient address
 * POST / s           mail a reveal link (?s=&r=) if the address matches
 * GET  /?s=&r=       ask confirmation, mail scanners only fetch links
 * POST / s r         display the password, then delete it
 */

declare(strict_types=1);

ini_set('display_errors', '0');

require __DIR__ . '/../src/config.php';
require __DIR__ . '/../src/crypto.php';
require __DIR__ . '/../src/db.php';
require __DIR__ . '/../src/mail.php';
require __DIR__ . '/../src/view.php';

function main(array $cfg, PDO $db, int $now): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? '';
    if ($method === 'POST') {
        $in = $_POST;
        if (isset($in['v'])) {
            do_compose($cfg, $db, $now);
        } elseif (isset($in['s'], $in['r'])) {
            do_reveal($db, $now);
        } elseif (isset($in['s'])) {
            do_claim($cfg, $db, $now);
        } else {
            do_start($cfg, $db, $now);
        }
    } elseif ($method === 'GET' || $method === 'HEAD') {
        $in = $_GET;
        if (isset($in['v'])) {
            page_compose($db, $now);
        } elseif (isset($in['s'], $in['r'])) {
            page_reveal($db, $now);
        } elseif (isset($in['s'])) {
            page_claim($db, $now);
        } else {
            respond(200, 'Share a password', view_start());
        }
    } else {
        header('Allow: GET, HEAD, POST');
        respond(405, 'Error', view_message('Method not allowed.'));
    }
}

function invalid(): void
{
    respond(404, 'Invalid link', view_message('This link is invalid, ' .
        'has expired or has already been used.'));
}

function too_many(): void
{
    respond(429, 'Error', view_message('Too many requests. Try again ' .
        'later.'));
}

function ip_key(): string
{
    return 'ip:' . ($_SERVER['REMOTE_ADDR'] ?? '');
}

/*
 * Complete the response before doing more work. Under php-fpm this hands
 * the whole page to the web server and ends the request.
 */
function finish_response(): void
{
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
        return;
    }
    while (ob_get_level() > 0) {
        ob_end_flush();
    }
    flush();
}

function do_start(array $cfg, PDO $db, int $now): void
{
    $title = 'Share a password';
    $email = email_normalize($_POST['email'] ?? null);
    if ($email === null) {
        respond(400, $title, view_start('This is not a valid address.'));
        return;
    }
    if (!in_array(email_domain($email), $cfg['allowed_domains'], true)) {
        respond(403, $title, view_start('This address is not allowed to ' .
            'share passwords.', $email));
        return;
    }

    $token = token_new();
    $ip = ip_key();
    $from = 'from:' . $email;
    $ok = db_tx($db, function () use ($db, $now, $cfg, $token, $email,
        $ip, $from): bool {
        if (!throttle_ok($db, $ip, $cfg['ip_limit'], THROTTLE_WINDOW,
            $now) || !throttle_ok($db, $from, $cfg['sender_limit'],
            THROTTLE_WINDOW, $now)) {
            return false;
        }
        throttle_hit($db, $ip, $now);
        throttle_hit($db, $from, $now);
        db_query($db, 'INSERT INTO sender (hash, email, expires) ' .
            'VALUES (?, ?, ?)',
            [token_hash($token), $email, $now + $cfg['token_ttl']]);
        return true;
    });
    if (!$ok) {
        too_many();
        return;
    }

    $link = $cfg['base_url'] . '/?v=' . token_encode($token);
    if (!mail_sender($cfg, $email, $link)) {
        error_log("sherpass: cannot send mail to $email");
        respond(500, 'Error', view_message('The mail could not be sent. ' .
            'Try again later.'));
        return;
    }
    respond(200, 'Check your mail',
        view_start_sent($email, duration($cfg['token_ttl'])));
}

function sender_email(PDO $db, string $token, int $now): ?string
{
    $email = db_query($db, 'SELECT email FROM sender ' .
        'WHERE hash = ? AND expires > ?', [token_hash($token), $now])
        ->fetchColumn();
    return is_string($email) ? $email : null;
}

function page_compose(PDO $db, int $now): void
{
    $token = token_decode($_GET['v']);
    $sender = $token === null ? null : sender_email($db, $token, $now);
    if ($sender === null) {
        invalid();
        return;
    }
    respond(200, 'Share a password', view_compose($_GET['v'], $sender));
}

function do_compose(array $cfg, PDO $db, int $now): void
{
    $token = token_decode($_POST['v']);
    $sender = $token === null ? null : sender_email($db, $token, $now);
    if ($sender === null) {
        invalid();
        return;
    }

    $title = 'Share a password';
    $v = $_POST['v'];
    $secret = $_POST['secret'] ?? '';
    $rcpt_in = $_POST['rcpt'] ?? '';
    $secret = is_string($secret) ? $secret : '';
    $rcpt_in = is_string($rcpt_in) ? $rcpt_in : '';
    if ($secret === '' || strlen($secret) > SECRET_MAX) {
        respond(400, $title, view_compose($v, $sender, 'The password must ' .
            'be 1 to ' . SECRET_MAX . ' bytes long.', '', $rcpt_in));
        return;
    }
    $rcpt = email_normalize($rcpt_in);
    if ($rcpt === null) {
        respond(400, $title, view_compose($v, $sender, 'The recipient ' .
            'address is not valid.', $secret, $rcpt_in));
        return;
    }

    $key = token_new();
    [$id, $enc, $tag] = secret_keys($key);
    $expires = $now + $cfg['secret_ttl'];
    $ok = db_tx($db, function () use ($db, $now, $token, $id, $enc, $tag,
        $sender, $rcpt, $secret, $expires): bool {
        $st = db_query($db, 'DELETE FROM sender ' .
            'WHERE hash = ? AND expires > ?', [token_hash($token), $now]);
        if ($st->rowCount() !== 1) {
            return false;
        }
        db_query($db, 'INSERT INTO secret ' .
            '(id, sender, rcpt, box, expires) VALUES (?, ?, ?, ?, ?)',
            [$id, $sender, rcpt_tag($rcpt, $tag),
            secret_seal($secret, $id, $enc), $expires]);
        return true;
    });
    if (!$ok) {
        invalid();
        return;
    }
    respond(200, 'Password shared', view_share(
        $cfg['base_url'] . '/?s=' . token_encode($key), $rcpt,
        gmdate('Y-m-d H:i', $expires) . ' UTC'));
}

/*
 * Return the keys derived from share key $s if its secret can still be
 * claimed.
 *
 * @return array{string, string, string}|null
 */
function secret_lookup(PDO $db, mixed $s, int $now): ?array
{
    $key = token_decode($s);
    if ($key === null) {
        return null;
    }
    $keys = secret_keys($key);
    $found = db_query($db, 'SELECT 1 FROM secret ' .
        'WHERE id = ? AND claimed IS NULL AND expires > ?',
        [$keys[0], $now])->fetchColumn();
    return $found === false ? null : $keys;
}

function page_claim(PDO $db, int $now): void
{
    if (secret_lookup($db, $_GET['s'], $now) === null) {
        invalid();
        return;
    }
    respond(200, 'Receive a password', view_claim($_GET['s']));
}

/*
 * The answer is the same whether the address matches or not, and the
 * mail is only sent once the page is out, so that someone holding the
 * share link cannot use it to confirm who the recipient is.
 */
function do_claim(array $cfg, PDO $db, int $now): void
{
    $keys = secret_lookup($db, $_POST['s'], $now);
    if ($keys === null) {
        invalid();
        return;
    }
    [$id, , $tag] = $keys;
    $s = $_POST['s'];
    $email = email_normalize($_POST['email'] ?? null);
    if ($email === null) {
        respond(400, 'Receive a password',
            view_claim($s, 'This is not a valid address.'));
        return;
    }

    $r = token_new();
    $ip = ip_key();
    $name = 'secret:' . $id;
    $sender = null;
    $state = db_tx($db, function () use ($db, $now, $cfg, $id, $tag, $email,
        $r, $ip, $name, &$sender): string {
        if (!throttle_ok($db, $ip, $cfg['ip_limit'], THROTTLE_WINDOW,
            $now)) {
            return 'throttled';
        }
        throttle_hit($db, $ip, $now);
        $row = db_query($db, 'SELECT sender, rcpt FROM secret ' .
            'WHERE id = ? AND claimed IS NULL AND expires > ?',
            [$id, $now])->fetch();
        if ($row === false) {
            return 'invalid';
        }
        if (!hash_equals($row['rcpt'], rcpt_tag($email, $tag)) ||
            !throttle_ok($db, $name, 1, $cfg['recipient_delay'], $now) ||
            !throttle_ok($db, $name, $cfg['recipient_limit'],
            THROTTLE_WINDOW, $now)) {
            return 'done';
        }
        throttle_hit($db, $name, $now);
        db_query($db, 'UPDATE secret SET reveal = ?, reveal_expires = ? ' .
            'WHERE id = ?', [token_hash($r), $now + $cfg['token_ttl'], $id]);
        $sender = $row['sender'];
        return 'mail';
    });
    if ($state === 'throttled') {
        too_many();
        return;
    }
    if ($state === 'invalid') {
        invalid();
        return;
    }
    respond(200, 'Check your mail',
        view_claim_sent(duration($cfg['token_ttl'])));
    if ($state !== 'mail') {
        return;
    }
    finish_response();
    $link = $cfg['base_url'] . '/?s=' . $s . '&r=' . token_encode($r);
    if (!mail_recipient($cfg, $email, $sender, $link)) {
        error_log("sherpass: cannot send the reveal mail of secret $id");
    }
}

/*
 * Return the id, the encryption key, the sender and the encrypted secret
 * if share key $s and reveal token $r are valid.
 *
 * @return array{string, string, string, string}|null
 */
function reveal_lookup(PDO $db, mixed $s, mixed $r, int $now): ?array
{
    $key = token_decode($s);
    $token = token_decode($r);
    if ($key === null || $token === null) {
        return null;
    }
    [$id, $enc] = secret_keys($key);
    $row = db_query($db, 'SELECT sender, box FROM secret WHERE id = ? ' .
        'AND reveal = ? AND reveal_expires > ? AND claimed IS NULL ' .
        'AND expires > ?', [$id, token_hash($token), $now, $now])->fetch();
    if ($row === false) {
        return null;
    }
    return [$id, $enc, $row['sender'], $row['box']];
}

function page_reveal(PDO $db, int $now): void
{
    $found = reveal_lookup($db, $_GET['s'], $_GET['r'], $now);
    if ($found === null) {
        invalid();
        return;
    }
    respond(200, 'Receive a password',
        view_reveal($_GET['s'], $_GET['r'], $found[2]));
}

/*
 * The secret is claimed first so that the link works only once, even
 * for concurrent requests. It is deleted once the page has been handed
 * to the web server, and a client going away must not stop that.
 */
function do_reveal(PDO $db, int $now): void
{
    ignore_user_abort(true);
    $found = db_tx($db, function () use ($db, $now): ?array {
        $found = reveal_lookup($db, $_POST['s'], $_POST['r'], $now);
        if ($found === null) {
            return null;
        }
        db_query($db, 'UPDATE secret SET reveal = NULL, ' .
            'reveal_expires = NULL, claimed = ? WHERE id = ?',
            [$now, $found[0]]);
        return $found;
    });
    if ($found === null) {
        invalid();
        return;
    }
    [$id, $enc, $sender, $box] = $found;
    $secret = secret_open($box, $id, $enc);
    if ($secret === null) {
        db_query($db, 'DELETE FROM secret WHERE id = ?', [$id]);
        throw new RuntimeException("cannot decrypt secret $id");
    }
    respond(200, 'Your password', view_secret($secret, $sender));
    finish_response();
    db_query($db, 'DELETE FROM secret WHERE id = ?', [$id]);
    sodium_memzero($secret);
}

try {
    $cfg = config_load(getenv('SHERPASS_CONFIG') ?:
        dirname(__DIR__) . '/sherpass.ini');
    $db = db_open($cfg['db_path']);
    $now = time();
    db_purge($db, $now);
    main($cfg, $db, $now);
} catch (Throwable $e) {
    error_log('sherpass: ' . $e->getMessage() . ' at ' . $e->getFile() .
        ':' . $e->getLine());
    if (!headers_sent()) {
        respond(500, 'Error', view_message('Internal error.'));
    }
}
