<?php

/*
 * Addresses and mail delivery, through the local MTA or SMTP.
 */

declare(strict_types=1);

const EMAIL_MAX = 254;

/*
 * Plain addresses only: a dot-atom local part without the % and ! routing
 * operators, at a host name. Quoted local parts are refused too, some
 * relays look inside the quotes and would deliver to another domain.
 */
const EMAIL_ATOM = '[a-z0-9#$&\'*+\/=?^_`{|}~-]+';
const EMAIL_RE = '/^' . EMAIL_ATOM . '(?:\.' . EMAIL_ATOM . ')*' .
    '@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/D';

/*
 * Return $v as a lowercase address, or null if it is not a plain one.
 * FILTER_VALIDATE_EMAIL adds the length limits of the parts.
 */
function email_normalize(mixed $v): ?string
{
    if (!is_string($v)) {
        return null;
    }
    $e = strtolower(trim($v));
    if (strlen($e) > EMAIL_MAX || preg_match(EMAIL_RE, $e) !== 1 ||
        filter_var($e, FILTER_VALIDATE_EMAIL) === false) {
        return null;
    }
    return $e;
}

function email_domain(string $e): string
{
    return substr($e, (int)strrpos($e, '@') + 1);
}

/**
 * Send a plain text mail, false if it could not be handed over. Every
 * part of the bodies is ASCII, hence 7bit. Lines end with CRLF, as the
 * headers PHP writes for mail().
 *
 * @param array<string, mixed> $cfg
 */
function mail_send(array $cfg, string $to, string $subject,
    string $body): bool
{
    $from = $cfg['mail_from'];
    $headers = [
        'From' => sprintf('"%s" <%s>', $cfg['mail_from_name'], $from),
        'To' => $to,
        'Subject' => $subject,
        'Date' => gmdate('D, d M Y H:i:s +0000'),
        'Message-ID' => sprintf('<%s@%s>', bin2hex(random_bytes(16)),
            email_domain($from)),
        'MIME-Version' => '1.0',
        'Content-Type' => 'text/plain; charset=US-ASCII',
        'Content-Transfer-Encoding' => '7bit',
        'Auto-Submitted' => 'auto-generated',
    ];
    $body = str_replace("\n", "\r\n", $body);

    if ($cfg['mail_transport'] === 'smtp') {
        $msg = '';
        foreach ($headers as $k => $v) {
            $msg .= "$k: $v\r\n";
        }
        try {
            smtp_send($cfg, $from, $to, "$msg\r\n$body");
        } catch (RuntimeException $e) {
            error_log('sherpass: ' . $e->getMessage());
            return false;
        }
        return true;
    }
    unset($headers['To'], $headers['Subject']);
    return mail($to, $subject, $body, $headers, '-f' . $from);
}

/**
 * @param array<string, mixed> $cfg
 */
function mail_sender(array $cfg, string $to, string $link): bool
{
    $ttl = duration($cfg['token_ttl']);
    /*
     * The link must be the only URL: mail clients make links of URLs, and
     * once Safe Links wraps them all, another one looks just like it.
     */
    $body = <<<TXT
        A request to share a password from $to was made.

        To continue, open this link within $ttl:

        $link

        The link can be used to share one password. If you did not make
        this request, ignore this mail.

        TXT;
    return mail_send($cfg, $to, 'Confirm your email address to share a ' .
        'password',
        $body);
}

/**
 * @param array<string, mixed> $cfg
 */
function mail_recipient(array $cfg, string $to, string $sender,
    string $code): bool
{
    $ttl = duration($cfg['token_ttl']);
    $body = <<<TXT
        $sender has shared a password with you.

        To display it, enter this code within $ttl on the page where you
        asked for it:

        $code

        If that page is closed, open the link $sender gave you again, it
        has a field for the code. The password can be displayed only once.
        It is deleted from the server right after.

        TXT;
    return mail_send($cfg, $to, 'A password has been shared with you', $body);
}

/**
 * @param array<string, mixed> $cfg
 */
function mail_cancel(array $cfg, string $to, string $rcpt, string $expires,
    string $link): bool
{
    $body = <<<TXT
        You have shared a password with $rcpt. It can be displayed once,
        until $expires.

        To delete it before it is displayed, open this link:

        $link

        It leads to a page with a button, nothing is deleted before you
        press it. Once the password has been displayed or has expired, the
        link no longer works.

        TXT;
    return mail_send($cfg, $to, 'You have shared a password', $body);
}
