<?php

/*
 * Addresses and mail delivery through the local MTA.
 */

declare(strict_types=1);

const EMAIL_MAX = 254;

/*
 * Return $v as a lowercase address, or null if it is not a valid one.
 */
function email_normalize(mixed $v): ?string
{
    if (!is_string($v)) {
        return null;
    }
    $e = strtolower(trim($v));
    if (strlen($e) > EMAIL_MAX || strpbrk($e, "\r\n") !== false ||
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
 * Send a plain text mail, false if the MTA refused it. PHP writes the
 * headers with CRLF, so the body gets the same line endings.
 *
 * @param array{mail_from: string, mail_from_name: string} $cfg
 */
function mail_send(array $cfg, string $to, string $subject,
    string $body): bool
{
    $headers = [
        'From' => sprintf('"%s" <%s>', $cfg['mail_from_name'],
            $cfg['mail_from']),
        'MIME-Version' => '1.0',
        'Content-Type' => 'text/plain; charset=UTF-8',
        'Content-Transfer-Encoding' => '8bit',
        'Auto-Submitted' => 'auto-generated',
    ];
    return mail($to, $subject, str_replace("\n", "\r\n", $body), $headers,
        '-f' . $cfg['mail_from']);
}

/**
 * @param array{base_url: string, mail_from: string, mail_from_name: string,
 *     token_ttl: int} $cfg
 */
function mail_sender(array $cfg, string $to, string $link): bool
{
    $ttl = duration($cfg['token_ttl']);
    $body = <<<TXT
        A request to share a password from $to was made on
        {$cfg['base_url']}

        To continue, open this link within $ttl:

        $link

        The link can be used to share one password. If you did not make
        this request, ignore this mail.

        TXT;
    return mail_send($cfg, $to, 'Confirm your address to share a password',
        $body);
}

/**
 * @param array{mail_from: string, mail_from_name: string, token_ttl: int} $cfg
 */
function mail_recipient(array $cfg, string $to, string $sender,
    string $link): bool
{
    $ttl = duration($cfg['token_ttl']);
    $body = <<<TXT
        $sender has shared a password with you.

        To display it, open this link within $ttl:

        $link

        The password can be displayed only once. It is deleted from the
        server right after.

        TXT;
    return mail_send($cfg, $to, 'A password has been shared with you', $body);
}
