# Sherpass

Sherpass shares one password with one person. The sender must own an
address in an allowed domain, the recipient must prove they own the
address the password was shared with, and the password can be displayed
only once before it is deleted from the server.

## How it works

1. The sender enters their address on the site. If its domain is in
   `allowed_domains`, a link is mailed to it.
2. The link leads to a form where the sender enters the password and the
   recipient address. Submitting it returns a share link. A sender link
   can be used for one password only.
3. The share link can be sent to the recipient by any means. Whoever
   opens it is asked for their address. If it is the recipient address,
   a link is mailed to it. The page says the same thing either way, so
   the share link alone does not reveal who the recipient is.
4. The mailed link asks for a confirmation, then displays the password.
   The password is deleted from the server right after the page has been
   sent.

Links sent by mail are valid for `token_ttl` seconds, 30 minutes by
default. An unclaimed password is deleted after `secret_ttl` seconds, 30
days by default. Asking again for a recipient link replaces the previous
one.

## Security

* The share link carries a random 256-bit key that is never stored. The
  database id, the encryption key and the key used to hash the recipient
  address are derived from it. The password is encrypted with
  XChaCha20-Poly1305 and the recipient address is only kept as a keyed
  BLAKE2b hash. A copy of the database, a backup or data recovered from
  the disk reveals neither the password nor the recipient. SQLite
  `secure_delete` is enabled as well.
* Every other token is 256 bits of randomness, only its SHA-256 is
  stored, and each one works once.
* Mail security scanners fetch the links they find in mail. Following a
  link never consumes anything: displaying the password requires
  pressing a button, which sends a POST request. The page asks to press
  it only once: a browser shows the answer to the last press, so a
  double click would display "already used" while the first press
  consumed the password.
* When the password is displayed, the secret is first marked as claimed,
  in a transaction that serializes concurrent requests, so only one of
  them can display it. The page is then handed to the web server with
  `fastcgi_finish_request()` and only after that is the secret deleted.
  A client going away does not stop the deletion. If PHP dies in
  between, the claimed secret can no longer be displayed and is purged
  with the expired rows 5 minutes later.
* The recipient link is mailed after the page has been sent, so the
  response time does not tell whether the address matched.
* Links in mail are built from `base_url`, never from the request `Host`
  header.
* Only plain addresses are accepted, with no quoted local part and no %
  or ! routing operator, which some relays follow to another domain.
* Pages are sent with a strict Content-Security-Policy, no JavaScript,
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. The
  password field disables browser spellcheck, which may send its content
  to a remote service.
* Mail goes through the local MTA or directly to an SMTP server. Over
  SMTP, TLS 1.2 or later is used, from the start or through STARTTLS,
  which is then mandatory: a server that does not offer it is not
  used. Certificates are verified against the system CAs or
  `smtp_cafile`, and the check can only be turned off for a server on
  the loopback interface. Credentials are never sent without TLS.
* Expired rows are purged at the start of each request, no cron job is
  needed.

Requests are rate limited, see `ip_limit`, `sender_limit`,
`recipient_limit` and `recipient_delay` below. Passwords are limited to
4096 bytes.

Sherpass cannot protect against someone who has both the share link and
access to the recipient mailbox, or against a compromised server, which
sees passwords as they are submitted and displayed.

## Requirements

* PHP 8.0 or later with the sodium and pdo_sqlite extensions, run through
  php-fpm. Developed and tested with PHP 8.4.
* nginx, or another web server, see below.
* A local MTA providing `sendmail`, for instance Exim, Postfix or
  OpenSMTPD, or an SMTP server, see `mail_transport` below. With
  `sendmail`, the default `sendmail_path` (`/usr/sbin/sendmail -t -i` on
  Debian) is fine. Either way, the server must be allowed to send mail
  as `mail_from`, with SPF and DKIM set up for its domain or the mails
  will likely be flagged as spam.

## Installation on Debian

    apt install nginx php8.4-fpm php8.4-sqlite3
    git clone https://github.com/renaudallard/sherpass.git /var/www/sherpass
    install -d -o www-data -g www-data -m 0700 /var/lib/sherpass
    install -d -o www-data -g adm -m 0750 /var/log/sherpass
    install -d -m 0755 /etc/sherpass
    install -g www-data -m 0640 /var/www/sherpass/sherpass.ini.example \
        /etc/sherpass/sherpass.ini

Edit `/etc/sherpass/sherpass.ini`. It may hold the SMTP password, keep
it readable by root and www-data only. Then set up nginx:

    cp /var/www/sherpass/nginx/sherpass.conf.example \
        /etc/nginx/sites-available/sherpass
    ln -s ../sites-available/sherpass /etc/nginx/sites-enabled/sherpass

Adjust `server_name`, the certificate paths and the php-fpm socket, then
`nginx -t && systemctl reload nginx`.

The example only passes `/` to PHP, serves `style.css` and returns 404
for anything else. It also tells PHP where the configuration is, through
the `SHERPASS_CONFIG` FastCGI parameter. Without it, Sherpass reads
`sherpass.ini` from its top directory.

## Configuration

`sherpass.ini` is a plain INI file. Unknown keys and invalid values are
rejected, and the site then answers every request with an error and logs
the reason. `base_url`, `mail_from`, `allowed_domains` and `db_path` are
mandatory, the other settings have defaults.

| Key | Meaning |
|---|---|
| `base_url` | Public URL of the site, used to build the links sent by mail. Must use https, plain http is only accepted for localhost. |
| `mail_from` | Sender address of every mail. |
| `mail_from_name` | Display name of the sender, printable ASCII without quotes or backslashes. Defaults to `Sherpass`. |
| `allowed_domains[]` | Domain allowed to share passwords, one line per domain. Exact match, subdomains are not included. |
| `db_path` | Absolute path of the SQLite database. Its directory must be writable by the PHP user and lie outside the web root. |
| `secret_ttl` | Lifetime of an unclaimed password, in seconds. Default 2592000 (30 days). |
| `token_ttl` | Lifetime of the links sent by mail, in seconds. Default 1800 (30 minutes). |
| `ip_limit` | POST requests per client IP per hour. Default 30. Raise it if many users share one address, behind NAT for instance. |
| `sender_limit` | Sender mails per address per hour. Default 3. |
| `recipient_limit` | Recipient mails per password per hour. Default 3. |
| `recipient_delay` | Minimum delay between two recipient mails for the same password, in seconds, 0 to 3600. Default 60. |
| `mail_transport` | `sendmail` to hand mails to the local MTA through PHP `mail()`, `smtp` to talk to an SMTP server directly. Default `sendmail`. |
| `smtp_host` | SMTP server name or IP address, mandatory with `smtp`. |
| `smtp_tls` | `tls` for TLS from the start, `starttls` to upgrade a plain connection, `off` for a relay without TLS. Default `tls`. |
| `smtp_port` | SMTP port. Default 465 with `tls`, 587 with `starttls`, 25 with `off`. |
| `smtp_user`, `smtp_password` | Credentials, set both or none. AUTH PLAIN is used, or AUTH LOGIN if the server only offers that. They require TLS. |
| `smtp_cafile` | Absolute path of the CA certificates to verify the server with, for a private CA. The system CAs are used otherwise. |
| `smtp_tls_verify` | `off` skips the certificate check. Only accepted when `smtp_host` is `localhost`, in 127.0.0.0/8 or `::1`. Default `on`. |

Behind a reverse proxy, every request comes from the proxy address, so
`ip_limit` applies to all users together.

Put `smtp_user` and `smtp_password` between single quotes. Inside double
quotes, `${...}` is expanded, and unquoted values such as `yes`, `none`
or numbers are turned into booleans or integers and rejected.

## Logging

Tokens travel in query strings. Once used or expired they are worthless,
but until then they should not end up in logs:

* The example nginx configuration logs `$uri`, which leaves the query
  string out, instead of `$request`.
* nginx adds the full request line to its error log entries. That
  includes PHP errors when php-fpm returns them over FastCGI, which it
  does when PHP has no `error_log`. Give PHP its own log in the php-fpm
  pool, for instance in `/etc/php/8.4/fpm/pool.d/www.conf`:

      php_admin_value[error_log] = /var/log/sherpass/php.log
      php_admin_flag[log_errors] = on

## Tests

    tests/run.sh

The script needs php-cli, php-sqlite3, curl and openssl. It checks the
configuration validation, then runs the whole flow against the PHP
built-in server on 127.0.0.1:8089 (set `PORT` to change it). Mails are
stored as files instead of being sent. SMTP delivery is then tested
against `tests/smtpd.php` listening on the three following ports, with
TLS, STARTTLS and without TLS, using a certificate made for the run.
Everything is written to `tmp/test`.

## Files

    public/index.php              front controller and request handling
    public/style.css              stylesheet
    src/config.php                configuration loading and validation
    src/crypto.php                tokens, key derivation and encryption
    src/db.php                    SQLite storage, expiry and rate limits
    src/mail.php                  addresses and mail
    src/smtp.php                  SMTP client
    src/view.php                  HTML pages
    sherpass.ini.example          example configuration
    nginx/sherpass.conf.example   example nginx virtual host
    tests/run.sh                  tests
    tests/sendmail.sh             sendmail stand-in used by the tests
    tests/smtpd.php               SMTP server used by the tests

## License

BSD 2-Clause, see `LICENSE`.
