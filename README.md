<p align="center">
  <img src="docs/logo.svg" width="128" alt="sherpass">
</p>

<h1 align="center">sherpass</h1>

<p align="center">
  <img src="https://img.shields.io/badge/PHP-8.0%2B-777BB4?logo=php&logoColor=white&style=flat-square" alt="PHP 8.0 or newer"/>
  <img src="https://img.shields.io/badge/platforms-OpenBSD%20%7C%20Debian-green?style=flat-square" alt="OpenBSD, Debian"/>
  <img src="https://img.shields.io/badge/nginx-1.25.1%2B-009639?logo=nginx&logoColor=white&style=flat-square" alt="nginx 1.25.1 or newer"/>
  <img src="https://img.shields.io/badge/JavaScript-none-1C2833?style=flat-square" alt="No JavaScript"/>
  <a href="./LICENSE">
    <img src="https://img.shields.io/badge/license-BSD--2--Clause-orange?style=flat-square" alt="BSD 2-Clause license"/>
  </a>
  <a href="https://www.paypal.me/RenaudAllard">
    <img src="https://img.shields.io/badge/PayPal-Donate-blue.svg?logo=paypal&style=flat-square" alt="PayPal"/>
  </a>
</p>

<p align="center">
  <b>Share one password with one person, once.</b><br/>
  The sender proves an address in an allowed domain, the recipient proves
  theirs by mail, and the password is displayed a single time before it
  is deleted.
</p>

---

Plain PHP with sodium and SQLite: no framework, no Composer, no
JavaScript. The key that decrypts a password is never stored and never
mailed, it only lives in the share link, so neither the database nor a
mailbox alone reveals the password. It runs as is in the chroot OpenBSD
gives nginx and php-fpm.

## Features

- **One display** - the password is shown once, then deleted from the
  server as soon as the page has been sent
- **Verified sender** - only addresses in `allowed_domains` can share,
  after confirming the address with a mailed link
- **Verified recipient** - anyone can open a share link, but only the
  recipient mailbox receives the code that, entered on the share page,
  displays the password, and the page does not tell who the recipient is
- **Key out of the server** - the database holds XChaCha20-Poly1305
  ciphertext and a keyed hash of the recipient, the key is only in the
  share link, never in a mail
- **Mail scanners** - the code mail holds no link, and following the
  sender link consumes nothing
- **No JavaScript** - strict Content-Security-Policy, no external
  resources, nothing cached
- **Mail** - through the local MTA, or over SMTP with TLS or STARTTLS,
  verified certificates and AUTH PLAIN or LOGIN
- **Rate limits** - per client, per sender address and per password,
  all configurable
- **Chroot** - runs in the default OpenBSD chroot of nginx and php-fpm
  with nothing but its own files
- **No cron** - expired rows are purged as requests come in

---

## How it works

1. The sender enters their address on the site. If its domain is in
   `allowed_domains`, a link is mailed to it.
2. The link leads to a form where the sender enters the password and the
   recipient address. Submitting it returns a share link. A sender link
   can be used for one password only.
3. The share link can be sent to the recipient by any means. Whoever
   opens it is asked for their address. If it is the recipient address,
   a code is mailed to it. The page says the same thing either way, so
   the share link alone does not reveal who the recipient is.
4. The recipient enters the code on the share page, which displays the
   password. The password is deleted from the server right after the
   page has been sent. Displaying it thus takes both the share link and
   the recipient mailbox.

The sender link and the code are valid for `token_ttl` seconds, 30
minutes by default. An unclaimed password is deleted after `secret_ttl`
seconds, 30 days by default. Asking again for a code replaces the
previous one. The share page also has a field for a code received
earlier.

## Install

| | |
| --- | --- |
| **PHP** | 8.0 or later with the sodium and pdo_sqlite extensions, run through php-fpm. Developed with PHP 8.4, tested on OpenBSD 8.0 and Debian |
| **Web server** | nginx 1.25.1 or later for the example configuration, which uses `http2 on`, or another web server |
| **Mail** | a local MTA providing `sendmail`, for instance Exim, Postfix or OpenSMTPD, or an SMTP server, see `mail_transport`. With `sendmail`, the default `sendmail_path` (`/usr/sbin/sendmail -t -i` on Debian) is fine. Either way, the server must be allowed to send mail as `mail_from`, with SPF and DKIM set up for its domain or the mails will likely be flagged as spam |

### OpenBSD

nginx and php-fpm both run in a chroot in `/var/www`, and sherpass lives
inside it. Install the packages and fetch the repository into
`/var/www/sherpass`:

```sh
pkg_add php-pdo_sqlite%8.4 nginx
ln -sf ../php-8.4.sample/pdo_sqlite.ini /etc/php-8.4/
ftp -o - https://github.com/renaudallard/sherpass/archive/refs/heads/main.tar.gz |
    tar xzf - -C /var/www
mv /var/www/sherpass-main /var/www/sherpass
```

With the git package, `git clone https://github.com/renaudallard/sherpass.git
/var/www/sherpass` does the same. Only `public/` and `src/` run, and they
must stay side by side; the rest holds the examples used below and the
tests. Then:

```sh
install -d -o www -g www -m 0700 /var/www/sherpass/db
install -g www -m 0640 /var/www/sherpass/sherpass.ini.example \
    /var/www/sherpass/sherpass.ini
```

Paths in `sherpass.ini` are the ones php-fpm sees, without `/var/www`,
and mail is best handed to smtpd(8), which listens on lo0:

```ini
db_path = "/sherpass/db/sherpass.db"
mail_transport = smtp
smtp_host = 127.0.0.1
smtp_tls = off
```

The default `/etc/php-fpm.conf` already runs its pool as www in the
chroot, listening on `/var/www/run/php-fpm.sock`. Have PHP log to syslog
by adding to the pool:

```ini
php_admin_value[error_log] = syslog
php_admin_flag[log_errors] = on
```

From the chroot, syslog(3) still reaches syslogd through sendsyslog(2),
with no file to create or rotate. The lines land in `/var/log/messages`,
tagged `php`.

Copy `nginx/sherpass.conf.example` to `/etc/nginx/sherpass.conf`,
include it from the `http` block of `/etc/nginx/nginx.conf`, and set,
besides `server_name` and the certificate paths:

```nginx
access_log /var/www/logs/sherpass.access.log sherpass;
fastcgi_pass unix:run/php-fpm.sock;
```

`root /var/www/sherpass/public` stays as it is: nginx removes its chroot
from it, so `$document_root/index.php` is also the path php-fpm sees.
Then:

```sh
rcctl enable php84_fpm nginx
rcctl start php84_fpm nginx
```

### Debian

```sh
apt install nginx php8.4-fpm php8.4-sqlite3
git clone https://github.com/renaudallard/sherpass.git /var/www/sherpass
install -d -o www-data -g www-data -m 0700 /var/lib/sherpass
install -d -o www-data -g adm -m 0750 /var/log/sherpass
install -d -m 0755 /etc/sherpass
install -g www-data -m 0640 /var/www/sherpass/sherpass.ini.example \
    /etc/sherpass/sherpass.ini
```

Edit `/etc/sherpass/sherpass.ini`. It may hold the SMTP password, keep
it readable by root and www-data only. Give PHP its own log in the
php-fpm pool, for instance in `/etc/php/8.4/fpm/pool.d/www.conf`:

```ini
php_admin_value[error_log] = /var/log/sherpass/php.log
php_admin_flag[log_errors] = on
```

Then set up nginx:

```sh
cp /var/www/sherpass/nginx/sherpass.conf.example \
    /etc/nginx/sites-available/sherpass
ln -s ../sites-available/sherpass /etc/nginx/sites-enabled/sherpass
```

Adjust `server_name`, the certificate paths and the php-fpm socket, and
tell sherpass where its configuration is, in the `location = /` block:

```nginx
fastcgi_param SHERPASS_CONFIG /etc/sherpass/sherpass.ini;
```

Then run `nginx -t && systemctl reload nginx`.

### The nginx example

It only passes `/` to PHP, serves `style.css` and returns 404 for
anything else. Its request body buffer is as large as the largest
accepted body: nginx writes bigger bodies to a temporary file, and the
compose form carries the password in clear.

sherpass reads `sherpass.ini` from its top directory, next to `public/`
and `src/`, unless the `SHERPASS_CONFIG` FastCGI parameter names another
file, as in the Debian setup above.

## Serving under a path

To serve sherpass under a path of an existing site, say
`https://example.com/sherpass/`, set
`base_url = "https://example.com/sherpass"`. The access log format of the
example has to be known before the `server` block of that site uses it:
put it in the `http` block, or at the top of the file holding that
`server` block:

```nginx
log_format sherpass '$remote_addr - $remote_user [$time_local] '
                    '"$request_method $uri $server_protocol" $status '
                    '$body_bytes_sent "$http_user_agent"';
```

Then put these locations in the `server` block. On OpenBSD, with php-fpm
in its chroot:

```nginx
location = /sherpass {
    return 301 /sherpass/;
}

location = /sherpass/ {
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME /sherpass/public/index.php;
    fastcgi_pass unix:run/php-fpm.sock;
    client_max_body_size 64k;
    client_body_buffer_size 64k;
    access_log /var/www/logs/sherpass.access.log sherpass;
}

location = /sherpass/style.css {
    alias /var/www/sherpass/public/style.css;
}

location ^~ /sherpass/ {
    return 404;
}
```

`SCRIPT_FILENAME` is the path php-fpm sees, which nginx passes as it is,
while it removes its chroot from `alias` as it does from `root`. The
redirect matters: the pages use relative links, which only resolve with
the final slash. On Debian, `SCRIPT_FILENAME` is
`/var/www/sherpass/public/index.php`, the socket and the log go where the
Debian setup puts them, and the `SHERPASS_CONFIG` line of that setup goes
in the `location = /sherpass/` block.

## Running in a chroot

sherpass only needs its own tree and the database directory, which is
how it runs on OpenBSD, where PHP logs to syslog. In any chroot:

- **Paths** - those in `sherpass.ini` and in `SHERPASS_CONFIG` are the
  ones php-fpm sees inside the chroot
- **Mail** - `mail()` runs `/bin/sh` and `sendmail`, which a chroot does
  not have: use `mail_transport = smtp`
- **Names** - on Linux, give `smtp_host` as an address: without
  `/etc/hosts` in the chroot, glibc cannot resolve `localhost`. OpenBSD
  resolves it anyway. Other names need `/etc/resolv.conf` in the chroot
- **TLS** - checking a certificate needs the CA certificates in the
  chroot: point `smtp_cafile` to a copy inside it. On OpenBSD, copying
  `/etc/ssl/cert.pem` to `/var/www/etc/ssl/cert.pem` works as well
- **Time zones** - Debian patches PHP to read them from
  `/usr/share/zoneinfo`, and every line PHP logs starts with the time.
  Without `usr/share/zoneinfo/UTC` in the chroot, a php-fpm worker
  crashes as soon as PHP logs something. OpenBSD's PHP uses its built-in
  time zone data and needs nothing

## Configuration

`sherpass.ini` is a plain INI file. Unknown keys and invalid values are
rejected, and the site then answers every request with an error and logs
the reason. `smtp_*` settings are refused unless `mail_transport` is
`smtp`, so that they cannot be left unused by mistake.
`base_url`, `mail_from`, `allowed_domains` and `db_path` are mandatory,
the other settings have defaults. A setting written `null` is an error,
not a way to ask for the default.

| Key | Meaning |
| --- | --- |
| `base_url` | Public URL of the site, used to build the sender link and the share link, at most 256 characters. Must use https, plain http is only accepted for localhost. |
| `mail_from` | Sender address of every mail. |
| `mail_from_name` | Display name of the sender, 1 to 64 printable ASCII characters without quotes or backslashes. Defaults to `Sherpass`. |
| `allowed_domains[]` | Domain allowed to share passwords, one line per domain. Exact match, subdomains are not included. |
| `db_path` | Absolute path of the SQLite database. Its directory must be writable by the PHP user and lie outside the web root. |
| `secret_ttl` | Lifetime of an unclaimed password, in seconds, at most 31536000 (a year). Default 2592000 (30 days). |
| `token_ttl` | Lifetime of the sender link and of the recipient code sent by mail, in seconds, at most 86400 (a day). Default 1800 (30 minutes). |
| `ip_limit` | Requests that can send a mail, an address entered on the start page or on a share page, per client and per hour. A client is an IPv4 address or an IPv6 /64. Default 30. Raise it if many users share one address, behind NAT for instance. |
| `sender_limit` | Sender mails per address per hour. Default 3. |
| `recipient_limit` | Codes mailed per password per hour. Default 3. |
| `recipient_delay` | Minimum delay between two codes mailed for the same password, in seconds, 0 to 3600. Default 60. |
| `mail_transport` | `sendmail` to hand mails to the local MTA through PHP `mail()`, `smtp` to talk to an SMTP server directly. Default `sendmail`, which refuses any `smtp_*` setting. |
| `smtp_host` | SMTP server name or IP address, mandatory with `smtp`. |
| `smtp_tls` | `tls` for TLS from the start, `starttls` to upgrade a plain connection, `off` for a relay without TLS, only accepted when `smtp_host` is `localhost`, in 127.0.0.0/8 or `::1`. Default `tls`. |
| `smtp_port` | SMTP port. Default 465 with `tls`, 587 with `starttls`, 25 with `off`. |
| `smtp_user`, `smtp_password` | Credentials, set both or none. AUTH PLAIN is used, or AUTH LOGIN if the server only offers that. They require TLS. |
| `smtp_cafile` | Absolute path of a file with the CA certificates to verify the server with, for a private CA. The system CAs are used otherwise. |
| `smtp_tls_verify` | `off` skips the certificate check. Only accepted when `smtp_host` is `localhost`, in 127.0.0.0/8 or `::1`. Default `on`. |

A mail that could not be sent counts against none of the rate limits.

Put `smtp_user` and `smtp_password` between single quotes. Inside double
quotes, `${...}` is expanded, and unquoted values such as `yes`, `none`
or numbers are turned into booleans or integers and rejected.

## Security

- **Share key** - a random 256-bit key, never stored and never mailed.
  The database id, the encryption key and the key used to hash the
  recipient address are derived from it. The password is encrypted with
  XChaCha20-Poly1305 and the recipient address is only kept as a keyed
  BLAKE2b hash, so a copy of the database, including its deleted pages,
  reveals neither the password nor the recipient, even together with the
  mails. SQLite `secure_delete` is enabled as well
- **Code** - the recipient gets a code rather than a link. It only works
  together with the share key, which the sender hands over by other
  means, so a mailbox alone is not enough to display the password
- **Tokens** - every token, the code included, is 256 bits of
  randomness, only its SHA-256 is stored, and each one works once
- **Mail scanners** - they fetch the links they find in mail. Following
  the sender link never consumes anything, it leads to a form, and the
  code mail holds no link at all
- **One display** - the secret is first marked as claimed, in a
  transaction that serializes concurrent requests, so only one of them
  can display it. The page is then handed to the web server with
  `fastcgi_finish_request()` and only after that is the secret deleted.
  A client going away does not stop the deletion. If PHP dies in
  between, the claimed secret can no longer be displayed and is purged
  with the expired rows 5 minutes later
- **Recipient privacy** - the claim page says the same thing whether the
  address matched or not, and nothing that depends on the address is
  done before it has been sent, so neither its text nor its response
  time tells whether the address matched
- **Links** - built from `base_url`, never from the request `Host` header
- **Addresses** - only plain addresses are accepted, with no quoted
  local part and no % or ! routing operator, which some relays follow
  to another domain
- **Pages** - sent with a strict Content-Security-Policy, no JavaScript,
  `Referrer-Policy: no-referrer` and `Cache-Control: no-store`. The
  password field disables browser spellcheck, which may send its content
  to a remote service
- **SMTP** - TLS 1.2 or later, from the start or through STARTTLS, which
  is then mandatory: a server that does not offer it is not used.
  Certificates are verified against the system CAs or `smtp_cafile`.
  TLS, or only the certificate check, can be turned off for a server on
  the loopback interface, nowhere else. Credentials are never sent
  without TLS. The whole dialogue must end within 30 seconds, however
  slowly the server answers
- **Rate limits** - see `ip_limit`, `sender_limit`, `recipient_limit`
  and `recipient_delay` under [Configuration](#configuration)

## Logging

Tokens travel in query strings. Once used or expired they are worthless,
but until then they should not end up in logs:

- **Access log** - the example nginx configuration logs `$uri`, which
  leaves the query string out, instead of `$request`
- **Error log** - nginx adds the full request line to its error log
  entries. That includes PHP errors when php-fpm returns them over
  FastCGI, which it does when PHP has no `error_log`. The installation
  steps above give PHP its own log for that reason

## Tests

```sh
tests/run.sh
```

The script needs php-cli, php-sqlite3, curl and openssl. It checks the
configuration validation, then runs the whole flow against the PHP
built-in server on 127.0.0.1:8089 (set `PORT` to change it). Mails are
stored as files instead of being sent. SMTP delivery is then tested
against `tests/smtpd.php` listening on the four following ports, with
TLS, STARTTLS, without TLS and with long credentials, using a
certificate made for the run. Everything is written to `tmp/test`.

## Layout

```
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
docs/logo.svg                 logo
```

## Limitations

- Someone who has both the share link and access to the recipient
  mailbox can display the password
- A compromised server sees passwords as they are submitted and
  displayed
- The recipient needs the share link at hand to enter the code: if the
  page where the code was asked is closed, the share link opens it again
- Without JavaScript, the display button cannot be disabled once
  pressed. A browser shows the answer to the last press, so a double
  click displays "already used" while the first press consumed the
  password. The page asks to press it only once
- The work and the mail that follow a matching claim keep a php-fpm
  worker busy for a moment, which can only show when no other worker is
  free
- Behind a reverse proxy, every request comes from the proxy address,
  so `ip_limit` applies to all users together
- Passwords are limited to 4096 characters

## License

BSD 2-Clause, see [LICENSE](LICENSE).
