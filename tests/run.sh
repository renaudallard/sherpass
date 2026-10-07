#!/bin/sh
#
# Configuration checks and end-to-end test of the whole flow against the
# PHP built-in server. Everything is written to tmp/test, mails included.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
T=$ROOT/tmp/test
PORT=${PORT:-8089}
BASE=http://127.0.0.1:$PORT
MAILDIR=$T/mail
BODY=$T/body
HEADERS=$T/headers

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

ok() {
    echo "ok - $*"
}

# get URL, post URL curl-args...: set STATUS, body and headers in files.
get() {
    request "$1"
}

post() {
    u=$1
    shift
    request "$u" "$@"
}

# The page can be complete before the script ends: claims send their mail
# and reveals delete the password once it is out. Wait for the server to
# log that it closed the connection of the request.
request() {
    u=$1
    shift
    from=$(($(wc -l < "$T/server.log") + 1))
    out=$(curl -s -o "$BODY" -D "$HEADERS" -w '%{http_code} %{local_port}' \
        "$@" "$u")
    STATUS=${out% *}
    i=0
    until tail -n +$from "$T/server.log" |
        grep -q "127.0.0.1:${out#* } Closing"; do
        i=$((i + 1))
        [ $i -lt 100 ] || fail "request to $u did not end"
        sleep 0.1
    done
}

expect() {
    [ "$STATUS" = "$1" ] || fail "$2: status $STATUS, expected $1"
    ok "$2"
}

has() {
    grep -qF -- "$1" "$BODY" || fail "body lacks: $1"
}

nmail() {
    ls "$MAILDIR" 2>/dev/null | wc -l | tr -d ' '
}

# Nothing may be in the PHP log, except where a failure is expected.
noerrors() {
    [ -s "$T/php.log" ] && fail "PHP logged errors $1: $(cat "$T/php.log")"
    ok "no PHP errors logged $1"
}

lastmail() {
    echo "$MAILDIR/$(nmail)"
}

# True if the page displays the content of file $1, escaped and intact.
shown() {
    php -r '$b = file_get_contents($argv[1]);
        $s = "<pre class=\"box\">\n" . htmlspecialchars(
            file_get_contents($argv[2]),
            ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, "UTF-8") . "</pre>";
        exit(str_contains($b, $s) ? 0 : 1);' "$BODY" "$1"
}

# Print $1 repeated $2 times, without head -c that OpenBSD does not have.
repeat() {
    php -r 'echo str_repeat($argv[1], (int)$argv[2]);' "$1" "$2"
}

# A valid code that matches nothing.
rndcode() {
    php -r 'echo bin2hex(random_bytes(32));'
}

# A valid token that matches nothing.
rnd() {
    php -r 'echo sodium_bin2base64(random_bytes(32),
        SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);'
}

sql() {
    php -r '$db = new PDO("sqlite:" . $argv[1]);
        foreach ($db->query($argv[2])->fetchAll(PDO::FETCH_NUM) as $r)
            echo implode("|", $r), "\n";' "$T/sherpass.db" "$1"
}

# Run a sender verification for $1, set V to the sender token.
sender() {
    post "$BASE/" --data-urlencode "email=$1"
    [ "$STATUS" = 200 ] || fail "sender $1: status $STATUS"
    V=$(grep -o "$BASE/?v=[A-Za-z0-9_-]*" "$(lastmail)") ||
        fail "no sender link for $1"
    V=${V#*v=}
}

# Share the content of file $2 from sender token $1 to $3, set S.
share() {
    post "$BASE/" --data-urlencode "v=$1" \
        --data-urlencode "secret@$2" --data-urlencode "rcpt=$3"
    [ "$STATUS" = 200 ] || fail "share: status $STATUS"
    S=$(grep -o "$BASE/?s=[A-Za-z0-9_-]*" "$BODY") || fail "no share link"
    S=${S#*s=}
}

# Claim share key $1 as $2, set R from the mail.
claim() {
    post "$BASE/" --data-urlencode "s=$1" --data-urlencode "email=$2"
    [ "$STATUS" = 200 ] || fail "claim: status $STATUS"
    R=$(grep -o '^[0-9a-f]\{64\}' "$(lastmail)") || fail "no code in the mail"
}

# Write the configuration of the test server, extra settings in $1.
webconfig() {
    cat > "$T/sherpass.ini" <<EOF
base_url = "$BASE"
mail_from = "sherpass@allard.it"
allowed_domains[] = "allard.it"
db_path = "$T/sherpass.db"
$1
EOF
}

rm -rf "$T"
mkdir -p "$T"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 1 -subj /CN=localhost -addext subjectAltName=DNS:localhost \
    -keyout "$T/smtp.key" -out "$T/smtp.crt" 2>/dev/null ||
    fail "cannot create the test certificate"

# Configuration validation.

# A rejection is a RuntimeException, anything else is a bug.
cfgtest() {
    printf '%s\n' "$2" > "$T/cfg.ini"
    r=0
    php -r 'require $argv[1] . "/src/config.php";
        require $argv[1] . "/src/mail.php";
        try {
            config_load($argv[2]);
        } catch (RuntimeException $e) {
            exit(1);
        }' "$ROOT" "$T/cfg.ini" > "$T/cfg.err" 2>&1 || r=$?
    case $r in
    0) r=pass ;;
    1) r=fail ;;
    *) fail "config: $3: crashed: $(cat "$T/cfg.err")" ;;
    esac
    [ "$r" = "$1" ] || fail "config: $3"
    ok "config: $3"
}

GOOD='base_url = "https://pass.allard.it"
mail_from = "sherpass@allard.it"
allowed_domains[] = "allard.it"
db_path = "/var/lib/sherpass/sherpass.db"
secret_ttl = 2592000
token_ttl = 1800'

cfgtest pass "$GOOD" "valid file accepted"
cfgtest pass "$(echo "$GOOD" | sed 's/^allowed_domains.*/allowed_domains = "allard.it"/')" \
    "single domain accepted"
cfgtest fail "$GOOD
colour = blue" "unknown key rejected"
cfgtest fail "$(echo "$GOOD" | sed 's|https://pass|http://pass|')" \
    "plain http rejected"
cfgtest fail "$(echo "$GOOD" | sed '1s|"$|/?a=b"|')" \
    "query in base_url rejected"
cfgtest fail "$(echo "$GOOD" | sed 's/^secret_ttl.*/secret_ttl = 30d/')" \
    "non numeric ttl rejected"
cfgtest fail "$(echo "$GOOD" | sed 's/^token_ttl.*/token_ttl = 0/')" \
    "zero ttl rejected"
cfgtest fail "$(echo "$GOOD" | sed 's/^secret_ttl.*/secret_ttl = 31536001/')" \
    "secret_ttl over a year rejected"
cfgtest fail "$(echo "$GOOD" | sed 's/^token_ttl.*/token_ttl = 86401/')" \
    "token_ttl over a day rejected"
cfgtest pass "$(echo "$GOOD" | sed '/_ttl/d')" "missing ttls use defaults"
cfgtest pass "$GOOD
ip_limit = 500
sender_limit = 1
recipient_limit = 10
recipient_delay = 0" "rate limits accepted"
cfgtest fail "$GOOD
ip_limit = 0" "zero limit rejected"
cfgtest fail "$GOOD
sender_limit = -1" "negative limit rejected"
cfgtest fail "$GOOD
recipient_delay = 3601" "delay over an hour rejected"
cfgtest fail "$GOOD
recipient_limit = many" "non numeric limit rejected"
cfgtest fail "$(echo "$GOOD" | sed '/^allowed_domains/d')" \
    "missing domains rejected"
cfgtest fail "$(echo "$GOOD" | sed 's|^db_path.*|db_path = "sherpass.db"|')" \
    "relative db_path rejected"
cfgtest pass "$GOOD
mail_from_name = \"Sherpass at Allard\"" "ASCII mail_from_name accepted"
cfgtest fail "$GOOD
mail_from_name = \"$(printf 'Sherp\303\240ss')\"" \
    "non ASCII mail_from_name rejected"
cfgtest fail "$(echo "$GOOD" | sed 's/^mail_from.*/mail_from = "nobody"/')" \
    "invalid mail_from rejected"
cfgtest fail "$(echo "$GOOD" |
    sed "s/^mail_from.*/mail_from = \"o'brien@allard.it\"/")" \
    "quote in mail_from rejected"

SMTP="$GOOD
mail_transport = smtp
smtp_host = smtp.example.org"

cfgtest pass "$SMTP" "SMTP with defaults accepted"
cfgtest pass "$SMTP
smtp_tls = starttls
smtp_port = 2587
smtp_user = 'sherpass'
smtp_password = 'p\"a\$s\${HOME};x'
smtp_cafile = $T/smtp.crt" "SMTP with STARTTLS and credentials accepted"
P=$(php -r 'require $argv[1] . "/src/config.php";
    require $argv[1] . "/src/mail.php";
    echo config_load($argv[2])["smtp_password"];' "$ROOT" "$T/cfg.ini")
[ "$P" = 'p"a$s${HOME};x' ] || fail "config: password read as $P"
ok "config: single quoted password kept as written"
cfgtest pass "$GOOD
mail_transport = smtp
smtp_host = localhost
smtp_tls = off" "SMTP without TLS to localhost accepted"
cfgtest fail "$SMTP
smtp_tls = off" "SMTP without TLS to a remote host rejected"
cfgtest fail "$GOOD
mail_transport = pigeon" "unknown transport rejected"
cfgtest fail "$GOOD
mail_transport = smtp" "SMTP without host rejected"
cfgtest fail "$SMTP
smtp_tls = maybe" "invalid smtp_tls rejected"
cfgtest fail "$SMTP
smtp_port = 70000" "invalid smtp_port rejected"
cfgtest fail "$GOOD
mail_transport = smtp
smtp_host = localhost
smtp_tls = off
smtp_user = sherpass
smtp_password = secret" "credentials without TLS rejected"
cfgtest fail "$SMTP
smtp_user = sherpass" "user without password rejected"
cfgtest fail "$SMTP
smtp_user = sherpass
smtp_password = 1234" "unquoted numeric password rejected"
cfgtest fail "$SMTP
smtp_cafile = smtp.crt" "relative smtp_cafile rejected"
cfgtest fail "$SMTP
smtp_cafile = $T/missing.crt" "missing smtp_cafile rejected"
cfgtest fail "$SMTP
smtp_tls_verify = off" "unverified TLS to a remote host rejected"
cfgtest fail "$SMTP
smtp_tls_verify = maybe" "invalid smtp_tls_verify rejected"
cfgtest fail "$GOOD
smtp_host = localhost
smtp_tls = off" "SMTP settings without mail_transport = smtp rejected"
cfgtest fail "$GOOD
mail_transport = sendmail
smtp_tls_verify = off" "SMTP setting with mail_transport = sendmail rejected"
cfgtest fail "$GOOD
smtp_port = 70000" "invalid smtp_port rejected with sendmail"
cfgtest fail "$GOOD
smtp_tls = maybe" "invalid smtp_tls rejected with sendmail"
cfgtest fail "$GOOD
smtp_user = sherpass" "user without password rejected with sendmail"
cfgtest fail "$GOOD
smtp_host = smtp.example.org
smtp_tls = off" "SMTP without TLS to a remote host rejected with sendmail"
cfgtest fail "$GOOD
mail_from_name = \"Sherpass
\"" "newline in mail_from_name rejected"
cfgtest fail "$SMTP
smtp_cafile = $T" "directory as smtp_cafile rejected"
cfgtest fail "$GOOD
allowed_domains[] = \"allard.it.\"" "domain with a final dot rejected"
cfgtest fail "$GOOD
allowed_domains[] = localhost" "single label domain rejected"
cfgtest fail "$(echo "$GOOD" | sed "1s|\"\$|/$(repeat a 250)\"|")" \
    "overlong base_url rejected"
cfgtest pass "$GOOD
mail_transport = smtp
smtp_host = localhost
smtp_tls_verify = \"off\"" "quoted off accepted for smtp_tls_verify"
cfgtest fail "$GOOD
mail_transport = null" "null mail_transport rejected"
cfgtest fail "$SMTP
smtp_tls = null" "null smtp_tls rejected"
for h in localhost 127.0.0.1 127.1.2.3 ::1; do
    cfgtest pass "$GOOD
mail_transport = smtp
smtp_host = $h
smtp_tls_verify = off" "unverified TLS to $h accepted"
done

# Rate limiting name of a client address.
iptest() {
    r=$(php -r 'require $argv[1] . "/src/db.php";
        $_SERVER["REMOTE_ADDR"] = $argv[2];
        echo throttle_ip();' "$ROOT" "$1")
    [ "$r" = "$2" ] || fail "client $1 counted as $r"
    ok "client $1 counted as $2"
}

iptest 192.0.2.7 ip:192.0.2.7
iptest 2001:db8:1:2:aaaa::1 ip:2001:db8:1:2::/64
iptest 2001:db8:1:2:ffff:1:2:3 ip:2001:db8:1:2::/64
iptest ::ffff:192.0.2.7 ip:192.0.2.7

# End-to-end flow.

webconfig ""

SHERPASS_CONFIG=$T/sherpass.ini PHP_CLI_SERVER_WORKERS=4 \
    php -d sendmail_path="$ROOT/tests/sendmail.sh $MAILDIR" \
    -d log_errors=1 -d error_log="$T/php.log" \
    -S "127.0.0.1:$PORT" -t "$ROOT/public" > "$T/server.log" 2>&1 &
BG=$!
trap 'kill $BG 2>/dev/null' EXIT INT TERM

i=0
until grep -q 'Development Server .* started' "$T/server.log"; do
    grep -q 'Failed to listen' "$T/server.log" &&
        fail "server did not start: $(cat "$T/server.log")"
    i=$((i + 1))
    [ $i -lt 50 ] || fail "server did not start"
    sleep 0.1
done

get "$BASE/"
expect 200 "start page"
has 'name="email"'
grep -qi "^content-security-policy: default-src 'none'" "$HEADERS" ||
    fail "no CSP header"
grep -qi '^cache-control: no-store' "$HEADERS" || fail "no no-store header"
grep -qi '^referrer-policy: no-referrer' "$HEADERS" ||
    fail "no referrer policy"
grep -qi '^x-powered-by' "$HEADERS" && fail "X-Powered-By sent"
ok "security headers"

post "$BASE/" --data-urlencode "email=nobody"
expect 400 "invalid sender address rejected"
for a in bob@example.com bob@sub.allard.it bob@allard.it.example.com; do
    post "$BASE/" --data-urlencode "email=$a"
    expect 403 "sender $a rejected"
done
for a in 'x%evil.example@allard.it' 'evil.example!x@allard.it' \
    '"x@evil.example"@allard.it' '"alice"@allard.it' 'a@[127.0.0.1]'; do
    post "$BASE/" --data-urlencode "email=$a"
    expect 400 "sender $a rejected"
done
post "$BASE/" --data 'email=%22a%5C%00b%22%40allard.it'
expect 400 "sender with an escaped NUL rejected"
[ "$(nmail)" = 0 ] || fail "mail sent for a rejected sender"
ok "no mail for rejected senders"

sender " Alice@Allard.IT "
ok "sender verification mail sent"
M=$(lastmail)
grep -q '^To: alice@allard.it' "$M" || fail "mail To"
grep -q '^From: "Sherpass" <sherpass@allard.it>' "$M" || fail "mail From"
grep -q '^Auto-Submitted: auto-generated' "$M" || fail "mail Auto-Submitted"
php -r 'exit(preg_match("/(?<!\r)\n/", file_get_contents($argv[1])));' "$M" ||
    fail "bare LF in mail"
ok "sender mail headers and line endings"

get "$BASE/?v=AAAA"
expect 404 "malformed sender token rejected"
get "$BASE/?v=$(rnd)"
expect 404 "unknown sender token rejected"
get "$BASE/?v=$V"
expect 200 "compose page"
has 'alice@allard.it'

printf '\n  p<b>a&s"s'"'"'\n\tw\303\251rd \342\202\254 ' > "$T/secret"
: > "$T/empty"
repeat x 4097 > "$T/big"
php -r 'echo str_repeat("\u{e9}", 4097);' > "$T/bigutf8"
php -r 'echo str_repeat("\u{e9}", 2000), "\r\n", str_repeat("x", 2095);' \
    > "$T/fullutf8"

post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/empty" \
    --data-urlencode "rcpt=bob@example.org"
expect 400 "empty password rejected"
post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/big" \
    --data-urlencode "rcpt=bob@example.org"
expect 400 "oversized password rejected"
post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/bigutf8" \
    --data-urlencode "rcpt=bob@example.org"
expect 400 "password over 4096 characters rejected"
has '1 to 4096 characters'
printf 'ab\377cd' > "$T/binary"
post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/binary" \
    --data-urlencode "rcpt=bob@example.org"
expect 400 "password with invalid UTF-8 rejected"
has 'bytes that are not text'
post "$BASE/" --data-urlencode "v=$V" --data "secret=ab%00cd" \
    --data-urlencode "rcpt=bob@example.org"
expect 400 "password with NUL rejected"
has 'bytes that are not text'
post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/secret" \
    --data-urlencode "rcpt=bob"
expect 400 "invalid recipient rejected"
get "$BASE/?v=$V"
expect 200 "sender token kept after input errors"

share "$V" "$T/secret" " Bob@Example.org "
ok "password shared"
has 'bob@example.org'
post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/secret" \
    --data-urlencode "rcpt=bob@example.org"
expect 404 "sender token works only once"
[ "$(sql 'SELECT COUNT(*) FROM sender')" = 0 ] || fail "sender token kept"

ROW=$(sql 'SELECT sender, rcpt, box, reveal FROM secret')
[ "$(sql 'SELECT COUNT(*) FROM secret')" = 1 ] || fail "secret row count"
case "$ROW" in
alice@allard.it\|*) ;;
*) fail "sender not stored" ;;
esac
case "$ROW" in
*bob*|*"$S"*) fail "recipient or key stored in clear" ;;
esac
grep -qF 'p<b>a' "$T/sherpass.db" && fail "password stored in clear"
ok "database holds no password, recipient or key"

get "$BASE/?s=$S"
expect 200 "claim page"
has 'name="email"'
has 'name="r"'
get "$BASE/?s=$(rnd)"
expect 404 "unknown share key rejected"

N=$(nmail)
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "email=eve@example.org"
expect 200 "wrong recipient answered"
cp "$BODY" "$T/wrong"
[ "$(nmail)" = "$N" ] || fail "mail sent to wrong recipient"
ok "no mail to wrong recipient"

claim "$S" "BOB@example.org"
cmp -s "$BODY" "$T/wrong" || fail "answer differs for the right recipient"
ok "same answer for right and wrong recipient"
has 'name="r"'
has 'Press the button only once'
ok "code asked after the address"
M=$(lastmail)
grep -q '^To: bob@example.org' "$M" || fail "code mail To"
grep -q '^alice@allard.it has shared a password' "$M" ||
    fail "code mail lacks sender"
ok "code mailed to recipient"
grep -qF "$S" "$M" && fail "share key in the code mail"
grep -qF "$BASE" "$M" && fail "link in the code mail"
ok "code mail holds neither the share key nor a link"

N=$(nmail)
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "email=bob@example.org"
expect 200 "repeated claim answered"
[ "$(nmail)" = "$N" ] || fail "repeated claim not throttled"
ok "repeated claim throttled"

post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=$(rndcode)"
expect 400 "wrong code rejected"
has 'This code is wrong or has expired'
has 'name="r"'
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=not a code"
expect 400 "malformed code rejected"
[ "$(sql 'SELECT COUNT(*) FROM secret')" = 1 ] || fail "secret lost"
ok "password kept after wrong codes"
post "$BASE/" --data-urlencode "s=$(rnd)" --data-urlencode "r=$R"
expect 404 "code with another share key rejected"

post "$BASE/" --data-urlencode "s=$S" \
    --data-urlencode "r=  $(echo "$R" | tr a-f A-F) "
expect 200 "password revealed with a code in capitals and spaces"
has 'alice@allard.it'
shown "$T/secret" || fail "password not displayed escaped and intact"
grep -qF 'p<b>a' "$BODY" && fail "password not escaped"
tail -n 1 "$BODY" | grep -q '</html>' || fail "page incomplete"
grep -qi '^cache-control: no-store' "$HEADERS" || fail "reveal cacheable"
ok "password displayed escaped and intact"
[ "$(sql 'SELECT COUNT(*) FROM secret')" = 0 ] || fail "secret not deleted"
ok "secret deleted after display"

post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=$R"
expect 404 "reveal works only once"
get "$BASE/?s=$S"
expect 404 "share link dead after reveal"

# Concurrent reveals: exactly one may succeed.

# 4096 characters, a line break counting as one, are accepted.

sender ursula@allard.it
share "$V" "$T/fullutf8" vera@example.org
claim "$S" vera@example.org
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=$R"
expect 200 "password of 4096 characters with a line break revealed"
shown "$T/fullutf8" || fail "long password not displayed intact"
ok "long password displayed intact"

sender carol@allard.it
share "$V" "$T/secret" dan@example.org
claim "$S" dan@example.org
PIDS=
for n in 1 2 3 4; do
    (
        BODY=$T/par$n
        HEADERS=$T/par$n.headers
        post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=$R"
        echo "$STATUS" > "$T/par$n.status"
    ) &
    PIDS="$PIDS $!"
done
# shellcheck disable=SC2086
wait $PIDS
W=$(cat "$T"/par?.status | grep -c '^200$' || true)
L=$(cat "$T"/par?.status | grep -c '^404$' || true)
[ "$W" = 1 ] && [ "$L" = 3 ] ||
    fail "concurrent reveals: $W succeeded, $L refused"
ok "concurrent reveals: one succeeded, three refused"

# Expiry.

sender dave@allard.it
share "$V" "$T/secret" erin@example.org
sql 'UPDATE secret SET expires = 1' > /dev/null
get "$BASE/?s=$S"
expect 404 "expired secret rejected"
[ "$(sql 'SELECT COUNT(*) FROM secret')" = 0 ] || fail "expired secret kept"
ok "expired secret purged"

sender erin@allard.it
sql 'UPDATE sender SET expires = 1' > /dev/null
get "$BASE/?v=$V"
expect 404 "expired sender token rejected"

# Rate limiting.

for n in 1 2 3; do
    sender frank@allard.it
done
post "$BASE/" --data-urlencode "email=frank@allard.it"
expect 429 "sender mails throttled"

# The configuration is read on every request, limits can change here.
cat >> "$T/sherpass.ini" <<EOF
sender_limit = 1
recipient_limit = 2
recipient_delay = 0
EOF
sender grace@allard.it
post "$BASE/" --data-urlencode "email=grace@allard.it"
expect 429 "configured sender limit applied"
share "$V" "$T/secret" ivan@example.org
N=$(nmail)
claim "$S" ivan@example.org
claim "$S" ivan@example.org
[ "$(nmail)" = $((N + 2)) ] || fail "configured recipient delay not applied"
ok "configured recipient delay applied"
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "email=ivan@example.org"
expect 200 "claim over the recipient limit answered"
[ "$(nmail)" = $((N + 2)) ] || fail "configured recipient limit not applied"
ok "configured recipient limit applied"
echo "ip_limit = 1" >> "$T/sherpass.ini"
post "$BASE/" --data-urlencode "email=judy@allard.it"
expect 429 "configured IP limit applied"

# SMTP delivery, against tests/smtpd.php.

SMTP_TLS=$((PORT + 1))
SMTP_STARTTLS=$((PORT + 2))
SMTP_PLAIN=$((PORT + 3))
SMTP_LONG=$((PORT + 4))

# Start a test SMTP server: mode port name [user pass [mechs]].
smtpd() {
    m=$1
    p=$2
    n=$3
    shift 3
    php "$ROOT/tests/smtpd.php" "$m" "$p" "$T/smtp.crt" "$T/smtp.key" \
        "$T/smtp-$n" "$T/smtp-$n.log" "$@" > "$T/smtp-$n.out" 2>&1 &
    BG="$BG $!"
    i=0
    until grep -q ready "$T/smtp-$n.out" 2>/dev/null; do
        i=$((i + 1))
        [ $i -lt 50 ] || fail "SMTP server $n did not start"
        sleep 0.1
    done
}

# Switch the test server to SMTP delivery, extra settings in $1.
smtpconfig() {
    webconfig "ip_limit = 1000
sender_limit = 1000
mail_transport = smtp
$1"
}

# Expect delivery with settings $1 to fail, logging $2, in the test named $3.
smtpfail() {
    noerrors "before: $3"
    smtpconfig "$1"
    post "$BASE/" --data-urlencode "email=paul@allard.it"
    expect 500 "$3"
    grep -qF -- "$2" "$T/php.log" || fail "$3: log lacks: $2"
    grep -v '\] sherpass: ' "$T/php.log" &&
        fail "$3: PHP logged more than the failure"
    : > "$T/php.log"
}

smtpd tls $SMTP_TLS tls sherpass 'p@ss w0rd'
smtpd starttls $SMTP_STARTTLS starttls sherpass 'p@ss w0rd' LOGIN
smtpd none $SMTP_PLAIN plain
LONGPASS=$(repeat x 400)
smtpd tls $SMTP_LONG long sherpass "$LONGPASS" PLAIN

CREDS="smtp_user = 'sherpass'
smtp_password = 'p@ss w0rd'"

smtpconfig "smtp_host = localhost
smtp_port = $SMTP_TLS
$CREDS
smtp_cafile = $T/smtp.crt"
MAILDIR=$T/smtp-tls
sender kate@allard.it
ok "sender mail over TLS"
M=$(lastmail)
grep -q '^To: kate@allard.it' "$M" || fail "SMTP mail To"
grep -q '^Subject: Confirm your email address' "$M" ||
    fail "SMTP mail Subject"
grep -q '^Date: ' "$M" || fail "SMTP mail Date"
grep -q '^Message-ID: <[0-9a-f]\{32\}@allard.it>' "$M" ||
    fail "SMTP Message-ID"
grep -qx 'AUTH PLAIN' "$T/smtp-tls.log" || fail "no AUTH PLAIN"
grep -qx 'MAIL FROM:<sherpass@allard.it>' "$T/smtp-tls.log" ||
    fail "SMTP envelope sender"
grep -qx 'RCPT TO:<kate@allard.it>' "$T/smtp-tls.log" ||
    fail "SMTP envelope recipient"
ok "SMTP headers, envelope and authentication"
share "$V" "$T/secret" leo@example.org
claim "$S" leo@example.org
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=$R"
expect 200 "password revealed with mails over TLS"

smtpconfig "smtp_host = localhost
smtp_port = $SMTP_STARTTLS
smtp_tls = starttls
$CREDS
smtp_cafile = $T/smtp.crt"
MAILDIR=$T/smtp-starttls
sender mike@allard.it
tr '\n' ' ' < "$T/smtp-starttls.log" |
    grep -q 'STARTTLS TLS EHLO \[127.0.0.1\] AUTH LOGIN MAIL' ||
    fail "STARTTLS not done before AUTH LOGIN"
ok "sender mail over STARTTLS with AUTH LOGIN"

smtpconfig "smtp_host = localhost
smtp_port = $SMTP_PLAIN
smtp_tls = off"
MAILDIR=$T/smtp-plain
sender nina@allard.it
ok "sender mail over plain SMTP"

smtpconfig "smtp_host = localhost
smtp_port = $SMTP_LONG
smtp_user = 'sherpass'
smtp_password = '$LONGPASS'
smtp_cafile = $T/smtp.crt"
MAILDIR=$T/smtp-long
sender olga@allard.it
grep -qx 'AUTH PLAIN without initial response' "$T/smtp-long.log" ||
    fail "long credentials sent with AUTH PLAIN"
ok "long credentials sent on their own line"
grep -qx 'AUTH PLAIN without initial response' "$T/smtp-tls.log" &&
    fail "short credentials not sent with AUTH PLAIN"
ok "short credentials sent with AUTH PLAIN"

smtpconfig "smtp_host = localhost
smtp_port = $SMTP_TLS
$CREDS
smtp_tls_verify = off"
MAILDIR=$T/smtp-tls
sender oscar@allard.it
ok "sender mail over unverified TLS to localhost"

smtpfail "smtp_host = localhost
smtp_port = $SMTP_TLS
$CREDS" "certificate verify failed" "unknown certificate rejected"
smtpfail "smtp_host = 127.0.0.1
smtp_port = $SMTP_TLS
$CREDS
smtp_cafile = $T/smtp.crt" "did not match expected name" \
    "certificate name mismatch rejected"
smtpfail "smtp_host = localhost
smtp_port = $SMTP_STARTTLS
smtp_tls = starttls
$CREDS" "certificate verify failed" "unknown STARTTLS certificate rejected"
smtpfail "smtp_host = localhost
smtp_port = $SMTP_TLS
smtp_user = 'sherpass'
smtp_password = 'wrong'
smtp_cafile = $T/smtp.crt" "AUTH failed: 535" "wrong password rejected"
smtpfail "smtp_host = localhost
smtp_port = $SMTP_PLAIN
smtp_tls = starttls
smtp_cafile = $T/smtp.crt" "does not offer STARTTLS" \
    "missing STARTTLS rejected"

# A mail that cannot be sent counts against no limit. Nothing listens on
# the port given to SMTP below.

DEAD=$((PORT + 9))
IPN=$(sql "SELECT COUNT(*) FROM throttle WHERE name = 'ip:127.0.0.1'")
noerrors "before failing sender mails"
webconfig "sender_limit = 1
mail_transport = smtp
smtp_host = localhost
smtp_port = $DEAD
smtp_tls = off"
for n in 1 2; do
    post "$BASE/" --data-urlencode "email=quinn@allard.it"
    expect 500 "failing sender mail $n not throttled"
done
[ "$(sql "SELECT COUNT(*) FROM sender WHERE email = 'quinn@allard.it'")" = 0 ] ||
    fail "sender link kept after a failed mail"
[ "$(sql "SELECT COUNT(*) FROM throttle WHERE name = 'from:quinn@allard.it'")" = 0 ] ||
    fail "failed sender mail counted"
[ "$(sql "SELECT COUNT(*) FROM throttle WHERE name = 'ip:127.0.0.1'")" = $((IPN + 2)) ] ||
    fail "failed sender mails not counted for the client"
ok "failed sender mails leave no link and no count for the address"
grep -v '\] sherpass: ' "$T/php.log" && fail "PHP logged more than the failures"
: > "$T/php.log"

smtpconfig "smtp_host = localhost
smtp_port = $SMTP_PLAIN
smtp_tls = off"
MAILDIR=$T/smtp-plain
sender rita@allard.it
share "$V" "$T/secret" sam@example.org
noerrors "before a failing code mail"
smtpconfig "smtp_host = localhost
smtp_port = $DEAD
smtp_tls = off"
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "email=sam@example.org"
expect 200 "claim answered while the code mail fails"
grep -qF 'cannot send the code' "$T/php.log" || fail "code mail did not fail"
grep -v '\] sherpass: ' "$T/php.log" && fail "PHP logged more than the failure"
: > "$T/php.log"
smtpconfig "smtp_host = localhost
smtp_port = $SMTP_PLAIN
smtp_tls = off"
N=$(nmail)
claim "$S" sam@example.org
[ "$(nmail)" = $((N + 1)) ] || fail "failed code mail counted"
ok "failed code mail does not delay the next one"
R1=$R
smtpconfig "smtp_host = localhost
smtp_port = $DEAD
smtp_tls = off
recipient_delay = 0"
noerrors "before a second failing code mail"
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "email=sam@example.org"
expect 200 "claim answered while its code mail fails"
: > "$T/php.log"
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=$R1"
expect 200 "code delivered before a failed mail still works"

# A lone dot and lines starting with one must survive DATA.
printf '.first\r\n.\r\nline\r\n..two\r\n' > "$T/dots"
php -r 'require $argv[1] . "/src/smtp.php";
    smtp_send(["base_url" => "https://pass.allard.it",
        "smtp_host" => "localhost", "smtp_port" => (int)$argv[2],
        "smtp_tls" => "none", "smtp_user" => "", "smtp_password" => "",
        "smtp_cafile" => "", "smtp_tls_verify" => true],
        "a@allard.it", "b@example.org", file_get_contents($argv[3]));' \
    "$ROOT" "$SMTP_PLAIN" "$T/dots" || fail "SMTP send of dotted lines"
MAILDIR=$T/smtp-plain
cmp -s "$(lastmail)" "$T/dots" || fail "dotted lines altered"
ok "dot stuffing"

noerrors "at the end"

echo "all tests passed"
