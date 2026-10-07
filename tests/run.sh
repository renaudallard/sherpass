#!/bin/sh
#
# Configuration checks and end-to-end test of the whole flow against the
# PHP built-in server. Everything is written to tmp/test, mails included.

set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
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
    STATUS=$(curl -s -o "$BODY" -D "$HEADERS" -w '%{http_code}' "$1")
}

post() {
    u=$1
    shift
    STATUS=$(curl -s -o "$BODY" -D "$HEADERS" -w '%{http_code}' "$@" "$u")
}

expect() {
    [ "$STATUS" = "$1" ] || fail "$2: status $STATUS, expected $1"
    ok "$2"
}

has() {
    grep -qF -- "$1" "$BODY" || fail "body lacks: $1"
}

nmail() {
    ls "$MAILDIR" 2>/dev/null | wc -l
}

lastmail() {
    echo "$MAILDIR/$(nmail)"
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
    R=$(grep -o "$BASE/?s=$1&r=[A-Za-z0-9_-]*" "$(lastmail)") ||
        fail "no reveal link"
    R=${R#*r=}
}

rm -rf "$T"
mkdir -p "$T"

# Configuration validation.

cfgtest() {
    printf '%s\n' "$2" > "$T/cfg.ini"
    if php -r 'require $argv[1] . "/src/config.php";
        require $argv[1] . "/src/mail.php";
        config_load($argv[2]);' "$ROOT" "$T/cfg.ini" 2>/dev/null; then
        r=pass
    else
        r=fail
    fi
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
cfgtest fail "$(echo "$GOOD" | sed '/^secret_ttl/d')" "missing ttl rejected"
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

# End-to-end flow.

cat > "$T/sherpass.ini" <<EOF
base_url = "$BASE"
mail_from = "sherpass@allard.it"
allowed_domains[] = "allard.it"
db_path = "$T/sherpass.db"
secret_ttl = 2592000
token_ttl = 1800
EOF

SHERPASS_CONFIG=$T/sherpass.ini PHP_CLI_SERVER_WORKERS=4 \
    php -d sendmail_path="$ROOT/tests/sendmail.sh $MAILDIR" \
    -d log_errors=1 -d error_log="$T/php.log" \
    -S "127.0.0.1:$PORT" -t "$ROOT/public" > "$T/server.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null' EXIT INT TERM

i=0
until curl -s -o /dev/null "$BASE/"; do
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
head -c 4097 /dev/zero | tr '\0' x > "$T/big"

post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/empty" \
    --data-urlencode "rcpt=bob@example.org"
expect 400 "empty password rejected"
post "$BASE/" --data-urlencode "v=$V" --data-urlencode "secret@$T/big" \
    --data-urlencode "rcpt=bob@example.org"
expect 400 "oversized password rejected"
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
has 'name="s"'
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
M=$(lastmail)
grep -q '^To: bob@example.org' "$M" || fail "reveal mail To"
grep -q '^alice@allard.it has shared a password' "$M" ||
    fail "reveal mail lacks sender"
ok "reveal mail sent to recipient"

N=$(nmail)
post "$BASE/" --data-urlencode "s=$S" --data-urlencode "email=bob@example.org"
expect 200 "repeated claim answered"
[ "$(nmail)" = "$N" ] || fail "repeated claim not throttled"
ok "repeated claim throttled"

get "$BASE/?s=$S&r=$R"
expect 200 "reveal confirmation page"
has 'Display the password'
has 'alice@allard.it'
get "$BASE/?s=$S&r=$R"
expect 200 "reveal link survives a GET"
grep -qF 'p<b>a' "$BODY" && fail "password shown on GET"
grep -qF 'p&lt;b&gt;a' "$BODY" && fail "password shown on GET"

post "$BASE/" --data-urlencode "s=$S" \
    --data-urlencode "r=$(rnd)"
expect 404 "wrong reveal token rejected"

post "$BASE/" --data-urlencode "s=$S" --data-urlencode "r=$R"
expect 200 "password revealed"
php -r '$b = file_get_contents($argv[1]);
    $s = "<pre class=\"box\">\n" . htmlspecialchars(file_get_contents($argv[2]),
        ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, "UTF-8") . "</pre>";
    exit(str_contains($b, $s) ? 0 : 1);' "$BODY" "$T/secret" ||
    fail "password not displayed escaped and intact"
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

sender carol@allard.it
share "$V" "$T/secret" dan@example.org
claim "$S" dan@example.org
PIDS=
for n in 1 2 3 4; do
    curl -s -o "$T/par$n" -w '%{http_code}\n' --data-urlencode "s=$S" \
        --data-urlencode "r=$R" "$BASE/" > "$T/par$n.status" &
    PIDS="$PIDS $!"
done
# shellcheck disable=SC2086
wait $PIDS
W=$(cat "$T"/par?.status | grep -c '^200$' || true)
[ "$W" = 1 ] || fail "concurrent reveals: $W succeeded"
ok "concurrent reveals: exactly one succeeded"

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

[ -s "$T/php.log" ] && fail "PHP logged errors: $(cat "$T/php.log")"
ok "no PHP errors logged"

echo "all tests passed"
