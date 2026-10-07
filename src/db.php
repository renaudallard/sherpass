<?php

/*
 * SQLite storage, expiry and rate limiting.
 */

declare(strict_types=1);

/* Longest rate limiting window, in seconds. */
const THROTTLE_WINDOW = 3600;

/*
 * A revealed secret is deleted once its page has been sent. This is only
 * a fallback for a process that died in between.
 */
const CLAIM_GRACE = 300;

const SCHEMA = <<<'SQL'
CREATE TABLE IF NOT EXISTS sender (
    hash TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS secret (
    id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    rcpt TEXT NOT NULL,
    box TEXT NOT NULL,
    expires INTEGER NOT NULL,
    reveal TEXT,
    reveal_expires INTEGER,
    claimed INTEGER
);
CREATE TABLE IF NOT EXISTS throttle (
    name TEXT NOT NULL,
    ts INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS throttle_name ON throttle (name, ts);
SQL;

function db_open(string $path): PDO
{
    umask(0077);
    $db = new PDO('sqlite:' . $path, null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 5,
    ]);
    $db->exec('PRAGMA secure_delete = ON');
    $db->exec(SCHEMA);
    return $db;
}

/**
 * @param list<int|string> $args
 */
function db_query(PDO $db, string $sql, array $args = []): PDOStatement
{
    $st = $db->prepare($sql);
    foreach ($args as $i => $v) {
        $st->bindValue($i + 1, $v, is_int($v) ? PDO::PARAM_INT :
            PDO::PARAM_STR);
    }
    $st->execute();
    return $st;
}

/*
 * Run $fn in a write transaction. BEGIN IMMEDIATE takes the write lock
 * up front, so concurrent requests are serialized.
 */
function db_tx(PDO $db, callable $fn): mixed
{
    $db->exec('BEGIN IMMEDIATE');
    try {
        $ret = $fn();
    } catch (Throwable $e) {
        $db->exec('ROLLBACK');
        throw $e;
    }
    $db->exec('COMMIT');
    return $ret;
}

function db_purge(PDO $db, int $now): void
{
    db_tx($db, function () use ($db, $now): void {
        db_query($db, 'DELETE FROM sender WHERE expires <= ?', [$now]);
        db_query($db, 'DELETE FROM secret WHERE ' .
            '(claimed IS NULL AND expires <= ?) OR claimed <= ?',
            [$now, $now - CLAIM_GRACE]);
        db_query($db, 'DELETE FROM throttle WHERE ts <= ?',
            [$now - THROTTLE_WINDOW]);
    });
}

/*
 * True if fewer than $max events were recorded for $name in the last
 * $window seconds.
 */
function throttle_ok(PDO $db, string $name, int $max, int $window,
    int $now): bool
{
    $n = db_query($db, 'SELECT COUNT(*) FROM throttle ' .
        'WHERE name = ? AND ts > ?', [$name, $now - $window])->fetchColumn();
    return (int)$n < $max;
}

/*
 * Rate limiting name of the client: its IPv4 address, or its /64 for
 * IPv6, as a single host usually gets a whole /64 to pick from.
 */
function throttle_ip(): string
{
    $addr = $_SERVER['REMOTE_ADDR'] ?? '';
    $bin = @inet_pton($addr);
    if ($bin === false) {
        return "ip:$addr";
    }
    if (strlen($bin) === 16 &&
        !str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
        return 'ip:' . inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) .
            '/64';
    }
    return 'ip:' . inet_ntop(substr($bin, -4));
}

function throttle_hit(PDO $db, string $name, int $now): void
{
    db_query($db, 'INSERT INTO throttle (name, ts) VALUES (?, ?)',
        [$name, $now]);
}
