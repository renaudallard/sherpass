<?php

/*
 * Tokens and secret encryption.
 *
 * Every token is 32 random bytes, sent as unpadded base64url and stored
 * only as its SHA-256. The key of a secret is never stored: the lookup
 * id, the encryption key and the recipient tag are all derived from it,
 * so the row of a secret reveals neither the password, its sender nor
 * its recipient.
 */

declare(strict_types=1);

const TOKEN_BYTES = 32;
const TOKEN_CHARS = 43;
const KDF_CONTEXT = 'sherpass';
const SECRET_MAX = 4096;    /* characters */

function token_new(): string
{
    return random_bytes(TOKEN_BYTES);
}

function token_encode(string $bin): string
{
    return sodium_bin2base64($bin, SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
}

/*
 * Decode a token received from the client, null if it is malformed.
 */
function token_decode(mixed $v): ?string
{
    if (!is_string($v) || strlen($v) !== TOKEN_CHARS) {
        return null;
    }
    try {
        $bin = sodium_base642bin($v,
            SODIUM_BASE64_VARIANT_URLSAFE_NO_PADDING);
    } catch (SodiumException) {
        return null;
    }
    return strlen($bin) === TOKEN_BYTES ? $bin : null;
}

function token_hash(string $bin): string
{
    return hash('sha256', $bin);
}

/*
 * The code mailed to the recipient is a token written in hex, which a
 * double click selects whole, unlike base64url and its dashes. Spaces
 * around it and capitals are accepted, as a copy may bring them.
 */
function code_encode(string $bin): string
{
    return bin2hex($bin);
}

function code_decode(mixed $v): ?string
{
    if (!is_string($v)) {
        return null;
    }
    $v = strtolower(trim($v));
    if (preg_match('/^[0-9a-f]{' . 2 * TOKEN_BYTES . '}$/D', $v) !== 1) {
        return null;
    }
    $bin = hex2bin($v);
    return $bin === false ? null : $bin;
}

/**
 * Derive the database id (hex), the encryption key and the recipient tag
 * key from the key of a secret.
 *
 * @return array{string, string, string}
 */
function secret_keys(string $key): array
{
    return [
        bin2hex(sodium_crypto_kdf_derive_from_key(16, 1, KDF_CONTEXT, $key)),
        sodium_crypto_kdf_derive_from_key(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 2,
            KDF_CONTEXT, $key),
        sodium_crypto_kdf_derive_from_key(
            SODIUM_CRYPTO_GENERICHASH_KEYBYTES, 3, KDF_CONTEXT, $key),
    ];
}

/*
 * Encrypt $plain with $ad as associated data, which binds it to where it
 * is stored. Returns nonce and ciphertext as hex.
 */
function secret_seal(string $plain, string $ad, string $enc): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    return bin2hex($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $plain, $ad, $nonce, $enc));
}

function secret_open(string $box, string $ad, string $enc): ?string
{
    $bin = hex2bin($box);
    $n = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    if ($bin === false || strlen($bin) <= $n) {
        return null;
    }
    $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        substr($bin, $n), $ad, substr($bin, 0, $n), $enc);
    return $plain === false ? null : $plain;
}

/*
 * The other values of a row are encrypted with the key of the password,
 * each under associated data naming it, so that none can be swapped.
 */
function field_seal(string $plain, string $id, string $name,
    string $enc): string
{
    return secret_seal($plain, "$id:$name", $enc);
}

function field_open(string $box, string $id, string $name,
    string $enc): ?string
{
    return secret_open($box, "$id:$name", $enc);
}

/*
 * Rows shared before the sender was encrypted hold it in clear, which an
 * address tells apart from hex by its @.
 */
function sender_open(string $box, string $id, string $enc): ?string
{
    if (str_contains($box, '@')) {
        return $box;
    }
    return field_open($box, $id, 'sender', $enc);
}

function rcpt_tag(string $email, string $tagkey): string
{
    return bin2hex(sodium_crypto_generichash($email, $tagkey));
}
