<?php

/*
 * Tokens and secret encryption.
 *
 * Every token is 32 random bytes, sent as unpadded base64url and stored
 * only as its SHA-256. The key of a secret is never stored: the lookup
 * id, the encryption key and the recipient tag are all derived from it,
 * so the database alone reveals neither the password nor the recipient.
 */

declare(strict_types=1);

const TOKEN_BYTES = 32;
const TOKEN_CHARS = 43;
const KDF_CONTEXT = 'sherpass';
const SECRET_MAX = 4096;

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
 * Encrypt $plain, bound to its row by using $id as associated data.
 * Returns nonce and ciphertext as hex.
 */
function secret_seal(string $plain, string $id, string $enc): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    return bin2hex($nonce . sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $plain, $id, $nonce, $enc));
}

function secret_open(string $box, string $id, string $enc): ?string
{
    $bin = hex2bin($box);
    $n = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    if ($bin === false || strlen($bin) <= $n) {
        return null;
    }
    $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
        substr($bin, $n), $id, substr($bin, 0, $n), $enc);
    return $plain === false ? null : $plain;
}

function rcpt_tag(string $email, string $tagkey): string
{
    return bin2hex(sodium_crypto_generichash($email, $tagkey));
}
