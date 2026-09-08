<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Verifies RS256-signed JWTs (Azure's id_token) against a tenant's published
 * JWKS, with no composer dependency - this plugin ships as a single
 * self-contained WordPress plugin, so no vendor/ directory to keep in sync.
 *
 * The one non-obvious piece is turning a JWK's modulus/exponent into
 * something openssl_verify() can use: PHP has no "build a public key from
 * raw RSA components" call, so we hand-encode the ASN.1 DER SubjectPublicKeyInfo
 * structure and wrap it as PEM. This is a standard, well-documented technique
 * (the same one general-purpose JWT libraries use internally) - see the test
 * in this plugin's repo that round-trips it against a locally generated
 * keypair before trusting it against real Azure tokens.
 */
final class TTM_Entra_SSO_Proxy_Rsa_Jwt_Verifier
{
    private const JWKS_CACHE_TTL = DAY_IN_SECONDS;

    /**
     * @return array<string, mixed>
     * @throws RuntimeException
     */
    public static function decode(string $jwt, string $tenantId): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed id_token.');
        }

        [$headerB64, $payloadB64, $signatureB64] = $parts;

        $header = json_decode(self::base64UrlDecode($headerB64), true);
        if (!is_array($header) || ($header['alg'] ?? null) !== 'RS256' || empty($header['kid'])) {
            throw new RuntimeException('id_token header is missing alg/kid or uses an unsupported algorithm.');
        }

        $publicKeyPem = self::publicKeyPemForKid((string) $header['kid'], $tenantId);
        $publicKey = openssl_pkey_get_public($publicKeyPem);

        if ($publicKey === false) {
            throw new RuntimeException('Could not load the matching JWKS public key.');
        }

        $signedData = "{$headerB64}.{$payloadB64}";
        $signature = self::base64UrlDecode($signatureB64);

        $verified = openssl_verify($signedData, $signature, $publicKey, OPENSSL_ALGO_SHA256);

        if ($verified !== 1) {
            throw new RuntimeException('id_token signature verification failed.');
        }

        $claims = json_decode(self::base64UrlDecode($payloadB64), true);
        if (!is_array($claims)) {
            throw new RuntimeException('Malformed id_token payload.');
        }

        $now = time();

        if (isset($claims['exp']) && $now >= (int) $claims['exp'] + 30) {
            throw new RuntimeException('id_token has expired.');
        }

        if (isset($claims['nbf']) && $now < (int) $claims['nbf'] - 30) {
            throw new RuntimeException('id_token is not yet valid.');
        }

        return $claims;
    }

    private static function publicKeyPemForKid(string $kid, string $tenantId): string
    {
        $jwks = self::fetchJwks($tenantId, false);
        $key = self::findKey($jwks, $kid);

        if ($key === null) {
            // Key not found - could be legitimate rotation. Refetch once,
            // bypassing the cache, before giving up.
            $jwks = self::fetchJwks($tenantId, true);
            $key = self::findKey($jwks, $kid);
        }

        if ($key === null) {
            throw new RuntimeException("No JWKS key found matching kid '{$kid}'.");
        }

        if (($key['kty'] ?? null) !== 'RSA' || empty($key['n']) || empty($key['e'])) {
            throw new RuntimeException('JWKS key is missing RSA components.');
        }

        return self::rsaComponentsToPem((string) $key['n'], (string) $key['e']);
    }

    /**
     * @param array<int, array<string, mixed>> $jwks
     * @return array<string, mixed>|null
     */
    private static function findKey(array $jwks, string $kid): ?array
    {
        foreach ($jwks as $key) {
            if (($key['kid'] ?? null) === $kid) {
                return $key;
            }
        }

        return null;
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private static function fetchJwks(string $tenantId, bool $bypassCache): array
    {
        $cacheKey = 'ttm_entra_sso_proxy_jwks_' . md5($tenantId);

        if (!$bypassCache) {
            $cached = get_transient($cacheKey);
            if (is_array($cached)) {
                return $cached;
            }
        }

        $response = wp_remote_get("https://login.microsoftonline.com/{$tenantId}/discovery/v2.0/keys", ['timeout' => 5]);

        if (is_wp_error($response)) {
            throw new RuntimeException('Could not fetch Microsoft JWKS: ' . $response->get_error_message());
        }

        if (wp_remote_retrieve_response_code($response) !== 200) {
            throw new RuntimeException('Unexpected response fetching Microsoft JWKS.');
        }

        $decoded = json_decode(wp_remote_retrieve_body($response), true);

        if (!is_array($decoded) || empty($decoded['keys']) || !is_array($decoded['keys'])) {
            throw new RuntimeException('Could not parse Microsoft JWKS response.');
        }

        set_transient($cacheKey, $decoded['keys'], self::JWKS_CACHE_TTL);

        return $decoded['keys'];
    }

    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        $padded = $remainder ? str_pad($data, strlen($data) + 4 - $remainder, '=') : $data;
        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }

    // --- JWK (n, e) -> PEM, via hand-encoded ASN.1 DER ------------------

    public static function rsaComponentsToPem(string $nB64u, string $eB64u): string
    {
        $modulus = self::base64UrlDecode($nB64u);
        $exponent = self::base64UrlDecode($eB64u);

        $rsaPublicKey = self::derSequence(
            self::derInteger($modulus) . self::derInteger($exponent)
        );

        // SEQUENCE { OID rsaEncryption (1.2.840.113549.1.1.1), NULL }
        $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500');

        $subjectPublicKeyInfo = self::derSequence(
            $algorithmIdentifier . self::derBitString($rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    private static function derLength(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derInteger(string $bytes): string
    {
        // Strip leading 0x00 padding, then re-add exactly one if the high
        // bit is set (otherwise it would be read as a negative integer).
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    private static function derSequence(string $content): string
    {
        return "\x30" . self::derLength(strlen($content)) . $content;
    }

    private static function derBitString(string $content): string
    {
        // Leading byte = number of unused bits in the last content byte (0 here).
        $withUnusedBitsPrefix = "\x00" . $content;

        return "\x03" . self::derLength(strlen($withUnusedBitsPrefix)) . $withUnusedBitsPrefix;
    }
}
