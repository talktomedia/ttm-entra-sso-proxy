<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * HS256 sign/verify for the proxy's own two short-lived tokens: the "state"
 * round-tripped through Entra (signed with this site's state key), and the
 * "handoff" token given to each client site (signed with that site's own
 * shared secret). Not used for Azure's id_token - that's RS256, see
 * TTM_Entra_SSO_Proxy_Rsa_Jwt_Verifier.
 */
final class TTM_Entra_SSO_Proxy_Jwt_Hs256
{
    /**
     * @param array<string, mixed> $claims
     */
    public static function encode(array $claims, string $secret): string
    {
        $header = self::base64UrlEncode((string) wp_json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
        $payload = self::base64UrlEncode((string) wp_json_encode($claims));
        $signature = self::sign("{$header}.{$payload}", $secret);

        return "{$header}.{$payload}.{$signature}";
    }

    /**
     * @return array<string, mixed>
     * @throws RuntimeException
     */
    public static function decode(string $jwt, string $secret): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed token.');
        }

        list($header, $payload, $signature) = $parts;

        if (!hash_equals(self::sign("{$header}.{$payload}", $secret), $signature)) {
            throw new RuntimeException('Token signature verification failed.');
        }

        $decodedHeader = json_decode(self::base64UrlDecode($header), true);
        if (!is_array($decodedHeader) || ($decodedHeader['alg'] ?? null) !== 'HS256') {
            throw new RuntimeException('Unsupported or missing token algorithm.');
        }

        $claims = json_decode(self::base64UrlDecode($payload), true);
        if (!is_array($claims)) {
            throw new RuntimeException('Malformed token payload.');
        }

        $now = time();

        if (isset($claims['exp']) && $now >= (int) $claims['exp']) {
            throw new RuntimeException('Token has expired.');
        }

        if (isset($claims['nbf']) && $now < (int) $claims['nbf']) {
            throw new RuntimeException('Token is not yet valid.');
        }

        return $claims;
    }

    private static function sign(string $data, string $secret): string
    {
        return self::base64UrlEncode(hash_hmac('sha256', $data, $secret, true));
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        $padded = $remainder ? str_pad($data, strlen($data) + 4 - $remainder, '=') : $data;
        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }
}
