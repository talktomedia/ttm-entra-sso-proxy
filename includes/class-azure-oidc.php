<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Talks to the standard Microsoft identity platform v2.0 endpoints directly
 * via WordPress's HTTP API - no OAuth client library needed for a flow this
 * small (one authorization-code exchange, one id_token to verify).
 */
final class TTM_Entra_SSO_Proxy_Azure_Oidc
{
    private string $tenantId;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;

    public function __construct(string $tenantId, string $clientId, string $clientSecret, string $redirectUri)
    {
        $this->tenantId = $tenantId;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
        $this->redirectUri = $redirectUri;
    }

    public function authorizationUrl(string $state): string
    {
        return add_query_arg([
            'client_id' => $this->clientId,
            'response_type' => 'code',
            'redirect_uri' => $this->redirectUri,
            'response_mode' => 'query',
            'scope' => 'openid profile email',
            'state' => $state,
        ], "https://login.microsoftonline.com/{$this->tenantId}/oauth2/v2.0/authorize");
    }

    /**
     * Exchanges the authorization code for tokens and returns the *verified*
     * id_token claims (signature, issuer, audience, tenant all checked).
     *
     * @return array<string, mixed>
     * @throws RuntimeException
     */
    public function exchangeCodeForClaims(string $code, string $expectedTenant): array
    {
        $response = wp_remote_post("https://login.microsoftonline.com/{$this->tenantId}/oauth2/v2.0/token", [
            'timeout' => 10,
            'body' => [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $this->redirectUri,
                'scope' => 'openid profile email',
            ],
        ]);

        if (is_wp_error($response)) {
            throw new RuntimeException('Token request failed: ' . $response->get_error_message());
        }

        $status = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if ($status !== 200 || !is_array($body)) {
            $detail = is_array($body) ? ($body['error_description'] ?? $body['error'] ?? 'unknown error') : 'unparsable response';
            throw new RuntimeException("Token exchange failed ({$status}): {$detail}");
        }

        if (empty($body['id_token'])) {
            throw new RuntimeException('Token response did not include an id_token.');
        }

        $claims = TTM_Entra_SSO_Proxy_Rsa_Jwt_Verifier::decode((string) $body['id_token'], $this->tenantId);

        $expectedIssuer = "https://login.microsoftonline.com/{$this->tenantId}/v2.0";
        if (($claims['iss'] ?? null) !== $expectedIssuer) {
            throw new RuntimeException('id_token issuer mismatch.');
        }

        if (($claims['aud'] ?? null) !== $this->clientId) {
            throw new RuntimeException('id_token audience mismatch.');
        }

        if (($claims['tid'] ?? null) !== $expectedTenant) {
            throw new RuntimeException('id_token was issued for an unexpected tenant.');
        }

        if (empty($claims['email']) && empty($claims['preferred_username'])) {
            throw new RuntimeException('id_token did not contain an email claim.');
        }

        return $claims;
    }
}
