<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The endpoints client sites and Entra talk to:
 *   GET  /wp-json/ttm-entra-sso-proxy/v1/authorize?site_id=...   (start login)
 *   GET  /wp-json/ttm-entra-sso-proxy/v1/callback                (Entra redirects here)
 *   GET  /wp-json/ttm-entra-sso-proxy/v1/status?site_id=...      (optional: is this site enabled?)
 *   POST /wp-json/ttm-entra-sso-proxy/v1/enroll                  (self-registration, see enroll())
 *
 * authorize/callback issue real HTTP redirects (header()+exit), same as the
 * standalone version - REST routing is just a convenient, already-secured
 * URL namespace to hang them off, not a JSON API in this case. status/enroll
 * are plain JSON responses.
 */
final class TTM_Entra_SSO_Proxy_Rest_Routes
{
    private const NAMESPACE = 'ttm-entra-sso-proxy/v1';

    public static function init(): void
    {
        add_action('rest_api_init', [self::class, 'register_routes']);
    }

    public static function register_routes(): void
    {
        register_rest_route(self::NAMESPACE, '/authorize', [
            'methods' => 'GET',
            'callback' => [self::class, 'authorize'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/callback', [
            'methods' => 'GET',
            'callback' => [self::class, 'callback'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/status', [
            'methods' => 'GET',
            'callback' => [self::class, 'status'],
            'permission_callback' => '__return_true',
        ]);

        register_rest_route(self::NAMESPACE, '/enroll', [
            'methods' => 'POST',
            'callback' => [self::class, 'enroll'],
            'permission_callback' => '__return_true',
        ]);
    }

    public static function authorize(WP_REST_Request $request): void
    {
        nocache_headers();

        if (!TTM_Entra_SSO_Proxy_Config::is_configured()) {
            self::text_error(500, 'SSO proxy is not configured.');
        }

        $site_id = sanitize_key((string) $request->get_param('site_id'));

        if ($site_id === '') {
            self::text_error(400, 'Missing site_id.');
        }

        if (!TTM_Entra_SSO_Proxy_Site_Registry::has($site_id)) {
            // Deliberately vague - don't confirm/deny which site_ids exist.
            self::text_error(403, 'Unknown or disabled site.');
        }

        $config = TTM_Entra_SSO_Proxy_Config::get();

        // Optional opaque string the calling site wants echoed back unchanged
        // (e.g. a post-login redirect path). Never interpreted here, just
        // carried through. Capped to stop it smuggling anything large
        // through the Entra state parameter.
        $context = substr((string) $request->get_param('context'), 0, 500);

        $now = time();
        $stateClaims = [
            'site_id' => $site_id,
            'nonce' => bin2hex(random_bytes(16)),
            'iat' => $now,
            'exp' => $now + (int) $config['token_ttl'],
        ];
        if ($context !== '') {
            $stateClaims['context'] = $context;
        }

        $state = TTM_Entra_SSO_Proxy_Jwt_Hs256::encode($stateClaims, TTM_Entra_SSO_Proxy_Config::state_signing_key());

        $oidc = new TTM_Entra_SSO_Proxy_Azure_Oidc(
            (string) $config['azure_tenant_id'],
            (string) $config['azure_client_id'],
            TTM_Entra_SSO_Proxy_Config::client_secret(),
            rest_url(self::NAMESPACE . '/callback')
        );

        wp_redirect($oidc->authorizationUrl($state));
        exit;
    }

    public static function callback(WP_REST_Request $request): void
    {
        nocache_headers();

        $config = TTM_Entra_SSO_Proxy_Config::get();

        if (!empty($request->get_param('error'))) {
            error_log('[ttm-entra-sso-proxy] Azure returned an error: ' . $request->get_param('error_description'));
            self::text_error(400, 'Sign-in was cancelled or failed.');
        }

        $code = (string) $request->get_param('code');
        $rawState = (string) $request->get_param('state');

        if ($code === '' || $rawState === '') {
            self::text_error(400, 'Missing code or state.');
        }

        try {
            $state = TTM_Entra_SSO_Proxy_Jwt_Hs256::decode($rawState, TTM_Entra_SSO_Proxy_Config::state_signing_key());
        } catch (RuntimeException $e) {
            error_log('[ttm-entra-sso-proxy] state verification failed: ' . $e->getMessage());
            self::text_error(400, 'Sign-in request expired or was tampered with. Please try again.');
        }

        $site_id = (string) ($state['site_id'] ?? '');

        if ($site_id === '' || !TTM_Entra_SSO_Proxy_Site_Registry::has($site_id)) {
            self::text_error(403, 'Unknown or disabled site.');
        }

        try {
            $oidc = new TTM_Entra_SSO_Proxy_Azure_Oidc(
                (string) $config['azure_tenant_id'],
                (string) $config['azure_client_id'],
                TTM_Entra_SSO_Proxy_Config::client_secret(),
                rest_url(self::NAMESPACE . '/callback')
            );

            $allowedTenant = $config['azure_allowed_tenant'] !== '' ? $config['azure_allowed_tenant'] : $config['azure_tenant_id'];
            $claims = $oidc->exchangeCodeForClaims($code, (string) $allowedTenant);
        } catch (RuntimeException $e) {
            error_log('[ttm-entra-sso-proxy] token exchange/verification failed: ' . $e->getMessage());
            self::text_error(500, 'Sign-in is temporarily unavailable. Please try again shortly.');
        }

        $email = strtolower((string) ($claims['email'] ?? $claims['preferred_username'] ?? ''));
        $allowedDomains = TTM_Entra_SSO_Proxy_Site_Registry::allowedEmailDomainsFor($site_id);

        if (!empty($allowedDomains)) {
            $emailDomain = strtolower(substr(strrchr($email, '@') ?: '', 1));
            if (!in_array($emailDomain, $allowedDomains, true)) {
                error_log("[ttm-entra-sso-proxy] Rejected login for {$email}: domain not allowed for site {$site_id}.");
                self::text_error(403, 'Your account is not permitted to sign in to this site.');
            }
        }

        $now = time();
        $handoffClaims = [
            'iss' => 'ttm-entra-sso-proxy',
            'site_id' => $site_id,
            'email' => $email,
            'name' => $claims['name'] ?? null,
            'oid' => $claims['oid'] ?? null,
            'tid' => $claims['tid'] ?? null,
            'jti' => bin2hex(random_bytes(16)),
            'iat' => $now,
            'exp' => $now + (int) $config['token_ttl'],
        ];

        if (!empty($state['context'])) {
            $handoffClaims['context'] = $state['context'];
        }

        if (TTM_Entra_SSO_Proxy_Config::is_force_admin($email)) {
            $handoffClaims['force_admin'] = true;
        }

        $handoff = TTM_Entra_SSO_Proxy_Jwt_Hs256::encode($handoffClaims, TTM_Entra_SSO_Proxy_Site_Registry::sharedSecretFor($site_id));

        $returnUri = TTM_Entra_SSO_Proxy_Site_Registry::returnUriFor($site_id);
        $separator = str_contains($returnUri, '?') ? '&' : '?';

        wp_redirect($returnUri . $separator . 'token=' . urlencode($handoff));
        exit;
    }

    public static function status(WP_REST_Request $request): WP_REST_Response
    {
        nocache_headers();

        $site_id = sanitize_key((string) $request->get_param('site_id'));

        if ($site_id === '') {
            return new WP_REST_Response(['error' => 'Missing site_id'], 400);
        }

        // Deliberately minimal: just enabled true/false, no other detail
        // exposed, for a site_id the caller already has to know.
        return new WP_REST_Response(['enabled' => TTM_Entra_SSO_Proxy_Site_Registry::has($site_id)], 200);
    }

    /**
     * Lets a freshly-installed client site register itself instead of
     * someone hand-copying a site_id/shared_secret pair into it. Gated two
     * independent ways:
     *
     *  1. Authorisation - the URL being enrolled must already appear in
     *     MainWP's own child-site list, so this can't be used as an open
     *     enrollment service for arbitrary unrelated domains. Fails closed
     *     (503) if that check can't be done right now, rather than skipping
     *     it.
     *  2. Proof of control - see verify_domain_control(). Knowing the
     *     plugin's shared key (it ships in public source, so assume it's
     *     public) is NOT sufficient on its own: the proxy calls back to the
     *     claimed URL directly, so an attacker naming someone else's real
     *     site here can't make it answer correctly without actually
     *     controlling it.
     *
     * Both checks are re-run even for a URL that's already registered, not
     * just on first creation - otherwise an already-enrolled site's secret
     * could be re-disclosed to an impersonator who never had to pass either
     * gate. Idempotent otherwise: calling this again for the same, verified
     * URL just returns its existing credentials, so it's safe to call on
     * every admin page load until it succeeds.
     */
    public static function enroll(WP_REST_Request $request): WP_REST_Response
    {
        nocache_headers();

        $siteUrl = untrailingslashit(esc_url_raw((string) $request->get_param('site_url')));
        if ($siteUrl === '' || !wp_http_validate_url($siteUrl)) {
            return new WP_REST_Response(['error' => 'Missing or invalid site_url.'], 400);
        }

        $mainwpSites = TTM_Entra_SSO_Proxy_MainWP_Import::fetch_sites();
        if (!is_array($mainwpSites)) {
            return new WP_REST_Response(['error' => "Could not verify this site against MainWP right now - it'll retry automatically."], 503);
        }

        $match = null;
        foreach ($mainwpSites as $mainwpSite) {
            if (untrailingslashit((string) $mainwpSite['url']) === $siteUrl) {
                $match = $mainwpSite;
                break;
            }
        }

        if ($match === null) {
            return new WP_REST_Response(['error' => 'This URL is not a recognised MainWP child site.'], 403);
        }

        if (!self::verify_domain_control($siteUrl)) {
            return new WP_REST_Response(['error' => 'Could not verify this site controls that URL.'], 403);
        }

        $returnUri = $siteUrl . '/wp-json/ttm-entra-sso/v1/callback';

        $existing = TTM_Entra_SSO_Proxy_Site_Registry::findByReturnUri($returnUri);
        if ($existing !== null) {
            return new WP_REST_Response([
                'site_id' => $existing['id'],
                'shared_secret' => $existing['shared_secret'],
            ], 200);
        }

        $siteId = TTM_Entra_SSO_Proxy_Site_Registry::generateSiteId((string) $match['name']);
        $secret = TTM_Entra_SSO_Proxy_Site_Registry::generateSecret();

        TTM_Entra_SSO_Proxy_Site_Registry::save($siteId, [
            'name' => (string) $match['name'],
            'shared_secret' => $secret,
            'return_uri' => $returnUri,
            'allowed_email_domains' => [],
            'enabled' => true,
        ]);

        return new WP_REST_Response([
            'site_id' => $siteId,
            'shared_secret' => $secret,
        ], 201);
    }

    /**
     * Domain-control check for enroll(): generates a nonce and asks
     * $siteUrl's own /enroll-challenge route (see TTM_Entra_SSO_Settings on
     * the client) to sign it with the shared key both sides carry. This
     * request goes straight to $siteUrl - DNS/hosting decides who answers
     * it, not whoever's POSTing to this endpoint - so an attacker naming a
     * URL they don't control can't produce a response that matches.
     */
    private static function verify_domain_control(string $siteUrl): bool
    {
        $nonce = bin2hex(random_bytes(16));

        $response = wp_remote_get(
            add_query_arg('nonce', $nonce, $siteUrl . '/wp-json/ttm-entra-sso/v1/enroll-challenge'),
            ['timeout' => 8]
        );

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return false;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);
        $expected = hash_hmac('sha256', $nonce, TTM_Entra_SSO_Proxy_Config::enroll_key());

        return is_array($body) && isset($body['response']) && hash_equals($expected, (string) $body['response']);
    }

    /**
     * @return never
     */
    private static function text_error(int $status, string $message): void
    {
        status_header($status);
        header('Content-Type: text/plain; charset=utf-8');
        echo esc_html($message);
        exit;
    }
}
