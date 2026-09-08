<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Central config. Everything except the Entra client secret lives in a
 * single WP option, edited on the settings screen. The client secret
 * itself is read from a wp-config.php constant when defined - keeping the
 * one secret that matters most out of the database, out of DB backups,
 * and out of any staging clone - falling back to the option field only if
 * that constant isn't set.
 */
final class TTM_Entra_SSO_Proxy_Config
{
    public const OPTION_KEY = 'ttm_entra_sso_proxy_settings';
    public const STATE_KEY_OPTION = 'ttm_entra_sso_proxy_state_key';
    public const CLIENT_SECRET_CONSTANT = 'TTM_ENTRA_SSO_CLIENT_SECRET';
    public const ENROLL_KEY_CONSTANT = 'TTM_ENTRA_SSO_ENROLL_KEY';

    /**
     * Shared by every TTM-managed client site (same constant/default on
     * both sides) so new installs can self-register with the proxy instead
     * of someone hand-copying a site_id/shared_secret pair 80 times - see
     * TTM_Entra_SSO_Proxy_Rest_Routes::enroll(). This value is NEVER sent
     * over the wire and is not itself a bearer credential: it only signs
     * the response to a domain-control challenge the proxy issues directly
     * to the URL being enrolled, so knowing this key (it ships in public
     * plugin source) doesn't let anyone enroll a domain they don't actually
     * control - DNS decides who answers that challenge, not whoever asked
     * to be enrolled. Enrollment is separately gated on the URL being a
     * recognised MainWP child site. Still overridable via wp-config.php if
     * you ever want to rotate it.
     */
    private const DEFAULT_ENROLL_KEY = '292a2a0521e894918f79cd896244e4d4286f8b8ce432ec48ffcdf219266ac0ea';

    /**
     * @return array<string, mixed>
     */
    public static function get(): array
    {
        $defaults = [
            'azure_tenant_id' => '',
            'azure_client_id' => '',
            'azure_client_secret' => '', // Only used if the wp-config constant isn't defined.
            'azure_allowed_tenant' => '',
            'token_ttl' => 120,
            'force_admin_emails' => '',
        ];

        return wp_parse_args(get_option(self::OPTION_KEY, []), $defaults);
    }

    public static function client_secret(): string
    {
        if (defined(self::CLIENT_SECRET_CONSTANT)) {
            return (string) constant(self::CLIENT_SECRET_CONSTANT);
        }

        $settings = self::get();

        return (string) $settings['azure_client_secret'];
    }

    public static function client_secret_source(): string
    {
        return defined(self::CLIENT_SECRET_CONSTANT) ? 'wp-config.php constant' : 'database (plugin settings)';
    }

    public static function enroll_key(): string
    {
        if (defined(self::ENROLL_KEY_CONSTANT)) {
            return (string) constant(self::ENROLL_KEY_CONSTANT);
        }

        return self::DEFAULT_ENROLL_KEY;
    }

    public static function state_signing_key(): string
    {
        $key = get_option(self::STATE_KEY_OPTION, '');

        if ($key === '') {
            // Shouldn't normally happen (set on activation), but don't let a
            // missing key silently disable signature checks - generate and
            // persist one now.
            $key = bin2hex(random_bytes(32));
            update_option(self::STATE_KEY_OPTION, $key, false);
        }

        return (string) $key;
    }

    /**
     * Staff who should always land as administrator on a client site, even
     * if that site's own "default role" is something lower - kept here,
     * one place, instead of hardcoded in the client plugin that gets copied
     * onto 80 sites (editing this list would otherwise mean editing and
     * redeploying code everywhere). Only affects accounts being newly
     * auto-created; see TTM_Entra_SSO_Proxy_Rest_Routes::callback().
     *
     * @return string[] Lowercased emails.
     */
    public static function force_admin_emails(): array
    {
        $raw = (string) self::get()['force_admin_emails'];
        $emails = preg_split('/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY) ?: [];

        return array_map('strtolower', $emails);
    }

    public static function is_force_admin(string $email): bool
    {
        return in_array(strtolower($email), self::force_admin_emails(), true);
    }

    public static function is_configured(): bool
    {
        $settings = self::get();

        return $settings['azure_tenant_id'] !== ''
            && $settings['azure_client_id'] !== ''
            && self::client_secret() !== '';
    }
}
