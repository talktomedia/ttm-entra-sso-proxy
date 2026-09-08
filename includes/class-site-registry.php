<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * The list of client sites permitted to use this proxy, stored as a single
 * WP option (this plugin lives on one WordPress install, so a plain option
 * is simpler and just as robust as a custom table for the site counts an
 * agency deals with).
 *
 * Each site has its own shared secret, used to sign/verify only that site's
 * handoff token - so one compromised client site never exposes another's
 * secret, or the Entra client secret itself. return_uri is always looked up
 * here, never taken from a request, which is what stops the proxy being
 * used as an open redirector.
 */
final class TTM_Entra_SSO_Proxy_Site_Registry
{
    public const OPTION_KEY = 'ttm_entra_sso_proxy_sites';

    /**
     * @return array<string, array<string, mixed>>
     */
    public static function all(): array
    {
        $sites = get_option(self::OPTION_KEY, []);

        return is_array($sites) ? $sites : [];
    }

    public static function has(string $siteId): bool
    {
        $sites = self::all();

        return isset($sites[$siteId]) && !empty($sites[$siteId]['enabled']);
    }

    /**
     * @return array<string, mixed>|null
     */
    public static function get(string $siteId): ?array
    {
        $sites = self::all();

        return $sites[$siteId] ?? null;
    }

    /**
     * Used by enrollment, which only knows a requesting site's URL, not
     * whatever site_id it may already have been assigned.
     *
     * @return array<string, mixed>|null Includes the site_id under 'id'.
     */
    public static function findByReturnUri(string $returnUri): ?array
    {
        foreach (self::all() as $siteId => $site) {
            if (($site['return_uri'] ?? '') === $returnUri) {
                return array_merge(['id' => $siteId], $site);
            }
        }

        return null;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function save(string $siteId, array $data): void
    {
        $sites = self::all();

        $sites[$siteId] = wp_parse_args($data, [
            'name' => $siteId,
            'shared_secret' => '',
            'return_uri' => '',
            'allowed_email_domains' => [],
            'enabled' => true,
        ]);

        update_option(self::OPTION_KEY, $sites, false);
    }

    public static function delete(string $siteId): void
    {
        $sites = self::all();
        unset($sites[$siteId]);
        update_option(self::OPTION_KEY, $sites, false);
    }

    public static function returnUriFor(string $siteId): string
    {
        return (string) (self::get($siteId)['return_uri'] ?? '');
    }

    public static function sharedSecretFor(string $siteId): string
    {
        return (string) (self::get($siteId)['shared_secret'] ?? '');
    }

    /**
     * @return string[]
     */
    public static function allowedEmailDomainsFor(string $siteId): array
    {
        $domains = self::get($siteId)['allowed_email_domains'] ?? [];

        return is_array($domains) ? $domains : [];
    }

    public static function generateSecret(): string
    {
        return bin2hex(random_bytes(32));
    }

    public static function generateSiteId(string $name): string
    {
        $base = sanitize_title($name) ?: 'site';
        $siteId = $base;
        $sites = self::all();
        $suffix = 1;

        while (isset($sites[$siteId])) {
            $siteId = $base . '-' . $suffix;
            $suffix++;
        }

        return $siteId;
    }
}
