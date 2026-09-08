<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Optional convenience: pulls site name + URL from MainWP's own child site
 * list so adding a site here means one less thing to type by hand.
 *
 * IMPORTANT - unlike the rest of this plugin, this integration could NOT be
 * tested against a live MainWP install from where it was written. It's built
 * against MainWP's documented Extensions API (mainwp_getextensions /
 * mainwp_extension_enabled_check / mainwp_getsites), which is the standard,
 * publicly documented mechanism third-party extensions use - but hook
 * signatures have been known to shift between MainWP versions, and this
 * hasn't been run against a real Dashboard. Treat it as best-effort: if it
 * doesn't work on your version, the "Add a site" form still works manually,
 * nothing else in the plugin depends on this succeeding.
 *
 * Manual step required regardless of whether the code is right: this plugin
 * needs to show up and be switched on under MainWP's own Extensions page
 * before mainwp_extension_enabled_check will hand back a key. That's how
 * MainWP gates ALL third-party extensions, not something this plugin can
 * skip.
 */
final class TTM_Entra_SSO_Proxy_MainWP_Import
{
    private const EXTENSION_API_ID = 'ttm-entra-sso-proxy';
    private const CACHE_KEY = 'ttm_entra_sso_proxy_mainwp_sites';
    private const CACHE_TTL = 300; // 5 minutes - site lists don't change minute to minute.

    public static function init(): void
    {
        add_filter('mainwp_getextensions', [self::class, 'register_extension']);
    }

    /**
     * @param array<int, array<string, mixed>> $plugins
     * @return array<int, array<string, mixed>>
     */
    public static function register_extension(array $plugins): array
    {
        $plugins[] = [
            'plugin' => TTM_ENTRA_SSO_PROXY_DIR . 'ttm-entra-sso-proxy.php',
            'api' => self::EXTENSION_API_ID,
            'mainwp' => false,
            'callback' => [self::class, 'render_extension_tab'],
        ];

        return $plugins;
    }

    /**
     * MainWP requires a render callback for the extension's own tab under
     * Extensions. All actual configuration lives on this plugin's normal
     * Settings screen, so this just points there.
     */
    public static function render_extension_tab(): void
    {
        printf(
            '<p>%s <a href="%s">%s</a></p>',
            esc_html__('TTM Entra ID SSO Proxy is configured from its own settings screen:', 'ttm-entra-sso-proxy'),
            esc_url(admin_url('options-general.php?page=ttm-entra-sso-proxy')),
            esc_html__('Settings -> Entra ID SSO Proxy', 'ttm-entra-sso-proxy')
        );
    }

    /**
     * True if this looks like a MainWP Dashboard install at all (regardless
     * of whether our extension has been enabled there yet).
     */
    public static function configured(): bool
    {
        return defined('MAINWP_PLUGIN_FILE') || class_exists('MainWP\\Dashboard\\MainWP_System');
    }

    /**
     * True if MainWP is present AND has handed us a working extension key.
     */
    public static function available(): bool
    {
        return self::childKey() !== null;
    }

    private static function childKey(): ?string
    {
        if (!self::configured() || !function_exists('apply_filters')) {
            return null;
        }

        try {
            $info = apply_filters('mainwp_extension_enabled_check', TTM_ENTRA_SSO_PROXY_DIR . 'ttm-entra-sso-proxy.php');
        } catch (\Throwable $e) {
            error_log('[ttm-entra-sso-proxy] MainWP enabled-check failed: ' . $e->getMessage());
            return null;
        }

        if (!is_array($info) || empty($info['key'])) {
            return null;
        }

        return (string) $info['key'];
    }

    /**
     * @return array<int, array{name: string, url: string}>|null Null means
     *         "couldn't fetch" (MainWP present but not enabled/reachable,
     *         or an unexpected response shape) - distinct from an empty
     *         array, which means "MainWP has no sites yet".
     */
    public static function fetch_sites(): ?array
    {
        $cached = get_transient(self::CACHE_KEY);
        if (is_array($cached)) {
            return $cached;
        }

        $childKey = self::childKey();
        if ($childKey === null) {
            return null;
        }

        try {
            $sites = apply_filters('mainwp_getsites', TTM_ENTRA_SSO_PROXY_DIR . 'ttm-entra-sso-proxy.php', $childKey);
        } catch (\Throwable $e) {
            error_log('[ttm-entra-sso-proxy] MainWP getsites failed: ' . $e->getMessage());
            return null;
        }

        if (!is_array($sites)) {
            return null;
        }

        $normalised = [];
        foreach ($sites as $site) {
            if (!is_array($site) || empty($site['url'])) {
                continue;
            }
            $normalised[] = [
                'name' => (string) ($site['name'] ?? $site['url']),
                'url' => untrailingslashit((string) $site['url']),
            ];
        }

        set_transient(self::CACHE_KEY, $normalised, self::CACHE_TTL);

        return $normalised;
    }
}
