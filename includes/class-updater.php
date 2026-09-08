<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Self-updates this plugin straight from GitHub tags - no third-party
 * updater plugin required. See the client plugin's identical class
 * (TTM_Entra_SSO_Updater) for the full rationale; kept as a separate copy
 * here rather than a shared library so each plugin stays a single
 * self-contained folder with no cross-plugin file dependency.
 *
 * To publish a new version: bump the Version header in
 * ttm-entra-sso-proxy.php, commit, then `git tag 1.2.0 && git push origin
 * 1.2.0` (a "v" prefix is fine too, it's stripped).
 */
final class TTM_Entra_SSO_Proxy_Updater
{
    private const CACHE_TTL = 6 * HOUR_IN_SECONDS;
    private const RETRY_TTL = 5 * MINUTE_IN_SECONDS;

    private string $pluginBasename;
    private string $repo;
    private string $version;

    public static function init(string $pluginFile, string $repo, string $version): void
    {
        // is_admin() alone would miss WP-CLI (`wp plugin update`) - it's not
        // a wp-admin request, so is_admin() is false there too, but it's the
        // realistic way updates get pushed across many sites at once.
        if (!is_admin() && !(defined('WP_CLI') && WP_CLI)) {
            return;
        }

        $instance = new self($pluginFile, $repo, $version);

        // Both the write side (fires when WordPress's own update-plugins.org
        // check completes) and the read side (fires on every read of the
        // transient, regardless of whether that check ever completed) - core
        // silently skips saving the transient at all if its request to
        // api.wordpress.org fails or errors, which would otherwise mean our
        // filter never runs on a host where that request doesn't succeed.
        add_filter('pre_set_site_transient_update_plugins', [$instance, 'inject_update']);
        add_filter('site_transient_update_plugins', [$instance, 'inject_update']);
        add_filter('upgrader_source_selection', [$instance, 'fix_folder_name'], 10, 4);
        add_action('upgrader_process_complete', [$instance, 'purge_cache_after_update'], 10, 2);
        add_filter('plugin_row_meta', [$instance, 'add_repo_link'], 10, 2);
    }

    private function __construct(string $pluginFile, string $repo, string $version)
    {
        $this->pluginBasename = plugin_basename($pluginFile);
        $this->repo = $repo;
        $this->version = $version;
    }

    /**
     * @param mixed $transient
     * @return mixed
     */
    public function inject_update($transient)
    {
        if (!is_object($transient)) {
            $transient = new stdClass();
        }

        // Normally already populated by core before this filter runs - but
        // when nothing has, e.g. the read-side filter firing before core's
        // own check has ever succeeded, build it ourselves so this doesn't
        // silently depend on that having happened first.
        if (empty($transient->checked)) {
            if (!function_exists('get_plugins')) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }

            $transient->checked = [];
            foreach (get_plugins() as $file => $data) {
                $transient->checked[$file] = $data['Version'];
            }
        }

        if (!isset($transient->response) || !is_array($transient->response)) {
            $transient->response = [];
        }

        $latest = $this->latest_tag();
        if ($latest === null || version_compare($latest['version'], $this->version, '<=')) {
            return $transient;
        }

        $item = new stdClass();
        $item->id = $this->repo;
        $item->slug = dirname($this->pluginBasename);
        $item->plugin = $this->pluginBasename;
        $item->new_version = $latest['version'];
        $item->url = "https://github.com/{$this->repo}";
        $item->package = $latest['zip'];
        $item->requires_php = '7.4';

        $transient->response[$this->pluginBasename] = $item;

        return $transient;
    }

    /**
     * @return array{tag: string, version: string, zip: string}|null
     */
    private function latest_tag(): ?array
    {
        $cacheKey = 'ttm_gh_updater_' . md5($this->repo);
        $cached = get_transient($cacheKey);
        if ($cached !== false) {
            return (is_array($cached) && !empty($cached)) ? $cached : null;
        }

        $response = wp_remote_get("https://api.github.com/repos/{$this->repo}/tags", [
            'headers' => ['Accept' => 'application/vnd.github+json'],
            'timeout' => 10,
        ]);

        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            set_transient($cacheKey, [], self::RETRY_TTL);
            return null;
        }

        $tags = json_decode(wp_remote_retrieve_body($response), true);
        $result = null;

        if (is_array($tags)) {
            foreach ($tags as $tag) {
                $name = (string) ($tag['name'] ?? '');
                $version = ltrim($name, 'vV');
                if ($version !== '' && preg_match('/^\d+(\.\d+){0,3}$/', $version)) {
                    $result = [
                        'tag' => $name,
                        'version' => $version,
                        'zip' => "https://github.com/{$this->repo}/archive/refs/tags/{$name}.zip",
                    ];
                    break;
                }
            }
        }

        set_transient($cacheKey, $result ?? [], self::CACHE_TTL);

        return $result;
    }

    /**
     * @param string $source
     * @param string $remote_source
     * @param mixed $upgrader
     * @param array<string, mixed>|null $hook_extra
     * @return string|WP_Error
     */
    public function fix_folder_name(string $source, string $remote_source, $upgrader, $hook_extra = null)
    {
        global $wp_filesystem;

        if (!is_array($hook_extra) || ($hook_extra['plugin'] ?? '') !== $this->pluginBasename) {
            return $source;
        }

        $corrected = trailingslashit($remote_source) . dirname($this->pluginBasename) . '/';

        if (untrailingslashit($source) === untrailingslashit($corrected)) {
            return $source;
        }

        if (!$wp_filesystem->move($source, $corrected, true)) {
            return new WP_Error('ttm_updater_rename_failed', 'Could not rename the downloaded plugin folder to match the installed one.');
        }

        return $corrected;
    }

    /**
     * @param mixed $upgrader
     * @param array<string, mixed> $options
     */
    public function purge_cache_after_update($upgrader, array $options): void
    {
        if (($options['action'] ?? '') === 'update' && ($options['type'] ?? '') === 'plugin') {
            delete_transient('ttm_gh_updater_' . md5($this->repo));
        }
    }

    /**
     * @param string[] $links
     * @return string[]
     */
    public function add_repo_link(array $links, string $file): array
    {
        if ($file === $this->pluginBasename) {
            $links[] = sprintf(
                '<a href="https://github.com/%s" target="_blank" rel="noopener">GitHub</a>',
                esc_attr($this->repo)
            );
        }

        return $links;
    }
}
