<?php
/**
 * Plugin Name: TTM Entra ID SSO Proxy
 * Description: Runs the Entra ID SSO proxy on this MainWP Dashboard install. Fronts a single Entra app registration for every client site running the TTM Entra ID SSO plugin.
 * Version: 1.2.8
 * Author: Talk To Media
 * Requires PHP: 7.4
 * License: Proprietary - internal TTM use
 * Update URI: https://github.com/talktomedia/ttm-entra-sso-proxy
 *
 * @package TtmEntraSsoProxy
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

define('TTM_ENTRA_SSO_PROXY_VERSION', '1.2.8');
define('TTM_ENTRA_SSO_PROXY_DIR', plugin_dir_path(__FILE__));
define('TTM_ENTRA_SSO_PROXY_URL', plugin_dir_url(__FILE__));
define('TTM_ENTRA_SSO_PROXY_GITHUB_REPO', 'talktomedia/ttm-entra-sso-proxy');

require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-config.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-jwt-hs256.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-rsa-jwt-verifier.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-azure-oidc.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-site-registry.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-rest-routes.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-admin-settings.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-mainwp-import.php';
require_once TTM_ENTRA_SSO_PROXY_DIR . 'includes/class-updater.php';

add_action('plugins_loaded', static function (): void {
    TTM_Entra_SSO_Proxy_Admin_Settings::init();
    TTM_Entra_SSO_Proxy_Rest_Routes::init();
    TTM_Entra_SSO_Proxy_MainWP_Import::init();
    TTM_Entra_SSO_Proxy_Updater::init(__FILE__, TTM_ENTRA_SSO_PROXY_GITHUB_REPO, TTM_ENTRA_SSO_PROXY_VERSION);
});

register_activation_hook(__FILE__, static function (): void {
    // The state-signing key protects the round trip to Entra and back - it
    // needs to exist before the first login attempt, and must never be
    // regenerated casually (that would invalidate in-flight logins for the
    // length of TOKEN_TTL, which is harmless, but keep it stable otherwise).
    if (empty(get_option(TTM_Entra_SSO_Proxy_Config::STATE_KEY_OPTION))) {
        update_option(TTM_Entra_SSO_Proxy_Config::STATE_KEY_OPTION, bin2hex(random_bytes(32)), false);
    }
});
