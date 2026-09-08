<?php

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Settings -> Entra ID SSO Proxy: Entra app config + the client site list.
 */
final class TTM_Entra_SSO_Proxy_Admin_Settings {
    private const NONCE_ACTION = 'ttm_entra_sso_proxy_site';

    public static function init(): void {
        add_action( 'admin_menu', [ self::class, 'register_menu' ] );
        add_action( 'admin_init', [ self::class, 'register_settings' ] );
        add_action( 'admin_post_ttm_entra_sso_proxy_save_site', [ self::class, 'handle_save_site' ] );
        add_action( 'admin_post_ttm_entra_sso_proxy_delete_site', [ self::class, 'handle_delete_site' ] );
        add_action( 'admin_post_ttm_entra_sso_proxy_add_all_sites', [ self::class, 'handle_add_all_sites' ] );
        add_action( 'admin_notices', [ self::class, 'render_notices' ] );
    }

    public static function register_menu(): void {
        add_options_page(
                'Entra ID SSO Proxy',
                'Entra ID SSO Proxy',
                'manage_options',
                'ttm-entra-sso-proxy',
                [ self::class, 'render_page' ]
        );
    }

    public static function register_settings(): void {
        register_setting( TTM_Entra_SSO_Proxy_Config::OPTION_KEY, TTM_Entra_SSO_Proxy_Config::OPTION_KEY, [ self::class, 'sanitize_config' ] );
    }

    /**
     * @param array<string, mixed> $input
     *
     * @return array<string, mixed>
     */
    public static function sanitize_config( array $input ): array {
        return [
                'azure_tenant_id'      => sanitize_text_field( $input['azure_tenant_id'] ?? '' ),
                'azure_client_id'      => sanitize_text_field( $input['azure_client_id'] ?? '' ),
                'azure_client_secret'  => defined( TTM_Entra_SSO_Proxy_Config::CLIENT_SECRET_CONSTANT )
                        ? '' // Ignore whatever was posted - the constant wins, don't also store it in the DB.
                        : trim( (string) ( $input['azure_client_secret'] ?? '' ) ),
                'azure_allowed_tenant' => sanitize_text_field( $input['azure_allowed_tenant'] ?? '' ),
                'token_ttl'            => max( 30, (int) ( $input['token_ttl'] ?? 120 ) ),
                'force_admin_emails'   => sanitize_textarea_field( $input['force_admin_emails'] ?? '' ),
                'app_role_map'         => sanitize_textarea_field( $input['app_role_map'] ?? '' ),
        ];
    }

    public static function render_notices(): void {
        if ( ! isset( $_GET['page'] ) || $_GET['page'] !== 'ttm-entra-sso-proxy' || empty( $_GET['ttm_notice'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            return;
        }

        $notice = sanitize_text_field( wp_unslash( (string) $_GET['ttm_notice'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

        if ( $notice === 'sites_added' ) {
            $count   = isset( $_GET['count'] ) ? (int) $_GET['count'] : 0; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $message = $count > 0
                    ? sprintf( '%d site%s added from MainWP.', $count, $count === 1 ? '' : 's' )
                    : 'No new sites to add - everything from MainWP is already listed.';
            printf( '<div class="notice notice-success is-dismissible"><p>%s</p></div>', esc_html( $message ) );

            return;
        }

        $messages = [
                'site_saved'         => [ 'success', 'Site saved.' ],
                'site_deleted'       => [ 'success', 'Site removed.' ],
                'invalid_site'       => [ 'error', 'Site ID must contain only lowercase letters, numbers and hyphens.' ],
                'mainwp_unavailable' => [ 'error', "MainWP site list isn't available right now." ],
        ];

        if ( ! isset( $messages[ $notice ] ) ) {
            return;
        }

        [ $type, $message ] = $messages[ $notice ];
        printf( '<div class="notice notice-%s is-dismissible"><p>%s</p></div>', esc_attr( $type ), esc_html( $message ) );
    }

    public static function handle_save_site(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Insufficient permissions.' );
        }
        check_admin_referer( self::NONCE_ACTION );

        $site_id = sanitize_key( (string) ( $_POST['site_id'] ?? '' ) );
        $is_new  = ! empty( $_POST['is_new'] );

        if ( $site_id === '' || ! preg_match( '/^[a-z0-9-]+$/', $site_id ) ) {
            wp_safe_redirect( add_query_arg( 'ttm_notice', 'invalid_site', self::page_url() ) );
            exit;
        }

        $existing = TTM_Entra_SSO_Proxy_Site_Registry::get( $site_id );

        $domains = array_filter( array_map( 'trim', explode( ',', (string) ( $_POST['allowed_email_domains'] ?? '' ) ) ) );

        $secret = trim( (string) ( $_POST['shared_secret'] ?? '' ) );
        if ( $secret === '' || ( ! empty( $_POST['regenerate_secret'] ) ) ) {
            $secret = TTM_Entra_SSO_Proxy_Site_Registry::generateSecret();
        }

        TTM_Entra_SSO_Proxy_Site_Registry::save( $site_id, [
                'name'                  => sanitize_text_field( $_POST['name'] ?? $site_id ),
                'shared_secret'         => $secret,
                'return_uri'            => esc_url_raw( $_POST['return_uri'] ?? ( $existing['return_uri'] ?? '' ) ),
                'allowed_email_domains' => array_values( $domains ),
                'enabled'               => ! empty( $_POST['enabled'] ),
        ] );

        wp_safe_redirect( add_query_arg( 'ttm_notice', 'site_saved', self::page_url() ) );
        exit;
    }

    public static function handle_delete_site(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Insufficient permissions.' );
        }
        check_admin_referer( self::NONCE_ACTION );

        $site_id = sanitize_key( (string) ( $_POST['site_id'] ?? '' ) );
        if ( $site_id !== '' ) {
            TTM_Entra_SSO_Proxy_Site_Registry::delete( $site_id );
        }

        wp_safe_redirect( add_query_arg( 'ttm_notice', 'site_deleted', self::page_url() ) );
        exit;
    }

    /**
     * Bulk-add every MainWP child site that isn't already registered here,
     * matched by return URI so re-running this never creates duplicates.
     */
    public static function handle_add_all_sites(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( 'Insufficient permissions.' );
        }
        check_admin_referer( self::NONCE_ACTION );

        $mainwp_sites = TTM_Entra_SSO_Proxy_MainWP_Import::available() ? TTM_Entra_SSO_Proxy_MainWP_Import::fetch_sites() : NULL;

        if ( ! is_array( $mainwp_sites ) ) {
            wp_safe_redirect( add_query_arg( 'ttm_notice', 'mainwp_unavailable', self::page_url() ) );
            exit;
        }

        $existing_uris = wp_list_pluck( TTM_Entra_SSO_Proxy_Site_Registry::all(), 'return_uri' );
        $added         = 0;

        foreach ( $mainwp_sites as $mainwp_site ) {
            $return_uri = untrailingslashit( (string) $mainwp_site['url'] ) . '/wp-json/ttm-entra-sso/v1/callback';

            if ( in_array( $return_uri, $existing_uris, true ) ) {
                continue;
            }

            $site_id = TTM_Entra_SSO_Proxy_Site_Registry::generateSiteId( $mainwp_site['name'] );

            TTM_Entra_SSO_Proxy_Site_Registry::save( $site_id, [
                    'name'                  => $mainwp_site['name'],
                    'shared_secret'         => TTM_Entra_SSO_Proxy_Site_Registry::generateSecret(),
                    'return_uri'            => $return_uri,
                    'allowed_email_domains' => [],
                    'enabled'               => true,
            ] );

            $existing_uris[] = $return_uri;
            $added++;
        }

        wp_safe_redirect( add_query_arg( [ 'ttm_notice' => 'sites_added', 'count' => $added ], self::page_url() ) );
        exit;
    }

    private static function page_url(): string {
        return admin_url( 'options-general.php?page=ttm-entra-sso-proxy' );
    }

    public static function render_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $config       = TTM_Entra_SSO_Proxy_Config::get();
        $redirect_uri = rest_url( 'ttm-entra-sso-proxy/v1/callback' );
        $sites        = TTM_Entra_SSO_Proxy_Site_Registry::all();
        $editing_id   = isset( $_GET['edit'] ) ? sanitize_key( wp_unslash( (string) $_GET['edit'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
        $editing      = $editing_id !== '' ? TTM_Entra_SSO_Proxy_Site_Registry::get( $editing_id ) : NULL;
        $mainwp_sites = TTM_Entra_SSO_Proxy_MainWP_Import::available() ? TTM_Entra_SSO_Proxy_MainWP_Import::fetch_sites() : NULL;
        ?>
        <div class="wrap">
            <h1>Entra ID SSO Proxy</h1>

            <h2>Entra app registration</h2>
            <p><strong>Redirect URI to register in Entra:</strong> <code><?php echo esc_html( $redirect_uri ); ?></code></p>
            <form method="post" action="options.php">
                <?php settings_fields( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ttm_tenant_id">Tenant ID</label></th>
                        <td>
                            <input type="text" id="ttm_tenant_id" class="regular-text"
                                   name="<?php echo esc_attr( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>[azure_tenant_id]"
                                   value="<?php echo esc_attr( $config['azure_tenant_id'] ); ?>">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_client_id">Client (application) ID</label></th>
                        <td>
                            <input type="text" id="ttm_client_id" class="regular-text"
                                   name="<?php echo esc_attr( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>[azure_client_id]"
                                   value="<?php echo esc_attr( $config['azure_client_id'] ); ?>">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Client secret</th>
                        <td>
                            <?php if ( defined( TTM_Entra_SSO_Proxy_Config::CLIENT_SECRET_CONSTANT ) ) : ?>
                                <p>Set via the <code><?php echo esc_html( TTM_Entra_SSO_Proxy_Config::CLIENT_SECRET_CONSTANT ); ?></code> constant in <code>wp-config.php</code>. Not stored in the database.</p>
                            <?php else : ?>
                                <input type="password" id="ttm_client_secret" class="regular-text" autocomplete="off"
                                       name="<?php echo esc_attr( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>[azure_client_secret]"
                                       value="<?php echo esc_attr( $config['azure_client_secret'] ); ?>">
                                <p class="description">
                                    Recommended instead: define <code><?php echo esc_html( TTM_Entra_SSO_Proxy_Config::CLIENT_SECRET_CONSTANT ); ?></code>
                                    in <code>wp-config.php</code> so this never sits in the database or a DB backup.
                                </p>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_allowed_tenant">Restrict logins to tenant</label></th>
                        <td>
                            <input type="text" id="ttm_allowed_tenant" class="regular-text"
                                   name="<?php echo esc_attr( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>[azure_allowed_tenant]"
                                   value="<?php echo esc_attr( $config['azure_allowed_tenant'] ); ?>"
                                   placeholder="defaults to Tenant ID above">
                            <p class="description">Leave blank to default to the Tenant ID above (recommended - locks logins to your own tenant only).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_token_ttl">Token lifetime (seconds)</label></th>
                        <td>
                            <input type="number" id="ttm_token_ttl" min="30" step="1"
                                   name="<?php echo esc_attr( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>[token_ttl]"
                                   value="<?php echo esc_attr( (string) $config['token_ttl'] ); ?>">
                            <p class="description">How long the state and handoff tokens are valid for. Keep this short (default 120s).</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_force_admin_emails">Always-admin emails</label></th>
                        <td>
                            <textarea id="ttm_force_admin_emails" class="regular-text" rows="3"
                                      name="<?php echo esc_attr( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>[force_admin_emails]"
                                      placeholder="someone@example.com&#10;someone.else@example.com"><?php echo esc_textarea( $config['force_admin_emails'] ); ?></textarea>
                            <p class="description">
                                One email per line (or comma separated). When a new WordPress account is auto-created
                                for one of these on any client site, it's given the <code>administrator</code> role
                                instead of that site's configured default role. Only applies to accounts being
                                created for the first time - doesn't change the role of an existing user.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_app_role_map">Entra App Role &rarr; WordPress role</label></th>
                        <td>
                            <textarea id="ttm_app_role_map" class="regular-text" rows="3"
                                      name="<?php echo esc_attr( TTM_Entra_SSO_Proxy_Config::OPTION_KEY ); ?>[app_role_map]"
                                      placeholder="WP.Admin=administrator&#10;WP.Editor=editor"><?php echo esc_textarea( $config['app_role_map'] ); ?></textarea>
                            <p class="description">
                                One <code>EntraRole=wp_role_slug</code> pair per line, matching the App Roles you've
                                defined on this Entra app registration and assigned under Enterprise Applications &rarr;
                                Users and groups. Checked top to bottom - list higher-privilege roles first, since the
                                first match wins for a user assigned more than one. Only applies when a new WordPress
                                account is auto-created; falls back to that site's own configured default role if the
                                user has none of these App Roles, or this is left blank. The always-admin list above
                                still wins over this regardless of App Role.
                            </p>
                        </td>
                    </tr>
                </table>
                <?php submit_button( 'Save Entra settings' ); ?>
            </form>

            <hr>

            <h2 style="display:flex; align-items:center; justify-content:space-between;">
                Client sites
                <?php if ( is_array( $mainwp_sites ) && ! empty( $mainwp_sites ) ) : ?>
                    <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline" onsubmit="return confirm('Add every MainWP child site that isn\'t already listed below? You can edit or remove any of them afterwards.');">
                        <?php wp_nonce_field( self::NONCE_ACTION ); ?>
                        <input type="hidden" name="action" value="ttm_entra_sso_proxy_add_all_sites">
                        <button type="submit" class="button button-primary">Add All</button>
                    </form>
                <?php endif; ?>
            </h2>
            <table class="widefat striped">
                <thead>
                <tr>
                    <th>Site ID</th>
                    <th>Name</th>
                    <th>Return URI</th>
                    <th>Allowed domains</th>
                    <th>Enabled</th>
                    <th></th>
                </tr>
                </thead>
                <tbody>
                <?php if ( empty( $sites ) ) : ?>
                    <tr>
                        <td colspan="6">No sites yet.</td>
                    </tr>
                <?php endif; ?>
                <?php foreach ( $sites as $id => $site ) : ?>
                    <tr>
                        <td><code><?php echo esc_html( $id ); ?></code></td>
                        <td><?php echo esc_html( $site['name'] ); ?></td>
                        <td><code><?php echo esc_html( $site['return_uri'] ); ?></code></td>
                        <td><?php echo esc_html( implode( ', ', $site['allowed_email_domains'] ) ?: '(any)' ); ?></td>
                        <td><?php echo ! empty( $site['enabled'] ) ? '&#10003;' : '&#10007;'; ?></td>
                        <td>
                            <a href="<?php echo esc_url( add_query_arg( [ 'page' => 'ttm-entra-sso-proxy', 'edit' => $id ], admin_url( 'options-general.php' ) ) ); ?>">Edit</a>
                            &nbsp;|&nbsp;
                            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="display:inline" onsubmit="return confirm('Remove this site? Its shared secret will stop working immediately.');">
                                <?php wp_nonce_field( self::NONCE_ACTION ); ?>
                                <input type="hidden" name="action" value="ttm_entra_sso_proxy_delete_site">
                                <input type="hidden" name="site_id" value="<?php echo esc_attr( $id ); ?>">
                                <button type="submit" class="button-link" style="color:#b32d2e;">Delete</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>

            <h3><?php echo $editing ? 'Edit site' : 'Add a site'; ?></h3>

            <?php if ( is_array( $mainwp_sites ) && ! $editing ) : ?>
                <p>
                    <label for="ttm_mainwp_prefill">Prefill from MainWP:</label>
                    <select id="ttm_mainwp_prefill">
                        <option value="">Choose a MainWP site&hellip;</option>
                        <?php foreach ( $mainwp_sites as $mainwp_site ) : ?>
                            <option value="<?php echo esc_attr( $mainwp_site['url'] ); ?>" data-name="<?php echo esc_attr( $mainwp_site['name'] ); ?>">
                                <?php echo esc_html( $mainwp_site['name'] . ' (' . $mainwp_site['url'] . ')' ); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                    <span class="description">Fills in Name and Return URI below. This uses MainWP's extension API - double-check the Return URI it fills in looks right before saving.</span>
                </p>
                <script>
                    (function () {
                        var select = document.getElementById('ttm_mainwp_prefill');
                        if (!select) {
                            return;
                        }
                        select.addEventListener('change', function () {
                            if (!this.value) {
                                return;
                            }
                            var name = this.selectedOptions[0].getAttribute('data-name');
                            var url = this.value.replace(/\/$/, '');
                            document.getElementById('ttm_site_name').value = name;
                            document.getElementById('ttm_site_return_uri').value = url + '/wp-json/ttm-entra-sso/v1/callback';
                            if (!document.getElementById('ttm_site_id').value) {
                                document.getElementById('ttm_site_id').value = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
                            }
                        });
                    })();
                </script>
            <?php elseif ( TTM_Entra_SSO_Proxy_MainWP_Import::configured() && $mainwp_sites === NULL ) : ?>
                <p class="description">MainWP import is enabled but the site list couldn't be fetched right now (see the debug log). You can still add sites manually below.</p>
            <?php endif; ?>

            <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
                <?php wp_nonce_field( self::NONCE_ACTION ); ?>
                <input type="hidden" name="action" value="ttm_entra_sso_proxy_save_site">
                <input type="hidden" name="is_new" value="<?php echo $editing ? '0' : '1'; ?>">
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ttm_site_id">Site ID</label></th>
                        <td>
                            <input type="text" id="ttm_site_id" name="site_id" class="regular-text" pattern="[a-z0-9-]+"
                                   value="<?php echo esc_attr( $editing_id ); ?>" <?php echo $editing ? 'readonly' : ''; ?> required>
                            <p class="description">Lowercase letters, numbers and hyphens only. Must match the Site ID entered in that site's plugin settings. Cannot be changed after creation.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_site_name">Name</label></th>
                        <td><input type="text" id="ttm_site_name" name="name" class="regular-text" value="<?php echo esc_attr( $editing['name'] ?? '' ); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_site_return_uri">Return URI</label></th>
                        <td>
                            <input type="url" id="ttm_site_return_uri" name="return_uri" class="regular-text"
                                   value="<?php echo esc_attr( $editing['return_uri'] ?? '' ); ?>"
                                   placeholder="https://clientsite.com/wp-json/ttm-entra-sso/v1/callback" required>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_site_domains">Allowed email domains</label></th>
                        <td>
                            <input type="text" id="ttm_site_domains" name="allowed_email_domains" class="regular-text"
                                   value="<?php echo esc_attr( implode( ', ', $editing['allowed_email_domains'] ?? [] ) ); ?>"
                                   placeholder="talktomedia.co.uk, example.com">
                            <p class="description">Comma separated. Leave blank to allow any user in the configured tenant.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Shared secret</th>
                        <td>
                            <input type="text" name="shared_secret" class="regular-text" readonly
                                   value="<?php echo esc_attr( $editing['shared_secret'] ?? TTM_Entra_SSO_Proxy_Site_Registry::generateSecret() ); ?>">
                            <label><input type="checkbox" name="regenerate_secret" value="1"> Generate a new secret on save (breaks this site's SSO until the plugin settings there are updated to match)</label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Enabled</th>
                        <td><label><input type="checkbox" name="enabled" value="1" <?php checked( ! isset( $editing ) || ! empty( $editing['enabled'] ) ); ?>> Allow logins for this site</label></td>
                    </tr>
                </table>
                <?php submit_button( $editing ? 'Save site' : 'Add site' ); ?>
            </form>
        </div>
        <?php
    }
}
