<?php
declare(strict_types=1);

namespace VGT\Vault;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * UI/UX: VGT VAULT ADMIN DASHBOARD
 * Verwaltet Menüs, Asset-Ladevorgänge und CRUD-Operationen unter striktem Escaping.
 */
final class Admin_Dashboard {

    public const OPTION_PREFIX = 'vgt_vault_key_';

    public function __construct() {
        add_action( 'admin_menu', [ $this, 'register_menu' ] );
        add_action( 'admin_enqueue_scripts', [ $this, 'enqueue_assets' ] );
        add_action( 'admin_post_vgt_vault_save', [ $this, 'handle_save' ] );
        add_action( 'admin_post_vgt_vault_delete', [ $this, 'handle_delete' ] );
        add_action( 'admin_init', [ $this, 'inject_secure_headers' ], 1 );
    }

    public function register_menu(): void {
        add_menu_page( 
            esc_html__( 'VGT Vault', 'vgt-key-vault' ), 
            esc_html__( 'VGT Vault', 'vgt-key-vault' ), 
            'manage_options', 
            'vgt-vault', 
            [ $this, 'render_dashboard' ], 
            'dashicons-shield', 
            80 
        );
    }

    /**
     * Registriert und lädt die ausgelagerten Styles und JS-Dateien.
     */
    public function enqueue_assets( string $hook ): void {
        if ( 'toplevel_page_vgt-vault' !== $hook ) {
            return;
        }

        wp_enqueue_style( 
            'vgt-vault-admin-css', 
            VGT_VAULT_URL . 'assets/css/vgt-vault-admin.css', 
            [], 
            VGT_VAULT_VERSION 
        );

        wp_enqueue_script( 
            'vgt-vault-admin-js', 
            VGT_VAULT_URL . 'assets/js/vgt-vault-admin.js', 
            [ 'jquery' ], 
            VGT_VAULT_VERSION, 
            true 
        );

        // Weitergabe von lokalisierten und escapten Strings an JS (Abwehr von Manipulation)
        wp_localize_script( 'vgt-vault-admin-js', 'vgtVaultData', [
            'confirm_msg' => esc_html__( 'Kritische Systemwarnung: Die Terminierung zerstört die abhängigen API-Pipelines. Bestätigen?', 'vgt-key-vault' )
        ] );
    }

    public function inject_secure_headers(): void {
        if ( is_admin() && ! headers_sent() ) {
            if ( isset( $_GET['page'] ) && $_GET['page'] === 'vgt-vault' ) {
                header( 'X-Frame-Options: SAMEORIGIN' );
                header( 'X-Content-Type-Options: nosniff' );
                header( 'Referrer-Policy: strict-origin-when-cross-origin' );
                header( 'X-XSS-Protection: 1; mode=block' );
            }
        }
    }

    public function handle_save(): void {
        $this->verify_request( 'vgt_vault_save_action' );

        $raw_key_name = isset( $_POST['key_name'] ) ? (string) $_POST['key_name'] : '';
        // Rigorose Filterung des Keys auf alphanumerische Zeichen
        $key_name = preg_replace( '/[^a-zA-Z0-9_\-]/', '', $raw_key_name );
        $key_value = isset( $_POST['key_value'] ) ? trim( (string) wp_unslash( $_POST['key_value'] ) ) : '';

        if ( ! empty( $key_name ) && ! empty( $key_value ) ) {
            $option_name = self::OPTION_PREFIX . $key_name;
            
            try {
                $encrypted_payload = Crypto_Engine::encrypt( $key_value, $option_name );
                update_option( $option_name, $encrypted_payload, false );
                Vault_Registry::add_to_index( $option_name );
                $status = 'saved';
            } catch ( \Throwable $e ) {
                error_log( '[VGT_VAULT_ERROR] ' . sanitize_text_field( $e->getMessage() ) );
                $status = 'error_crypto';
            }
        } else {
            $status = 'error_input';
        }

        wp_safe_redirect( admin_url( 'admin.php?page=vgt-vault&status=' . sanitize_key( $status ) ) );
        exit;
    }

    public function handle_delete(): void {
        $this->verify_request( 'vgt_vault_delete_action' );

        $raw_option_name = isset( $_POST['option_name'] ) ? (string) $_POST['option_name'] : '';
        $option_name = sanitize_key( $raw_option_name );

        if ( ! empty( $option_name ) && str_starts_with( $option_name, self::OPTION_PREFIX ) ) {
            delete_option( $option_name );
            Vault_Registry::remove_from_index( $option_name );
            $status = 'deleted';
        } else {
            $status = 'error_delete';
        }

        wp_safe_redirect( admin_url( 'admin.php?page=vgt-vault&status=' . sanitize_key( $status ) ) );
        exit;
    }

    private function verify_request( string $nonce_action ): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'VGT Protocol: Access Denied.', 'vgt-key-vault' ), '', [ 'response' => 403 ] );
        }
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], $nonce_action ) ) {
            wp_die( esc_html__( 'VGT Protocol: Invalid Security Token (CSRF blockiert).', 'vgt-key-vault' ), '', [ 'response' => 403 ] );
        }
    }

    public function render_dashboard(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( esc_html__( 'VGT Protocol: Access Denied.', 'vgt-key-vault' ) );
        }

        $registered_keys = Vault_Registry::get_index();
        $stored_data = [];

        foreach ( $registered_keys as $key ) {
            if ( ! is_string( $key ) ) {
                continue;
            }
            $val = get_option( $key );
            if ( $val !== false ) {
                $stored_data[$key] = $val;
            } else {
                Vault_Registry::remove_from_index( $key ); 
            }
        }

        $this->render_html( $stored_data );
    }

    private function render_html( array $stored_data ): void {
        $status = isset( $_GET['status'] ) ? sanitize_key( $_GET['status'] ) : '';
        $pqc_active = Crypto_Engine::is_pqc_supported();
        ?>
        <div class="vgt-vault-matrix">
            <div class="vgt-header">
                <div class="vgt-icon-shield">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                    </svg>
                </div>
                <div class="vgt-header-text">
                    <h1><?php esc_html_e( 'VGT Crypto Vault', 'vgt-key-vault' ); ?></h1>
                    <p>
                        <?php esc_html_e( 'Status:', 'vgt-key-vault' ); ?> 
                        <?php if ( $pqc_active ) : ?>
                            <span class="vgt-badge vgt-badge-pqc"><?php esc_html_e( 'PQC-HYBRID AKTIV (ML-KEM-1024 / ML-DSA-87 + Classical)', 'vgt-key-vault' ); ?></span>
                        <?php else : ?>
                            <span class="vgt-badge vgt-badge-classic"><?php esc_html_e( 'AES-256-GCM AKTIV (Classic Secure)', 'vgt-key-vault' ); ?></span>
                        <?php endif; ?>
                    </p>
                </div>
            </div>

            <?php if ( $status === 'saved' ): ?>
                <div class="vgt-alert vgt-alert-success">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> 
                    <?php esc_html_e( 'Payload AAD-versiegelt und in Registry indiziert.', 'vgt-key-vault' ); ?>
                </div>
            <?php elseif ( $status === 'deleted' ): ?>
                <div class="vgt-alert vgt-alert-warn">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> 
                    <?php esc_html_e( 'Knotenpunkt und Index-Referenz terminiert.', 'vgt-key-vault' ); ?>
                </div>
            <?php elseif ( $status === 'error_crypto' ): ?>
                <div class="vgt-alert vgt-alert-danger">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> 
                    <?php esc_html_e( 'KERNEL PANIC: Verschlüsselung fehlgeschlagen. System-Salts prüfen.', 'vgt-key-vault' ); ?>
                </div>
            <?php elseif ( $status === 'error_input' ): ?>
                <div class="vgt-alert vgt-alert-danger">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> 
                    <?php esc_html_e( 'Eingabefehler: Identifier und Token dürfen nicht leer sein.', 'vgt-key-vault' ); ?>
                </div>
            <?php elseif ( $status === 'error_delete' ): ?>
                <div class="vgt-alert vgt-alert-danger">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> 
                    <?php esc_html_e( 'Löschfehler: Ungültiger Key-Namespace blockiert.', 'vgt-key-vault' ); ?>
                </div>
            <?php endif; ?>

            <div class="vgt-grid-layout">
                <div class="vgt-panel">
                    <h3>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path>
                        </svg> 
                        <?php esc_html_e( 'Key Injection', 'vgt-key-vault' ); ?>
                    </h3>
                    <form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="POST">
                        <input type="hidden" name="action" value="vgt_vault_save">
                        <?php wp_nonce_field( 'vgt_vault_save_action' ); ?>
                        
                        <div class="vgt-control">
                            <label class="vgt-label" for="key_name"><?php esc_html_e( 'System Identifier', 'vgt-key-vault' ); ?></label>
                            <input type="text" id="key_name" name="key_name" class="vgt-input" placeholder="groq_api_key" required autocomplete="off">
                        </div>
                        <div class="vgt-control">
                            <label class="vgt-label" for="key_value"><?php esc_html_e( 'Plaintext Token', 'vgt-key-vault' ); ?></label>
                            <input type="password" id="key_value" name="key_value" class="vgt-input" placeholder="gsk_..." required autocomplete="off">
                        </div>
                        <button type="submit" class="vgt-btn"><?php esc_html_e( 'In Vault versiegeln', 'vgt-key-vault' ); ?></button>
                        <p class="vgt-micro-copy">
                            <?php esc_html_e( 'Vollständig geschützte AAD-Bindung. Unautorisierte Modifikation der Quelldaten zerstört die Entschlüsselungskette mathematisch sofort.', 'vgt-key-vault' ); ?>
                        </p>
                    </form>
                </div>

                <div class="vgt-panel">
                    <h3>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
                        </svg> 
                        <?php esc_html_e( 'Aktive Kryptoknoten (O(1) Indexed)', 'vgt-key-vault' ); ?>
                    </h3>
                    <div class="vgt-key-stream">
                        <?php if ( empty( $stored_data ) ): ?>
                            <div class="vgt-empty-state">
                                <?php esc_html_e( 'Registry Index leer.', 'vgt-key-vault' ); ?>
                            </div>
                        <?php else: ?>
                            <?php foreach ( $stored_data as $key_name => $encrypted_val ) : ?>
                                <div class="vgt-key-node">
                                    <div class="vgt-key-meta">
                                        <span class="vgt-key-id">
                                            <?php echo esc_html( str_replace( self::OPTION_PREFIX, '', (string) $key_name ) ); ?>
                                        </span>
                                        <span class="vgt-key-hash">
                                            <?php echo esc_html( substr( (string) $encrypted_val, 0, 48 ) ); ?>...
                                        </span>
                                    </div>
                                    <form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="POST" class="vgt-delete-form">
                                        <input type="hidden" name="action" value="vgt_vault_delete">
                                        <input type="hidden" name="option_name" value="<?php echo esc_attr( (string) $key_name ); ?>">
                                        <?php wp_nonce_field( 'vgt_vault_delete_action' ); ?>
                                        <button type="submit" class="vgt-btn-danger"><?php esc_html_e( 'Terminieren', 'vgt-key-vault' ); ?></button>
                                    </form>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
}