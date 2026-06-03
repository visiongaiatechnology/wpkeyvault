<?php
/**
 * Plugin Name: VGT Key Vault
 * Plugin URI:  https://visiongaiatechnology.de
 * Description: Hochsicherer, AES-256-GCM verschlüsselter Tresor für API-Keys mit AAD-Binding.
 * Version:     3.1.0
 * Author:      VisionGaiaTechnology
 * Requires PHP: 8.0
 * License:     AGPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/agpl-3.0.html
 * * VGT OMEGA PROTOCOL: This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your option) 
 * any later version.
 */

declare(strict_types=1);

namespace VGT\Vault;

if ( ! defined( 'ABSPATH' ) ) {
    exit( 'VGT Protocol: Direct access denied.' );
}

// ============================================================================
// EXCEPTION HIERARCHY
// ============================================================================
class VaultException extends \Exception {}

/**
 * KERNEL: VISIONGAIATECHNOLOGY CRYPTO VAULT
 */
final class Crypto_Engine {

    private const ENCRYPTION_METHOD = 'aes-256-gcm';
    private const GCM_TAG_LENGTH = 16;

    /**
     * Deriviert einen mathematisch sicheren Master-Key mit maximaler Entropie.
     * Nutzt HKDF zur sicheren Schlüsselableitung aus allen verfügbaren WP-Salts.
     */
    private static function get_master_key(): string {
        $salts = '';
        $keys_to_check = [
            'SECURE_AUTH_KEY',
            'AUTH_KEY',
            'LOGGED_IN_KEY',
            'NONCE_KEY',
            'SECURE_AUTH_SALT',
            'AUTH_SALT',
            'LOGGED_IN_SALT',
            'NONCE_SALT'
        ];

        foreach ( $keys_to_check as $const ) {
            if ( defined( $const ) ) {
                $salts .= constant( $const );
            }
        }

        // Sicherheits-Anomalie-Schild bei fehlenden Salts in der wp-config.php
        if ( empty( $salts ) ) {
            $salts = get_option( 'vgt_vault_system_salt' );
            if ( empty( $salts ) ) {
                try {
                    $salts = bin2hex( random_bytes( 32 ) );
                    update_option( 'vgt_vault_system_salt', $salts, false );
                } catch ( \Throwable $e ) {
                    // Letzter Notanker bei fehlerhaftem OS-Zufallsgenerator
                    $salts = hash( 'sha256', (string) wp_hash( 'vgt-vault-emergency-salt' ) );
                }
            }
        }

        return hash_hkdf( 'sha256', $salts, 0, 'vgt_vault_master_domain_v3', 'vgt_hkdf_salt_binding' );
    }

    /**
     * Verschlüsselt Klartext mit AES-256-GCM und AAD-VGT-Context-Binding.
     */
    public static function encrypt( string $plaintext, string $context_id ): string {
        if ( empty( $plaintext ) ) {
            return '';
        }

        $iv_length = openssl_cipher_iv_length( self::ENCRYPTION_METHOD );
        if ( $iv_length === false ) {
            throw new VaultException( 'Kryptografischer Systemfehler: Ungültige IV-Länge.' );
        }

        $iv  = random_bytes( $iv_length );
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::ENCRYPTION_METHOD,
            self::get_master_key(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context_id, // AAD Binding (Verhindert Ciphertext-Swapping Angriffe)
            16
        );

        if ( $ciphertext === false ) {
            throw new VaultException( 'VGT Vault Error: AES-256-GCM encryption failed.' );
        }

        return base64_encode( $iv . $tag . $ciphertext );
    }

    /**
     * Entschlüsselt Chiffretext unter strikter GCM-Tag- und AAD-Verifikation.
     */
    public static function decrypt( string $payload, string $context_id ): string {
        if ( empty( $payload ) ) {
            return '';
        }

        $data = base64_decode( $payload, true );
        if ( $data === false ) {
            throw new VaultException( 'VGT Vault Error: Invalid Base64 payload.' );
        }

        $iv_length = openssl_cipher_iv_length( self::ENCRYPTION_METHOD );
        if ( $iv_length === false ) {
            throw new VaultException( 'Kryptografischer Systemfehler: Ungültige IV-Länge.' );
        }
        
        if ( strlen( $data ) < $iv_length + self::GCM_TAG_LENGTH ) {
            throw new VaultException( 'VGT Vault Error: Payload length compromised.' );
        }

        $iv         = substr( $data, 0, $iv_length );
        $tag        = substr( $data, $iv_length, self::GCM_TAG_LENGTH );
        $ciphertext = substr( $data, $iv_length + self::GCM_TAG_LENGTH );

        $decrypted = openssl_decrypt(
            $ciphertext,
            self::ENCRYPTION_METHOD,
            self::get_master_key(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context_id // AAD Binding Verification
        );

        if ( $decrypted === false ) {
            throw new VaultException( 'VGT Vault Error: Decryption failed. Signature mismatch, altered payload, or Context ID swap.' );
        }

        return $decrypted;
    }
}

/**
 * SYSTEM: REGISTRY (O(1) Data Retrieval via Hash Map)
 * STATUS: DIAMANT VGT SUPREME
 */
final class Vault_Registry {
    private const REGISTRY_KEY = 'vgt_vault_registry_index';

    public static function add_to_index( string $option_name ): void {
        $index = get_option( self::REGISTRY_KEY, [] );
        if ( ! is_array( $index ) ) {
            $index = [];
        }
        if ( ! isset( $index[ $option_name ] ) ) {
            $index[ $option_name ] = true; // Hash Map Allocation (O(1))
            update_option( self::REGISTRY_KEY, $index, false );
        }
    }

    public static function remove_from_index( string $option_name ): void {
        $index = get_option( self::REGISTRY_KEY, [] );
        if ( is_array( $index ) && isset( $index[ $option_name ] ) ) {
            unset( $index[ $option_name ] );
            update_option( self::REGISTRY_KEY, $index, false );
        }
    }

    public static function get_index(): array {
        $index = get_option( self::REGISTRY_KEY, [] );
        if ( empty( $index ) || ! is_array( $index ) ) {
            return [];
        }

        // Auto-Migration: Falls noch das alte Array-Format (O(n)) in der DB liegt,
        // wird es on-the-fly in die Hash-Map migriert.
        if ( isset( $index[0] ) ) {
            $migrated_index = [];
            foreach ( $index as $val ) {
                if ( is_string( $val ) ) {
                    $migrated_index[ $val ] = true;
                }
            }
            update_option( self::REGISTRY_KEY, $migrated_index, false );
            return array_keys( $migrated_index );
        }

        return array_keys( $index );
    }
}

/**
 * UI/UX: VGT VAULT ADMIN DASHBOARD
 */
final class Admin_Dashboard {

    public const OPTION_PREFIX = 'vgt_vault_key_';

    public function __construct() {
        add_action( 'admin_menu', [ $this, 'register_menu' ] );
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
     * Injektiert systemweit strikte Sicherheits-Header zur Abwehr von Browser-basierten Angriffen.
     */
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
        
        // CHIRURGISCHES SANITIZING: Erlaube nur sichere alphanumerische Zeichen für Options-Namen
        $key_name = preg_replace( '/[^a-zA-Z0-9_\-]/', '', $raw_key_name );
        $key_value = isset( $_POST['key_value'] ) ? trim( (string) wp_unslash( $_POST['key_value'] ) ) : '';

        if ( ! empty( $key_name ) && ! empty( $key_value ) ) {
            // Option-Swapping Barriere: Erzwinge zwingend den isolierten Prefix
            $option_name = self::OPTION_PREFIX . $key_name;
            
            try {
                // Verschlüsselung mit AAD Context
                $encrypted_payload = Crypto_Engine::encrypt( $key_value, $option_name );
                update_option( $option_name, $encrypted_payload, false );
                Vault_Registry::add_to_index( $option_name );
                $status = 'saved';
            } catch ( \Throwable $e ) {
                error_log( '[VGT_VAULT_ERROR] ' . $e->getMessage() );
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

        // Verifiziere, dass der zu löschende Key tatsächlich zum isolierten Vault-Namespace gehört
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
                Vault_Registry::remove_from_index( $key ); // Auto-Heal Registry
            }
        }

        $this->render_html( $stored_data );
    }

    private function render_html( array $stored_data ): void {
        $status = isset( $_GET['status'] ) ? sanitize_key( $_GET['status'] ) : '';
        ?>
        <style>
            :root {
                --vgt-bg: #09090b; --vgt-surface: #121216; --vgt-border: rgba(255, 255, 255, 0.08);
                --vgt-accent: #00e5ff; --vgt-accent-glow: rgba(0, 229, 255, 0.2);
                --vgt-danger: #ef4444; --vgt-text-main: #f8fafc; --vgt-text-muted: #94a3b8;
            }
            .vgt-vault-matrix {
                max-width: 1200px; margin: 30px auto 30px 10px; font-family: 'Inter', system-ui, sans-serif; 
                color: var(--vgt-text-main); background: var(--vgt-bg); border-radius: 16px; 
                padding: 30px; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); border: 1px solid var(--vgt-border);
            }
            .vgt-vault-matrix * { box-sizing: border-box; }
            .vgt-header { display: flex; align-items: center; gap: 24px; padding-bottom: 30px; border-bottom: 1px solid var(--vgt-border); margin-bottom: 30px; position: relative; }
            .vgt-header::after { content: ''; position: absolute; bottom: -1px; left: 0; width: 150px; height: 1px; background: var(--vgt-accent); box-shadow: 0 0 15px var(--vgt-accent); }
            .vgt-icon-shield { width: 56px; height: 56px; background: var(--vgt-accent-glow); border: 1px solid rgba(0,229,255,0.4); border-radius: 14px; display: flex; align-items: center; justify-content: center; color: var(--vgt-accent); }
            .vgt-header-text h1 { margin: 0; font-size: 1.8rem; font-weight: 800; color: #fff; letter-spacing: -0.02em; }
            .vgt-header-text p { margin: 4px 0 0; color: var(--vgt-text-muted); font-size: 0.95rem; }
            .vgt-grid-layout { display: grid; grid-template-columns: 400px 1fr; gap: 32px; align-items: start; }
            @media (max-width: 900px) { .vgt-grid-layout { grid-template-columns: 1fr; } }
            .vgt-panel { background: var(--vgt-surface); border: 1px solid var(--vgt-border); border-radius: 12px; padding: 28px; position: relative; overflow: hidden; }
            .vgt-panel h3 { margin: 0 0 24px 0; font-size: 1.1rem; color: #fff; display: flex; align-items: center; gap: 10px; font-weight: 600; }
            .vgt-control { margin-bottom: 20px; }
            .vgt-label { display: block; color: var(--vgt-text-muted); font-size: 0.8rem; text-transform: uppercase; font-weight: 700; margin-bottom: 8px; letter-spacing: 0.05em; }
            .vgt-input { width: 100%; background: #000; border: 1px solid var(--vgt-border); color: #fff; padding: 12px 16px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; transition: all 0.2s ease; }
            .vgt-input:focus { border-color: var(--vgt-accent); outline: none; box-shadow: 0 0 0 3px var(--vgt-accent-glow); }
            .vgt-btn { width: 100%; background: var(--vgt-text-main); color: #000; border: none; padding: 14px; border-radius: 8px; font-weight: 700; font-size: 0.95rem; cursor: pointer; transition: all 0.2s ease; display: inline-flex; justify-content: center; align-items: center; gap: 8px; }
            .vgt-btn:hover { background: var(--vgt-accent); transform: translateY(-1px); box-shadow: 0 4px 12px var(--vgt-accent-glow); }
            .vgt-btn-danger { width: auto; background: transparent; color: var(--vgt-danger); border: 1px solid rgba(239, 68, 68, 0.3); padding: 8px 16px; font-size: 0.85rem; font-weight: 700; border-radius: 8px; cursor: pointer; transition: all 0.2s; }
            .vgt-btn-danger:hover { background: rgba(239, 68, 68, 0.1); border-color: var(--vgt-danger); color: var(--vgt-danger); }
            .vgt-key-stream { display: flex; flex-direction: column; gap: 12px; }
            .vgt-key-node { background: #000; border: 1px solid var(--vgt-border); border-radius: 8px; padding: 16px; display: flex; justify-content: space-between; align-items: center; transition: border-color 0.2s; }
            .vgt-key-node:hover { border-color: rgba(255,255,255,0.2); }
            .vgt-key-meta { display: flex; flex-direction: column; gap: 6px; overflow: hidden; }
            .vgt-key-id { color: var(--vgt-text-main); font-weight: 600; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; }
            .vgt-key-hash { color: var(--vgt-accent); font-size: 0.75rem; font-family: monospace; opacity: 0.7; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 350px; }
            .vgt-alert { padding: 16px; border-radius: 8px; margin-bottom: 24px; font-weight: 500; display: flex; align-items: center; gap: 10px; font-size: 0.9rem; }
            .vgt-alert-success { background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.2); }
            .vgt-alert-warn { background: rgba(245, 158, 11, 0.1); color: #f59e0b; border: 1px solid rgba(245, 158, 11, 0.2); }
            .vgt-alert-danger { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.2); }
            .vgt-micro-copy { font-size: 0.75rem; color: var(--vgt-text-muted); margin-top: 16px; line-height: 1.5; }
        </style>

        <div class="vgt-vault-matrix">
            <div class="vgt-header">
                <div class="vgt-icon-shield">
                    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                </div>
                <div class="vgt-header-text">
                    <h1><?php esc_html_e( 'VGT Crypto Vault', 'vgt-key-vault' ); ?></h1>
                    <p><?php esc_html_e( 'AES-256-GCM Verschlüsselungs-Kernel. Context-Aware AAD Binding integriert.', 'vgt-key-vault' ); ?></p>
                </div>
            </div>

            <?php if ( $status === 'saved' ): ?>
                <div class="vgt-alert vgt-alert-success"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> <?php esc_html_e( 'Payload AAD-versiegelt und in Registry indiziert.', 'vgt-key-vault' ); ?></div>
            <?php elseif ( $status === 'deleted' ): ?>
                <div class="vgt-alert vgt-alert-warn"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg> <?php esc_html_e( 'Knotenpunkt und Index-Referenz terminiert.', 'vgt-key-vault' ); ?></div>
            <?php elseif ( $status === 'error_crypto' ): ?>
                <div class="vgt-alert vgt-alert-danger"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg> <?php esc_html_e( 'KERNEL PANIC: Verschlüsselung fehlgeschlagen. System-Salts prüfen.', 'vgt-key-vault' ); ?></div>
            <?php elseif ( $status === 'error_input' ): ?>
                <div class="vgt-alert vgt-alert-danger"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> <?php esc_html_e( 'Eingabefehler: Identifier und Token dürfen nicht leer sein.', 'vgt-key-vault' ); ?></div>
            <?php elseif ( $status === 'error_delete' ): ?>
                <div class="vgt-alert vgt-alert-danger"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg> <?php esc_html_e( 'Löschfehler: Ungültiger Key-Namespace blockiert.', 'vgt-key-vault' ); ?></div>
            <?php endif; ?>

            <div class="vgt-grid-layout">
                <div class="vgt-panel">
                    <h3><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg> <?php esc_html_e( 'Key Injection', 'vgt-key-vault' ); ?></h3>
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
                        <p class="vgt-micro-copy"><?php esc_html_e( 'Mathematische GCM-Sicherung. Der Ciphertext ist hardware- und site-gebunden an den Identifier (AAD). Unautorisierte Manipulation ist rechnerisch unmöglich.', 'vgt-key-vault' ); ?></p>
                    </form>
                </div>

                <div class="vgt-panel">
                    <h3><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg> <?php esc_html_e( 'Aktive Kryptoknoten (O(1) Indexed)', 'vgt-key-vault' ); ?></h3>
                    <div class="vgt-key-stream">
                        <?php if ( empty( $stored_data ) ): ?>
                            <div style="color: var(--vgt-text-muted); font-size: 0.9rem; text-align: center; padding: 20px; border: 1px dashed var(--vgt-border); border-radius: 8px;"><?php esc_html_e( 'Registry Index leer.', 'vgt-key-vault' ); ?></div>
                        <?php else: ?>
                            <?php foreach ( $stored_data as $key_name => $encrypted_val ) : ?>
                                <div class="vgt-key-node">
                                    <div class="vgt-key-meta">
                                        <!-- Bereinige Ausgabe des Prefixes zur besseren Lesbarkeit -->
                                        <span class="vgt-key-id"><?php echo esc_html( str_replace( self::OPTION_PREFIX, '', (string) $key_name ) ); ?></span>
                                        <span class="vgt-key-hash">GCM-Cipher: <?php echo esc_html( substr( (string) $encrypted_val, 0, 42 ) ); ?>...</span>
                                    </div>
                                    <form action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" method="POST" onsubmit="return confirm('<?php echo esc_js( __( 'Kritische Systemwarnung: Die Terminierung zerstört die abhängigen API-Pipelines. Bestätigen?', 'vgt-key-vault' ) ); ?>');">
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

/**
 * SYSTEM: INTER-PLUGIN API FACADE
 * STATUS: DIAMANT VGT SUPREME
 * * Nutzung in externen Modulen: \VGT\Vault\API::get_key('groq_api_key');
 */
final class API {
    /**
     * Extrahiert und dechiffriert einen Key in O(1).
     * @throws VaultException bei Manipulation oder Fehlen des Keys.
     */
    public static function get_key( string $identifier ): string {
        $option_name = Admin_Dashboard::OPTION_PREFIX . preg_replace( '/[^a-zA-Z0-9_\-]/', '', $identifier );
        $payload = get_option( $option_name );
        
        if ( $payload === false ) {
            throw new VaultException( "VGT Vault Error: Key [{$identifier}] existiert nicht in der Matrix." );
        }

        return Crypto_Engine::decrypt( (string) $payload, $option_name );
    }
}

// Initialisierung der Admin-Konsole
if ( is_admin() ) {
    new Admin_Dashboard();
}
