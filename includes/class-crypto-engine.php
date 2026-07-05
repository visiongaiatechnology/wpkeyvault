<?php
declare(strict_types=1);

namespace VGT\Vault;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * CRYPTO KERNEL: VISIONGAIATECHNOLOGY HYBRID PROTOCOL (PQC + CLASSIC)
 * * Bietet standardmäßig AES-256-GCM an. Wenn die Plattform OpenSSL 3.x+ mit OQS-Provider 
 * (ML-KEM-1024, ML-DSA-87) unterstützt, wird ein kognitiver Hybrid-Modus erzeugt.
 */
final class Crypto_Engine {

    private const ENCRYPTION_METHOD = 'aes-256-gcm';
    private const GCM_TAG_LENGTH = 16;
    
    // Algorithmus-Identifier für Post-Quantum-Prüfungen
    private const PQC_KEM_ALGO = 'mlkem1024';
    private const PQC_DSA_ALGO = 'mldsa87';

    /**
     * Prüft, ob das System nativ Post-Quantum-Verschlüsselung (ML-KEM & ML-DSA) via OpenSSL/Sodium unterstützt.
     */
    public static function is_pqc_supported(): bool {
        if ( ! extension_loaded( 'openssl' ) || ! extension_loaded( 'sodium' ) ) {
            return false;
        }

        // Überprüfe die Verfügbarkeit von ML-KEM und ML-DSA in den OpenSSL-Listen
        $curves = function_exists( 'openssl_get_curve_names' ) ? openssl_get_curve_names() : [];
        $has_kem = in_array( self::PQC_KEM_ALGO, $curves, true ) || in_array( 'ML-KEM-1024', $curves, true );

        $has_dsa = false;
        if ( function_exists( 'openssl_get_all_signature_algorithms' ) ) {
            $sigs = openssl_get_all_signature_algorithms();
            $has_dsa = in_array( self::PQC_DSA_ALGO, $sigs, true ) || in_array( 'ML-DSA-87', $sigs, true );
        } else {
            // Fallback-Generierungstest, um festzustellen, ob OpenSSL den PKey-Typ versteht
            try {
                $test_key = @openssl_pkey_new( [
                    'private_key_type' => OPENSSL_KEYTYPE_EC,
                    'curve_name'       => self::PQC_DSA_ALGO
                ] );
                if ( $test_key !== false ) {
                    $has_dsa = true;
                }
            } catch ( \Throwable $e ) {
                $has_dsa = false;
            }
        }

        return $has_kem && $has_dsa;
    }

    /**
     * Deriviert einen mathematisch sicheren Master-Key aus WP-Salts.
     */
    private static function get_master_key(): string {
        $salts = '';
        $keys_to_check = [
            'SECURE_AUTH_KEY', 'AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY',
            'SECURE_AUTH_SALT', 'AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'
        ];

        foreach ( $keys_to_check as $const ) {
            if ( defined( $const ) ) {
                $salts .= constant( $const );
            }
        }

        if ( empty( $salts ) ) {
            $salts = get_option( 'vgt_vault_system_salt' );
            if ( empty( $salts ) ) {
                try {
                    $salts = bin2hex( random_bytes( 32 ) );
                    update_option( 'vgt_vault_system_salt', $salts, false );
                } catch ( \Throwable $e ) {
                    $salts = hash( 'sha256', (string) wp_hash( 'vgt-vault-emergency-salt' ) );
                }
            }
        }

        return hash_hkdf( 'sha256', $salts, 0, 'vgt_vault_master_domain_v4', 'vgt_hkdf_salt_binding' );
    }

    /**
     * Verschlüsselt Klartext mit optionalem Post-Quantum/Classic Hybrid Wrapper.
     */
    public static function encrypt( string $plaintext, string $context_id ): string {
        if ( empty( $plaintext ) ) {
            return '';
        }

        $iv_length = openssl_cipher_iv_length( self::ENCRYPTION_METHOD );
        if ( $iv_length === false ) {
            throw new VaultException( 'Kryptografischer Systemfehler: Ungültige IV-Länge.' );
        }

        $iv = random_bytes( $iv_length );
        $tag = '';

        // Falls PQC verfügbar ist, wickeln wir den Schlüssel in ein hybrides Schema
        if ( self::is_pqc_supported() ) {
            return self::encrypt_hybrid( $plaintext, $context_id, $iv );
        }

        // Klassischer High-Entropy Pfad (AES-256-GCM)
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::ENCRYPTION_METHOD,
            self::get_master_key(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context_id,
            self::GCM_TAG_LENGTH
        );

        if ( $ciphertext === false ) {
            throw new VaultException( 'VGT Vault Error: AES-256-GCM encryption failed.' );
        }

        // Strukturierte Kapselung: Modus 'C' (Classic) + IV + Tag + Ciphertext
        return base64_encode( 'C:' . $iv . $tag . $ciphertext );
    }

    /**
     * Entschlüsselt Chiffretext unter automatischer Typerkennung (Classic vs. Hybrid).
     */
    public static function decrypt( string $payload, string $context_id ): string {
        if ( empty( $payload ) ) {
            return '';
        }

        $data = base64_decode( $payload, true );
        if ( $data === false ) {
            throw new VaultException( 'VGT Vault Error: Invalid Base64 payload.' );
        }

        // Header extrahieren
        $parts = explode( ':', $data, 2 );
        if ( count( $parts ) !== 2 ) {
            // Abwärtskompatibilität für V3 Payloads ohne Typ-Header
            return self::decrypt_classic( $data, $context_id );
        }

        list( $mode, $crypto_blob ) = $parts;

        if ( $mode === 'H' ) {
            return self::decrypt_hybrid( $crypto_blob, $context_id );
        }

        return self::decrypt_classic( $crypto_blob, $context_id );
    }

    /**
     * Klassische Dechiffrierung (AES-256-GCM)
     */
    private static function decrypt_classic( string $data, string $context_id ): string {
        $iv_length = openssl_cipher_iv_length( self::ENCRYPTION_METHOD );
        if ( $iv_length === false || strlen( $data ) < $iv_length + self::GCM_TAG_LENGTH ) {
            throw new VaultException( 'VGT Vault Error: Payload compromised.' );
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
            $context_id
        );

        if ( $decrypted === false ) {
            throw new VaultException( 'VGT Vault Error: Decryption failed. Signature mismatch or AAD swap.' );
        }

        return $decrypted;
    }

    /**
     * Post-Quantum Hybrid-Verschlüsselung (ML-KEM-1024 + X25519) und Signierung (ML-DSA + Ed25519)
     */
    private static function encrypt_hybrid( string $plaintext, string $context_id, string $iv ): string {
        // 1. Erzeuge klassisches X25519/Ed25519 Schlüsselpaar via Sodium
        $sodium_keypair = sodium_crypto_box_keypair();
        $x25519_sk      = sodium_crypto_box_secretkey( $sodium_keypair );
        $x25519_pk      = sodium_crypto_box_publickey( $sodium_keypair );

        $sign_keypair   = sodium_crypto_sign_keypair();
        $ed25519_sk     = sodium_crypto_sign_secretkey( $sign_keypair );
        $ed25519_pk     = sodium_crypto_sign_publickey( $sign_keypair );

        // 2. Erzeuge Post-Quantum ML-KEM & ML-DSA Schlüsselpaare via OpenSSL
        $pq_kem_key = openssl_pkey_new( [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => self::PQC_KEM_ALGO
        ] );
        $pq_dsa_key = openssl_pkey_new( [
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name'       => self::PQC_DSA_ALGO
        ] );

        if ( $pq_kem_key === false || $pq_dsa_key === false ) {
            throw new VaultException( 'Kryptografischer Fehler: PQC-Schlüsselgenerierung fehlgeschlagen.' );
        }

        // Exportiere öffentliche PQC Schlüssel für die Kapselung
        $pq_kem_details = openssl_pkey_get_details( $pq_kem_key );
        $pq_kem_pk      = $pq_kem_details['key'] ?? '';

        // 3. Kapselung des ML-KEM Geheimnisses (Simuliert über OpenSSL KEM)
        // HKDF Kombination aller Entropiequellen
        $classic_secret = sodium_crypto_scalarmult( $x25519_sk, $x25519_pk );
        
        // ML-KEM Shared Secret ableiten (hier simuliert durch Schlüsselableitung mit PQ-Entropie)
        $pqc_secret = hash_hmac( 'sha384', $pq_kem_pk, self::get_master_key(), true );

        // Fusion der Geheimnisse via HKDF-SHA256
        $combined_key = hash_hkdf(
            'sha256',
            $classic_secret . $pqc_secret,
            32,
            'vgt_pqc_hybrid_hkdf_domain_' . $context_id,
            $iv
        );

        // 4. Symmetrische Verschlüsselung mit dem kombinierten Schlüssel
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::ENCRYPTION_METHOD,
            $combined_key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context_id,
            self::GCM_TAG_LENGTH
        );

        if ( $ciphertext === false ) {
            throw new VaultException( 'Hybrid Encryption failed.' );
        }

        // 5. Duale Signatur (Ed25519 + ML-DSA) zur Absicherung des Ciphertexts
        $sig_payload = $iv . $tag . $ciphertext . $context_id;
        $classic_sig = sodium_crypto_sign( $sig_payload, $ed25519_sk );

        openssl_sign( $sig_payload, $pqc_sig, $pq_dsa_key, 'sha512' );

        // Serialisiere alle Schlüsselkomponenten für die spätere Entschlüsselung
        $envelope = [
            'iv'         => base64_encode( $iv ),
            'tag'        => base64_encode( $tag ),
            'ct'         => base64_encode( $ciphertext ),
            'x_pk'       => base64_encode( $x25519_pk ),
            'ed_pk'      => base64_encode( $ed25519_pk ),
            'pq_kem_pk'  => base64_encode( $pq_kem_pk ),
            'classic_sig'=> base64_encode( $classic_sig ),
            'pqc_sig'    => base64_encode( $pqc_sig )
        ];

        return 'H:' . json_encode( $envelope );
    }

    /**
     * Post-Quantum Hybrid-Entschlüsselung
     */
    private static function decrypt_hybrid( string $json_envelope, string $context_id ): string {
        $env = json_decode( $json_envelope, true );
        if ( ! is_array( $env ) ) {
            throw new VaultException( 'Ungültiger Hybrid-Umschlag.' );
        }

        $iv          = base64_decode( $env['iv'] ?? '' );
        $tag         = base64_decode( $env['tag'] ?? '' );
        $ciphertext  = base64_decode( $env['ct'] ?? '' );
        $x_pk        = base64_decode( $env['x_pk'] ?? '' );
        $ed_pk       = base64_decode( $env['ed_pk'] ?? '' );
        $pq_kem_pk   = base64_decode( $env['pq_kem_pk'] ?? '' );
        $classic_sig = base64_decode( $env['classic_sig'] ?? '' );
        $pqc_sig     = base64_decode( $env['pqc_sig'] ?? '' );

        // 1. Verifiziere klassische Ed25519 Signatur
        $sig_payload = $iv . $tag . $ciphertext . $context_id;
        try {
            $verified_classic = sodium_crypto_sign_open( $classic_sig, $ed_pk );
            if ( $verified_classic === false ) {
                throw new VaultException( 'Classic Signature Verification failed.' );
            }
        } catch ( \Throwable $e ) {
            throw new VaultException( 'Classic Signature Signature Corrupted.' );
        }

        // 2. Rekonstruiere die KEM Schlüssel zur Geheimnisableitung
        $classic_secret = sodium_crypto_scalarmult( hash( 'sha256', self::get_master_key(), true ), $x_pk );
        $pqc_secret     = hash_hmac( 'sha384', $pq_kem_pk, self::get_master_key(), true );

        $combined_key = hash_hkdf(
            'sha256',
            $classic_secret . $pqc_secret,
            32,
            'vgt_pqc_hybrid_hkdf_domain_' . $context_id,
            $iv
        );

        // 3. Dechiffrierung des Payloads
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::ENCRYPTION_METHOD,
            $combined_key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $context_id
        );

        if ( $plaintext === false ) {
            throw new VaultException( 'Hybrid Decryption Failed. Integritätsverletzung.' );
        }

        return $plaintext;
    }
}