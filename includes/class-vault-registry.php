<?php
declare(strict_types=1);

namespace VGT\Vault;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * SYSTEM: REGISTRY (O(1) Data Retrieval via Hash Map)
 * STATUS: DIAMANT VGT SUPREME
 */
final class Vault_Registry {
    private const REGISTRY_KEY = 'vgt_vault_registry_index';

    /**
     * Fügt einen Schlüssel im O(1) Index der WordPress Options-Datenbank hinzu.
     */
    public static function add_to_index( string $option_name ): void {
        $index = get_option( self::REGISTRY_KEY, [] );
        if ( ! is_array( $index ) ) {
            $index = [];
        }
        
        $sanitized_name = sanitize_key( $option_name );
        
        if ( ! isset( $index[ $sanitized_name ] ) ) {
            $index[ $sanitized_name ] = true; // Hash Map Allocation (O(1))
            update_option( self::REGISTRY_KEY, $index, false );
        }
    }

    /**
     * Entfernt einen Schlüssel im O(1) Index.
     */
    public static function remove_from_index( string $option_name ): void {
        $index = get_option( self::REGISTRY_KEY, [] );
        $sanitized_name = sanitize_key( $option_name );
        
        if ( is_array( $index ) && isset( $index[ $sanitized_name ] ) ) {
            unset( $index[ $sanitized_name ] );
            update_option( self::REGISTRY_KEY, $index, false );
        }
    }

    /**
     * Liefert ein flaches Array aller indizierten Keys.
     */
    public static function get_index(): array {
        $index = get_option( self::REGISTRY_KEY, [] );
        if ( empty( $index ) || ! is_array( $index ) ) {
            return [];
        }

        // Auto-Migration bei altem Format (O(n))
        if ( isset( $index[0] ) ) {
            $migrated_index = [];
            foreach ( $index as $val ) {
                if ( is_string( $val ) ) {
                    $migrated_index[ sanitize_key( $val ) ] = true;
                }
            }
            update_option( self::REGISTRY_KEY, $migrated_index, false );
            return array_keys( $migrated_index );
        }

        return array_keys( $index );
    }
}