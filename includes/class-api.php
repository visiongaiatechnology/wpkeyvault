<?php
declare(strict_types=1);

namespace VGT\Vault;

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * SYSTEM: INTER-PLUGIN API FACADE
 * STATUS: DIAMANT VGT SUPREME
 * * Verwendung in externen Systemen: 
 * \VGT\Vault\API::get_key('groq_api_key');
 */
final class API {
    /**
     * Extrahiert und dechiffriert einen Key in O(1).
     * * @throws VaultException bei Manipulation oder Fehlen des Keys.
     */
    public static function get_key( string $identifier ): string {
        $sanitized_identifier = preg_replace( '/[^a-zA-Z0-9_\-]/', '', $identifier );
        $option_name = Admin_Dashboard::OPTION_PREFIX . $sanitized_identifier;
        
        $payload = get_option( $option_name );
        
        if ( $payload === false ) {
            throw new VaultException( "VGT Vault Error: Key [{$identifier}] existiert nicht in der Matrix." );
        }

        return Crypto_Engine::decrypt( (string) $payload, $option_name );
    }
}