<?php
/**
 * Plugin Name: VGT Key Vault
 * Plugin URI:  https://visiongaiatechnology.de
 * Description: Hochsicherer, modularer, AES-256-GCM / PQC-Hybrid verschlüsselter Tresor für API-Keys mit AAD-Binding.
 * Version:     4.0.0
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

// Definition von Plugin-Konstanten für saubere Dateipfade
define( 'VGT_VAULT_PATH', plugin_dir_path( __FILE__ ) );
define( 'VGT_VAULT_URL', plugin_dir_url( __FILE__ ) );
define( 'VGT_VAULT_VERSION', '4.0.0' );

// Exception Hierarchy
class VaultException extends \Exception {}

// Laden der modularen Kern-Klassen
require_once VGT_VAULT_PATH . 'includes/class-crypto-engine.php';
require_once VGT_VAULT_PATH . 'includes/class-vault-registry.php';
require_once VGT_VAULT_PATH . 'includes/class-api.php';
require_once VGT_VAULT_PATH . 'includes/class-admin-dashboard.php';

// Initialisierung des Dashboards im Admin-Kontext
if ( is_admin() ) {
    new Admin_Dashboard();
}