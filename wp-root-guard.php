<?php
/**
 * WP Root Guard
 *
 * @package           WPRootGuard
 * @author            Mujaddid Halimurrosyid
 * @copyright         2026 Mujaddid Halimurrosyid
 * @license           GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       WP Root Guard
 * Plugin URI:        https://indahweb.com/wp-root-guard
 * Description:       Mendeteksi folder asing/mencurigakan yang muncul di root directory WordPress Anda untuk mencegah malware judi slot.
 * Version:           1.0.1
 * Author:            Mujaddid Halimurrosyid
 * Author URI:        https://indahweb.com
 * License:           GPL v2 or later
 * Text Domain:       wp-root-guard
 * Domain Path:       /languages
 * Requires PHP:      8.1
 * Requires at least: 6.0
 */

// Mencegah akses langsung ke file.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// Definisikan konstanta plugin.
define( 'WP_ROOT_GUARD_VERSION', '1.0.1' );
define( 'WP_ROOT_GUARD_FILE', __FILE__ );
define( 'WP_ROOT_GUARD_PATH', plugin_dir_path( __FILE__ ) );
define( 'WP_ROOT_GUARD_URL', plugin_dir_url( __FILE__ ) );

/**
 * Autoloader kustom untuk WP Root Guard.
 * Mengikuti struktur namespace WPRootGuard.
 *
 * @param string $class Nama kelas lengkap beserta namespace.
 */
spl_autoload_register( function( $class ) {
	$prefix = 'WPRootGuard\\';
	$len    = strlen( $prefix );

	if ( strncmp( $prefix, $class, $len ) !== 0 ) {
		return;
	}

	$relative_class = substr( $class, $len );
	$file           = str_replace( '\\', '/', $relative_class );
	$parts          = explode( '/', $file );
	$last           = array_pop( $parts );

	// Konversi nama kelas menjadi format WordPress (class-nama-kelas.php)
	$class_name = 'class-' . strtolower( preg_replace( '/([a-z])([A-Z])/', '$1-$2', $last ) ) . '.php';
	array_push( $parts, $class_name );

	$first_part = strtolower( $parts[0] );
	if ( in_array( $first_part, array( 'admin', 'includes' ), true ) ) {
		$file_path = WP_ROOT_GUARD_PATH . strtolower( implode( '/', $parts ) );
	} else {
		$file_path = WP_ROOT_GUARD_PATH . 'includes/' . $class_name;
	}

	if ( file_exists( $file_path ) ) {
		require_once $file_path;
	}
} );

/**
 * Fungsi aktivasi plugin.
 */
function activate_wp_root_guard() {
	if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
		deactivate_plugins( plugin_basename( __FILE__ ) );
		wp_die( esc_html__( 'Plugin ini memerlukan PHP versi 8.1 atau lebih tinggi.', 'wp-root-guard' ) );
	}
	WPRootGuard\Activator::activate();
}
register_activation_hook( __FILE__, 'activate_wp_root_guard' );

/**
 * Fungsi deaktivasi plugin.
 */
function deactivate_wp_root_guard() {
	WPRootGuard\Deactivator::deactivate();
}
register_deactivation_hook( __FILE__, 'deactivate_wp_root_guard' );

/**
 * Memulai plugin.
 */
function run_wp_root_guard() {
	$plugin = new WPRootGuard\Plugin();
	$plugin->run();
}
run_wp_root_guard();
