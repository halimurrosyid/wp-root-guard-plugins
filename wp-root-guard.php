<?php
/**
 * Bootstrap utama plugin WP Root Guard.
 *
 * Berkas ini bertanggung jawab untuk:
 * 1. Mendefinisikan konstanta global plugin.
 * 2. Mendaftarkan autoloader untuk namespace WPRootGuard.
 * 3. Mendaftarkan hook aktivasi dan deaktivasi plugin.
 * 4. Menjalankan plugin via hook plugins_loaded.
 *
 * @package           WPRootGuard
 * @since             1.0.0
 * @author            Mujaddid Halimurrosyid
 * @copyright         2026 Mujaddid Halimurrosyid
 * @license           GPL-2.0-or-later
 *
 * @wordpress-plugin
 * Plugin Name:       WP Root Guard
 * Plugin URI:        https://ajidmujaddid.staff.telkomuniversity.ac.id/
 * Description:       Mendeteksi folder asing/mencurigakan yang muncul di root directory WordPress Anda untuk mencegah malware judi slot.
 * Version:           3.2.0
 * Author:            Mujaddid Halimurrosyid
 * Author URI:        https://ajidmujaddid.staff.telkomuniversity.ac.id/
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
define( 'WP_ROOT_GUARD_VERSION', '3.2.0' );
define( 'WP_ROOT_GUARD_FILE', __FILE__ );
define( 'WP_ROOT_GUARD_PATH', plugin_dir_path( __FILE__ ) );
define( 'WP_ROOT_GUARD_URL', plugin_dir_url( __FILE__ ) );

/**
 * Autoloader PSR-like untuk namespace WPRootGuard.
 *
 * Memetakan WPRootGuard\NamaKelas menjadi class-nama-kelas.php.
 * Folder top-level dapat diperluas via filter wp_root_guard_autoload_dirs.
 *
 * @param string $class Nama kelas lengkap beserta namespace.
 */
spl_autoload_register( function ( $class ) {
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

	if ( empty( $parts ) ) {
		$file_path = WP_ROOT_GUARD_PATH . 'includes/' . $class_name;
	} else {
		$first_part = strtolower( $parts[0] );

		$known_dirs = apply_filters(
			'wp_root_guard_autoload_dirs',
			array( 'admin', 'includes' )
		);

		if ( in_array( $first_part, $known_dirs, true ) ) {
			$dir_path  = strtolower( implode( '/', $parts ) );
			$file_path = WP_ROOT_GUARD_PATH . $dir_path . '/' . $class_name;
		} else {
			$file_path = WP_ROOT_GUARD_PATH . 'includes/' . $class_name;
		}
	}

	if ( file_exists( $file_path ) ) {
		require_once $file_path;
	}
} );

/**
 * Fungsi aktivasi plugin.
 *
 * Memvalidasi versi PHP dan WordPress sebelum menjalankan Activator.
 */
function wp_root_guard_activate() {
	if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
		deactivate_plugins( plugin_basename( __FILE__ ) );
		wp_die( esc_html__( 'Plugin ini memerlukan PHP versi 8.1 atau lebih tinggi.', 'wp-root-guard' ) );
	}

	global $wp_version;
	if ( version_compare( $wp_version, '6.0', '<' ) ) {
		deactivate_plugins( plugin_basename( __FILE__ ) );
		wp_die( esc_html__( 'Plugin ini memerlukan WordPress versi 6.0 atau lebih tinggi.', 'wp-root-guard' ) );
	}

	if ( class_exists( 'WPRootGuard\\Activator' ) ) {
		WPRootGuard\Activator::activate();
	}
}
register_activation_hook( __FILE__, 'wp_root_guard_activate' );

/**
 * Fungsi deaktivasi plugin.
 */
function wp_root_guard_deactivate() {
	if ( class_exists( 'WPRootGuard\\Deactivator' ) ) {
		WPRootGuard\Deactivator::deactivate();
	}
}
register_deactivation_hook( __FILE__, 'wp_root_guard_deactivate' );

/**
 * Memulai plugin.
 *
 * Dijalankan via plugins_loaded priority 5 agar semua plugin sudah ter-load
 * sebelum orkestrasi, menghindari race condition dengan plugin lain.
 */
function wp_root_guard_run() {
	if ( ! class_exists( 'WPRootGuard\\Plugin' ) ) {
		return;
	}
	$plugin = new WPRootGuard\Plugin();
	$plugin->run();
}
add_action( 'plugins_loaded', 'wp_root_guard_run', 5 );
