<?php
/**
 * Mengelola pengaturan plugin dan whitelist.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Settings
 *
 * Menangani pengambilan dan penyimpanan data whitelist serta konfigurasi plugin.
 */
class Settings {

	/**
	 * Mendapatkan whitelist bawaan (default whitelist).
	 *
	 * @return array Daftar folder yang masuk dalam whitelist bawaan.
	 */
	public static function get_default_whitelist() {
		return array(
			'wp-admin',
			'wp-content',
			'wp-includes',
			'.well-known',
			'cgi-bin',
		);
	}

	/**
	 * Mendapatkan whitelist kustom dari user (diambil dari Options API).
	 *
	 * @return array Daftar folder yang di-whitelist oleh user.
	 */
	public static function get_user_whitelist() {
		$whitelist = get_option( 'wp_root_guard_whitelist', array() );
		return is_array( $whitelist ) ? $whitelist : array();
	}

	/**
	 * Menambahkan folder ke whitelist kustom user.
	 *
	 * @param string $folder Nama folder yang ingin dipercayai.
	 * @return bool True jika berhasil ditambahkan, false jika sebaliknya.
	 */
	public static function add_to_whitelist( $folder ) {
		$folder = sanitize_text_field( trim( $folder ) );
		if ( empty( $folder ) ) {
			return false;
		}

		$whitelist = self::get_user_whitelist();

		// Jika folder sudah ada di whitelist atau default whitelist, return true.
		if ( in_array( $folder, $whitelist, true ) || in_array( $folder, self::get_default_whitelist(), true ) ) {
			return true;
		}

		$whitelist[] = $folder;
		return update_option( 'wp_root_guard_whitelist', $whitelist );
	}

	/**
	 * Menghapus folder dari whitelist kustom user.
	 *
	 * @param string $folder Nama folder yang ingin dihapus dari whitelist.
	 * @return bool True jika berhasil dihapus, false jika sebaliknya.
	 */
	public static function remove_from_whitelist( $folder ) {
		$folder = sanitize_text_field( trim( $folder ) );
		if ( empty( $folder ) ) {
			return false;
		}

		$whitelist = self::get_user_whitelist();
		$key       = array_search( $folder, $whitelist, true );

		if ( false !== $key ) {
			unset( $whitelist[ $key ] );
			$whitelist = array_values( $whitelist );
			return update_option( 'wp_root_guard_whitelist', $whitelist );
		}

		return false;
	}

	/**
	 * Mendapatkan semua folder gabungan dari default whitelist dan user whitelist.
	 *
	 * @return array Gabungan semua folder whitelist.
	 */
	public static function get_all_whitelisted() {
		return array_merge( self::get_default_whitelist(), self::get_user_whitelist() );
	}
}
