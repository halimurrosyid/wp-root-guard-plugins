<?php
/**
 * Pengelolaan konfigurasi plugin dan whitelist untuk WP Root Guard.
 *
 * Berkas ini berisi class Settings yang menangani konfigurasi plugin,
 * penyimpanan opsi di database, pengelolaan daftar putih (whitelist),
 * serta validasi pengaturan keamanan termasuk trusted proxies.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Settings
 *
 * Menangani pengambilan, penyimpanan, dan validasi data whitelist
 * serta konfigurasi plugin WP Root Guard.
 *
 * @package WPRootGuard
 * @since   1.0.0
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
	 * Mendapatkan whitelist berkas bawaan di root WordPress.
	 *
	 * @return array Daftar nama berkas standar.
	 */
	public static function get_default_file_whitelist() {
		return array(
			'index.php',
			'license.txt',
			'readme.html',
			'wp-activate.php',
			'wp-blog-header.php',
			'wp-comments-post.php',
			'wp-config-sample.php',
			'wp-config.php',
			'wp-cron.php',
			'wp-links-opml.php',
			'wp-load.php',
			'wp-login.php',
			'wp-mail.php',
			'wp-settings.php',
			'wp-signup.php',
			'wp-trackback.php',
			'xmlrpc.php',
			'.htaccess',
			'web.config',
			'robots.txt',
			'favicon.ico',
		);
	}

	/**
	 * Mendapatkan semua folder dan file gabungan dari default whitelist dan user whitelist.
	 *
	 * @return array Gabungan semua folder dan file whitelist.
	 */
	public static function get_all_whitelisted() {
		return array_merge( 
			self::get_default_whitelist(), 
			self::get_default_file_whitelist(), 
			self::get_user_whitelist() 
		);
	}

	/**
	 * Memvalidasi dan membersihkan daftar IP trusted proxies.
	 *
	 * Memisahkan input berdasarkan baris baru atau koma, membuang spasi kosong,
	 * dan memvalidasi setiap IP dengan FILTER_VALIDATE_IP.
	 *
	 * @param mixed $proxies Daftar IP berupa array atau string.
	 * @return array Array berisi alamat IP yang valid dan unik.
	 */
	public static function sanitize_trusted_proxies( $proxies ) {
		if ( is_string( $proxies ) ) {
			$proxies = preg_split( '/[\r\n,]+/', $proxies );
		}

		if ( ! is_array( $proxies ) ) {
			return array();
		}

		$valid_proxies = array();
		foreach ( $proxies as $item ) {
			if ( is_string( $item ) ) {
				$sub_items = preg_split( '/[\r\n,]+/', $item );
				foreach ( $sub_items as $ip ) {
					$ip = trim( $ip );
					if ( '' !== $ip && filter_var( $ip, FILTER_VALIDATE_IP ) ) {
						$valid_proxies[] = $ip;
					}
				}
			}
		}

		return array_values( array_unique( $valid_proxies ) );
	}

	/**
	 * Mendapatkan seluruh pengaturan konfigurasi plugin dengan nilai bawaan.
	 *
	 * @return array Asosiatif array berisi pengaturan.
	 */
	public static function get_settings() {
		$defaults = array(
			'scan_interval'                 => 'every_5_minutes',
			'enable_uploads_php_scan'       => true,
			'enable_ip_blocker'             => false,
			'enable_auto_quarantine'        => false,
			'enable_email_notifications'    => false,
			'admin_email'                   => get_option( 'admin_email' ),
			'enable_telegram_notifications' => false,
			'telegram_bot_token'            => '',
			'telegram_chat_id'              => '',
			'trusted_proxies'               => array(),
		);

		$settings = get_option( 'wp_root_guard_settings', array() );
		$merged   = array_merge( $defaults, is_array( $settings ) ? $settings : array() );

		// Validasi trusted_proxies selalu berupa array IP yang valid.
		$merged['trusted_proxies'] = isset( $merged['trusted_proxies'] ) ? self::sanitize_trusted_proxies( $merged['trusted_proxies'] ) : array();

		return $merged;
	}

	/**
	 * Menyimpan dan memperbarui pengaturan plugin.
	 *
	 * @param array $new_settings Pengaturan baru yang akan disimpan.
	 * @return bool True jika berhasil diperbarui.
	 */
	public static function update_settings( $new_settings ) {
		if ( ! is_array( $new_settings ) ) {
			return false;
		}

		$settings = self::get_settings();

		if ( isset( $new_settings['scan_interval'] ) ) {
			$old_interval    = isset( $settings['scan_interval'] ) ? $settings['scan_interval'] : '';
			$new_interval    = sanitize_text_field( $new_settings['scan_interval'] );
			$valid_intervals = array( 'every_5_minutes', 'every_15_minutes', 'every_30_minutes', 'hourly', 'twicedaily', 'daily' );
			if ( in_array( $new_interval, $valid_intervals, true ) ) {
				$settings['scan_interval'] = $new_interval;
				if ( $old_interval !== $new_interval ) {
					Cron::reschedule_event( $new_interval );
				}
			}
		}

		if ( array_key_exists( 'enable_uploads_php_scan', $new_settings ) ) {
			$settings['enable_uploads_php_scan'] = filter_var( $new_settings['enable_uploads_php_scan'], FILTER_VALIDATE_BOOLEAN );
		}

		if ( array_key_exists( 'enable_ip_blocker', $new_settings ) ) {
			$settings['enable_ip_blocker'] = filter_var( $new_settings['enable_ip_blocker'], FILTER_VALIDATE_BOOLEAN );
		}

		if ( array_key_exists( 'enable_auto_quarantine', $new_settings ) ) {
			$settings['enable_auto_quarantine'] = filter_var( $new_settings['enable_auto_quarantine'], FILTER_VALIDATE_BOOLEAN );
		}

		if ( array_key_exists( 'enable_email_notifications', $new_settings ) ) {
			$settings['enable_email_notifications'] = filter_var( $new_settings['enable_email_notifications'], FILTER_VALIDATE_BOOLEAN );
		}

		if ( isset( $new_settings['admin_email'] ) ) {
			$settings['admin_email'] = sanitize_email( trim( (string) $new_settings['admin_email'] ) );
		}

		if ( array_key_exists( 'enable_telegram_notifications', $new_settings ) ) {
			$settings['enable_telegram_notifications'] = filter_var( $new_settings['enable_telegram_notifications'], FILTER_VALIDATE_BOOLEAN );
		}

		if ( isset( $new_settings['telegram_bot_token'] ) ) {
			$settings['telegram_bot_token'] = sanitize_text_field( trim( (string) $new_settings['telegram_bot_token'] ) );
		}

		if ( isset( $new_settings['telegram_chat_id'] ) ) {
			$settings['telegram_chat_id'] = sanitize_text_field( trim( (string) $new_settings['telegram_chat_id'] ) );
		}

		if ( isset( $new_settings['trusted_proxies'] ) ) {
			$settings['trusted_proxies'] = self::sanitize_trusted_proxies( $new_settings['trusted_proxies'] );
		}

		return update_option( 'wp_root_guard_settings', $settings );
	}

	/**
	 * Alias untuk update_settings().
	 *
	 * @param array $new_settings Pengaturan baru yang akan disimpan.
	 * @return bool True jika berhasil diperbarui.
	 */
	public static function save_settings( $new_settings ) {
		return self::update_settings( $new_settings );
	}
}
