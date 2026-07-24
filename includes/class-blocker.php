<?php
/**
 * Mengelola pemblokiran IP penyerang dan proteksi akses webshell di .htaccess.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Blocker
 *
 * Menangani pencegatan permintaan HTTP mencurigakan, pencatatan IP penyerang,
 * serta pembaruan otomatis berkas root .htaccess.
 */
class Blocker {

	/**
	 * Mendaftarkan hook penjelajahan HTTP.
	 */
	public function init() {
		add_action( 'init', array( $this, 'intercept_malicious_requests' ), 1 );
	}

	/**
	 * Mendapatkan alamat IP pengakses dengan mempertimbangkan proxy / Cloudflare secara aman.
	 *
	 * @return string Alamat IP pengakses.
	 */
	public static function get_client_ip() {
		$ip = '';
		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$ip = sanitize_text_field( $_SERVER['HTTP_CF_CONNECTING_IP'] );
		} elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$ip_list = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
			$ip      = trim( reset( $ip_list ) );
		} elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( $_SERVER['REMOTE_ADDR'] );
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '127.0.0.1';
	}

	/**
	 * Mencegat permintaan HTTP berbahaya (misal mencoba menjalankan .php di folder uploads atau query string webshell).
	 */
	public function intercept_malicious_requests() {
		$settings = Settings::get_settings();
		if ( empty( $settings['enable_ip_blocker'] ) ) {
			return;
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] ) ? strtolower( $_SERVER['REQUEST_URI'] ) : '';
		$query_str   = isset( $_SERVER['QUERY_STRING'] ) ? strtolower( $_SERVER['QUERY_STRING'] ) : '';

		$is_malicious = false;
		$reason       = '';

		// 1. Percobaan mengeksekusi berkas PHP di dalam wp-content/uploads/
		if ( false !== strpos( $request_uri, '/wp-content/uploads/' ) && preg_match( '/\.(php|phtml|php3|php4|php5|php7|phps|phar|inc)($|\?)/i', $request_uri ) ) {
			$is_malicious = true;
			$reason       = esc_html__( 'Percobaan Eksekusi PHP di Folder Uploads', 'wp-root-guard' );
		}

		// 2. Query string webshell mencurigakan (misal ?cmd=id, ?shell=, ?c99=, ?r57=)
		if ( ! $is_malicious && ! empty( $query_str ) ) {
			if ( preg_match( '/(cmd=|shell=|c99=|r57=|eval\(|base64_decode\()/i', $query_str ) ) {
				$is_malicious = true;
				$reason       = esc_html__( 'Percobaan Webshell Command Injection', 'wp-root-guard' );
			}
		}

		if ( $is_malicious ) {
			$ip = self::get_client_ip();
			self::block_ip( $ip, $reason );

			// Berikan respons HTTP 403 Forbidden dan langsung hentikan proses
			header( 'HTTP/1.1 403 Forbidden' );
			header( 'Status: 403 Forbidden' );
			wp_die(
				esc_html__( 'Akses Ditolak: Aktivitas mencurigakan terdeteksi oleh WP Root Guard.', 'wp-root-guard' ),
				esc_html__( '403 Forbidden', 'wp-root-guard' ),
				array( 'response' => 403 )
			);
		}
	}

	/**
	 * Memblokir IP penyerang dan memperbarui berkas root .htaccess.
	 *
	 * @param string $ip Alamat IP yang ingin diblokir.
	 * @param string $reason Alasan pemblokiran.
	 * @return bool True jika berhasil diblokir.
	 */
	public static function block_ip( $ip, $reason = '' ) {
		$ip = filter_var( trim( $ip ), FILTER_VALIDATE_IP );
		if ( ! $ip ) {
			return false;
		}

		$blocked_ips = get_option( 'wp_root_guard_blocked_ips', array() );
		if ( ! is_array( $blocked_ips ) ) {
			$blocked_ips = array();
		}

		if ( ! isset( $blocked_ips[ $ip ] ) ) {
			$time_wib = Scanner::get_wib_time();
			$blocked_ips[ $ip ] = array(
				'ip'     => $ip,
				'reason' => ! empty( $reason ) ? $reason : esc_html__( 'Manual Block / Malicious Activity', 'wp-root-guard' ),
				'time'   => $time_wib,
			);
			update_option( 'wp_root_guard_blocked_ips', $blocked_ips );

			self::sync_htaccess_blocked_ips( $blocked_ips );

			Logger::log(
				esc_html__( 'IP Penyerang Diblokir Otomatis', 'wp-root-guard' ),
				$ip . ' (' . $reason . ')',
				esc_html__( 'Blocked', 'wp-root-guard' )
			);

			// Kirim notifikasi Telegram jika aktif
			$settings = Settings::get_settings();
			if ( ! empty( $settings['enable_telegram_notifications'] ) && ! empty( $settings['telegram_bot_token'] ) && ! empty( $settings['telegram_chat_id'] ) ) {
				$site_name = get_bloginfo( 'name' );
				$site_url  = home_url();
				$tg_msg    = "🚫 *[WP Root Guard] IP Penyerang Diblokir!*\n\n";
				$tg_msg   .= "Situs: *{$site_name}* ({$site_url})\n";
				$tg_msg   .= "📍 *IP*: `{$ip}`\n";
				$tg_msg   .= "💀 *Alasan*: {$reason}\n";
				$tg_msg   .= "⏱️ *Waktu*: {$time_wib}";
				Scanner::send_telegram_message( $settings['telegram_bot_token'], $settings['telegram_chat_id'], $tg_msg );
			}

			return true;
		}

		return false;
	}

	/**
	 * Membuka blokir IP (Unblock IP).
	 *
	 * @param string $ip Alamat IP yang ingin dibuka blokirnya.
	 * @return bool True jika berhasil di-unblock.
	 */
	public static function unblock_ip( $ip ) {
		$blocked_ips = get_option( 'wp_root_guard_blocked_ips', array() );
		if ( is_array( $blocked_ips ) && isset( $blocked_ips[ $ip ] ) ) {
			unset( $blocked_ips[ $ip ] );
			update_option( 'wp_root_guard_blocked_ips', $blocked_ips );

			self::sync_htaccess_blocked_ips( $blocked_ips );

			Logger::log(
				esc_html__( 'IP Penyerang Dibuka Blokirnya (Unblocked)', 'wp-root-guard' ),
				$ip,
				esc_html__( 'Unblocked', 'wp-root-guard' )
			);

			return true;
		}
		return false;
	}

	/**
	 * Mengambil daftar IP yang saat ini diblokir.
	 *
	 * @return array Daftar IP terblokir.
	 */
	public static function get_blocked_ips() {
		$blocked = get_option( 'wp_root_guard_blocked_ips', array() );
		return is_array( $blocked ) ? $blocked : array();
	}

	/**
	 * Menyinkronkan daftar IP terblokir ke berkas root .htaccess.
	 *
	 * @param array $blocked_ips Daftar IP terblokir.
	 */
	public static function sync_htaccess_blocked_ips( $blocked_ips ) {
		$htaccess_file = ABSPATH . '.htaccess';
		if ( ! file_exists( $htaccess_file ) || ! is_writable( $htaccess_file ) ) {
			return;
		}

		$content = file_get_contents( $htaccess_file );

		$start_marker = '# BEGIN WP Root Guard Blocked IPs';
		$end_marker   = '# END WP Root Guard Blocked IPs';

		$block_rules = '';
		if ( ! empty( $blocked_ips ) ) {
			$block_rules  = $start_marker . "\n";
			$block_rules .= "<IfModule mod_authz_core.c>\n";
			foreach ( $blocked_ips as $ip_info ) {
				$block_rules .= "    Require not ip " . $ip_info['ip'] . "\n";
			}
			$block_rules .= "</IfModule>\n";
			$block_rules .= "<IfModule !mod_authz_core.c>\n";
			$block_rules .= "    Order allow,deny\n";
			$block_rules .= "    Allow from all\n";
			foreach ( $blocked_ips as $ip_info ) {
				$block_rules .= "    Deny from " . $ip_info['ip'] . "\n";
			}
			$block_rules .= "</IfModule>\n";
			$block_rules .= $end_marker;
		}

		// Jika marker sudah ada, ganti blok lamanya.
		if ( false !== strpos( $content, $start_marker ) && false !== strpos( $content, $end_marker ) ) {
			$pattern     = '/' . preg_quote( $start_marker, '/' ) . '.*?' . preg_quote( $end_marker, '/' ) . '/s';
			$new_content = preg_replace( $pattern, $block_rules, $content );
		} else {
			$new_content = ! empty( $block_rules ) ? $content . "\n\n" . $block_rules . "\n" : $content;
		}

		@file_put_contents( $htaccess_file, $new_content );
	}
}
