<?php
/**
 * Modul proteksi aktif WP Root Guard.
 *
 * Berkas ini berisi class Blocker yang bertanggung jawab untuk:
 * 1. Mencegat request HTTP mencurigakan (eksekusi PHP di uploads, query webshell).
 * 2. Mendeteksi IP pengakses dengan aman (trusted proxy aware).
 * 3. Memblokir IP penyerang via .htaccess dan fallback PHP.
 * 4. Mengelola auto-expire IP dengan cron prune.
 * 5. Menyinkronkan aturan blokir ke .htaccess secara atomic.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Blocker
 *
 * Menangani pencegatan permintaan HTTP mencurigakan, pencatatan IP penyerang,
 * pembaruan otomatis berkas root .htaccess, dan auto-expire IP blokir.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Blocker {

	/**
	 * Durasi default blokir IP dalam detik (24 jam).
	 */
	const DEFAULT_BLOCK_DURATION = 86400;

	/**
	 * Nama transient untuk lock file .htaccess.
	 */
	const HTACCESS_LOCK_KEY = 'wp_root_guard_htaccess_lock';

	/**
	 * Mendaftarkan hook penjelajahan HTTP.
	 */
	public function init() {
		add_action( 'init', array( $this, 'intercept_malicious_requests' ), 1 );
	}

	/**
	 * Mendapatkan alamat IP pengakses dengan aman.
	 *
	 * OWASP A01:2021 — Broken Access Control (CWE-348 IP Spoofing).
	 * Header proxy (CF-Connecting-IP, X-Forwarded-For) hanya dipercaya
	 * jika REMOTE_ADDR terdaftar di trusted proxy. Fallback ke REMOTE_ADDR.
	 *
	 * @return string Alamat IP pengakses.
	 */
	public static function get_client_ip() {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] )
			? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) )
			: '';

		if ( ! filter_var( $remote_addr, FILTER_VALIDATE_IP ) ) {
			return '0.0.0.0';
		}

		$settings        = Settings::get_settings();
		$trusted_proxies = isset( $settings['trusted_proxies'] ) && is_array( $settings['trusted_proxies'] )
			? $settings['trusted_proxies']
			: array();

		if ( ! in_array( $remote_addr, $trusted_proxies, true ) ) {
			return $remote_addr;
		}

		if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
			$candidate = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
			if ( filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
				return $candidate;
			}
		}

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
			$list = array_map(
				'trim',
				explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) )
			);
			for ( $i = count( $list ) - 1; $i >= 0; $i-- ) {
				$candidate = $list[ $i ];
				if ( ! filter_var( $candidate, FILTER_VALIDATE_IP ) ) {
					continue;
				}
				if ( ! in_array( $candidate, $trusted_proxies, true ) ) {
					return $candidate;
				}
			}
		}

		return $remote_addr;
	}

	/**
	 * Mencegat permintaan HTTP berbahaya.
	 *
	 * OWASP A01:2021 — Broken Access Control.
	 * Pattern check SELALU dijalankan (termasuk admin-ajax). Admin login
	 * yang sah hanya di-log, bukan diblokir, kecuali via admin-ajax.
	 * Cron dan WP-CLI dikecualikan untuk mencegah self-block.
	 */
	public function intercept_malicious_requests() {
		if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$settings = Settings::get_settings();
		if ( empty( $settings['enable_ip_blocker'] ) ) {
			return;
		}

		$is_admin_request = is_admin();
		$can_manage       = current_user_can( 'manage_options' );

		$request_uri = isset( $_SERVER['REQUEST_URI'] )
			? strtolower( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) )
			: '';
		$query_str   = isset( $_SERVER['QUERY_STRING'] )
			? strtolower( sanitize_text_field( wp_unslash( $_SERVER['QUERY_STRING'] ) ) )
			: '';

		$is_malicious = false;
		$reason       = '';

		if ( false !== strpos( $request_uri, '/wp-content/uploads/' )
			&& preg_match( '/\.(php|phtml|php3|php4|php5|php7|phps|phar|inc)($|\?)/i', $request_uri ) ) {
			$is_malicious = true;
			$reason       = esc_html__( 'Percobaan Eksekusi PHP di Folder Uploads', 'wp-root-guard' );
		}

		if ( ! $is_malicious && ! empty( $query_str ) ) {
			if ( preg_match( '/(?:^|&)(cmd|shell|c99|r57|eval)\s*=/i', $query_str )
				|| preg_match( '/base64_decode\s*\(/i', $query_str ) ) {
				$is_malicious = true;
				$reason       = esc_html__( 'Percobaan Webshell Command Injection', 'wp-root-guard' );
			}
		}

		if ( ! $is_malicious ) {
			$ip          = self::get_client_ip();
			$blocked_ips = self::get_blocked_ips();
			if ( isset( $blocked_ips[ $ip ] ) ) {
				if ( $is_admin_request && ! wp_doing_ajax() && $can_manage ) {
					return;
				}
				$is_malicious = true;
				$reason       = isset( $blocked_ips[ $ip ]['reason'] )
					? $blocked_ips[ $ip ]['reason']
					: esc_html__( 'IP Terblokir oleh Sistem Security', 'wp-root-guard' );
			}
		}

		if ( $is_malicious ) {
			if ( $is_admin_request && ! wp_doing_ajax() && $can_manage ) {
				Logger::log(
					esc_html__( 'Pola mencurigakan diakses oleh admin', 'wp-root-guard' ),
					$request_uri,
					esc_html__( 'Warning', 'wp-root-guard' )
				);
				return;
			}

			$ip = self::get_client_ip();
			self::block_ip( $ip, $reason );
			self::render_403_page( $ip, $reason );
		}
	}

	/**
	 * Menampilkan halaman 403 dan menghentikan eksekusi.
	 *
	 * @param string $ip Alamat IP.
	 * @param string $reason Alasan blokir.
	 */
	private static function render_403_page( $ip, $reason ) {
		header( 'HTTP/1.1 403 Forbidden' );
		header( 'Status: 403 Forbidden' );
		header( 'Retry-After: 3600' );

		$die_message  = '<div style="font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif; line-height: 1.6; color: #1e293b;">';
		$die_message .= '<h2 style="color: #dc2626; margin-top: 0;">🚫 ' . esc_html__( 'Akses Ditolak oleh WP Root Guard', 'wp-root-guard' ) . '</h2>';
		$die_message .= '<p>' . sprintf( esc_html__( 'Alamat IP Anda (%s) atau permintaan HTTP yang Anda kirimkan terdeteksi mengandung aktivitas mencurigakan oleh sistem keamanan WP Root Guard.', 'wp-root-guard' ), '<code>' . esc_html( $ip ) . '</code>' ) . '</p>';
		if ( ! empty( $reason ) ) {
			$die_message .= '<p style="background: #fef2f2; border-left: 4px solid #ef4444; padding: 10px 14px; border-radius: 4px;"><strong>' . esc_html__( 'Alasan Pemblokiran:', 'wp-root-guard' ) . '</strong> ' . esc_html( $reason ) . '</p>';
		}
		$die_message .= '<hr style="border: none; border-top: 1px solid #e2e8f0; margin: 16px 0;">';
		$die_message .= '<p style="font-size: 13px; color: #64748b;">' . sprintf(
			wp_kses_post( __( 'Jika Anda adalah Administrator situs ini, Anda tetap dapat mengakses dasbor di %s untuk mengelola dan membuka pemblokiran IP ini di menu <strong>Root Guard -> Proteksi IP Terblokir</strong>.', 'wp-root-guard' ) ),
			'<a href="' . esc_url( admin_url() ) . '" style="color: #2563eb;">' . esc_html( admin_url() ) . '</a>'
		) . '</p>';
		$die_message .= '</div>';

		wp_die(
			$die_message,
			esc_html__( '403 Forbidden - WP Root Guard', 'wp-root-guard' ),
			array( 'response' => 403 )
		);
	}

	/**
	 * Memblokir IP penyerang dengan auto-expire.
	 *
	 * OWASP A04:2021 — Insecure Design (CWE-770 Resource Exhaustion).
	 * Setiap IP yang diblokir memiliki timestamp expiry untuk mencegah
	 * .htaccess membengkak tanpa batas.
	 *
	 * @param string $ip Alamat IP yang ingin diblokir.
	 * @param string $reason Alasan pemblokiran.
	 * @param int    $duration Durasi blokir (detik). 0 = default 24 jam.
	 * @return bool True jika berhasil diblokir.
	 */
	public static function block_ip( $ip, $reason = '', $duration = 0 ) {
		$ip = filter_var( trim( $ip ), FILTER_VALIDATE_IP );
		if ( ! $ip ) {
			return false;
		}

		// Jangan pernah memblokir localhost/loopback demi mencegah lockout developer/admin
		if ( in_array( $ip, array( '127.0.0.1', '::1' ), true ) ) {
			return false;
		}

		$settings        = Settings::get_settings();
		$trusted_proxies = isset( $settings['trusted_proxies'] ) && is_array( $settings['trusted_proxies'] )
			? $settings['trusted_proxies']
			: array();

		// Jangan pernah memblokir IP yang terdaftar di trusted proxies
		if ( in_array( $ip, $trusted_proxies, true ) ) {
			return false;
		}

		$blocked_ips = get_option( 'wp_root_guard_blocked_ips', array() );
		if ( ! is_array( $blocked_ips ) ) {
			$blocked_ips = array();
		}

		if ( isset( $blocked_ips[ $ip ] ) ) {
			return false;
		}

		$duration = $duration > 0 ? $duration : self::DEFAULT_BLOCK_DURATION;
		$time_wib = Scanner::get_wib_time();

		$blocked_ips[ $ip ] = array(
			'ip'      => $ip,
			'reason'  => ! empty( $reason ) ? $reason : __( 'Manual Block / Malicious Activity', 'wp-root-guard' ),
			'time'    => $time_wib,
			'expires' => time() + $duration,
		);

		update_option( 'wp_root_guard_blocked_ips', $blocked_ips );
		self::sync_htaccess_blocked_ips( $blocked_ips );

		Logger::log(
			esc_html__( 'IP Penyerang Diblokir Otomatis', 'wp-root-guard' ),
			$ip . ' (' . $reason . ')',
			esc_html__( 'Blocked', 'wp-root-guard' )
		);

		$settings = Settings::get_settings();
		if ( ! empty( $settings['enable_telegram_notifications'] )
			&& ! empty( $settings['telegram_bot_token'] )
			&& ! empty( $settings['telegram_chat_id'] ) ) {
			$site_name = get_bloginfo( 'name' );
			$site_url  = home_url();
			$tg_msg    = "🚫 *[WP Root Guard] IP Penyerang Diblokir!*\n\n";
			$tg_msg   .= "Situs: *{$site_name}* ({$site_url})\n";
			$tg_msg   .= "📍 *IP*: `{$ip}`\n";
			$tg_msg   .= "💀 *Alasan*: {$reason}\n";
			$tg_msg   .= "⏱️ *Waktu*: {$time_wib}\n";
			$tg_msg   .= "⏳ *Berlaku hingga*: " . Scanner::get_wib_time( time() + $duration );
			Scanner::send_telegram_message( $settings['telegram_bot_token'], $settings['telegram_chat_id'], $tg_msg );
		}

		return true;
	}

	/**
	 * Membuka blokir IP.
	 *
	 * @param string $ip Alamat IP yang ingin dibuka blokirnya.
	 * @return bool True jika berhasil di-unblock.
	 */
	public static function unblock_ip( $ip ) {
		$ip = filter_var( trim( $ip ), FILTER_VALIDATE_IP );
		if ( ! $ip ) {
			return false;
		}

		$blocked_ips = get_option( 'wp_root_guard_blocked_ips', array() );
		if ( ! is_array( $blocked_ips ) || ! isset( $blocked_ips[ $ip ] ) ) {
			return false;
		}

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

	/**
	 * Membersihkan IP yang sudah kedaluwarsa dari block list.
	 *
	 * Dipanggil oleh cron job wp_root_guard_prune_ips.
	 *
	 * @return int Jumlah IP yang dibersihkan.
	 */
	public static function prune_expired_ips() {
		$blocked_ips = get_option( 'wp_root_guard_blocked_ips', array() );
		if ( ! is_array( $blocked_ips ) || empty( $blocked_ips ) ) {
			return 0;
		}

		$now     = time();
		$changed = false;
		$count   = 0;

		foreach ( $blocked_ips as $ip => $info ) {
			if ( isset( $info['expires'] ) && $info['expires'] > 0 && $info['expires'] < $now ) {
				unset( $blocked_ips[ $ip ] );
				$changed = true;
				++$count;

				Logger::log(
					esc_html__( 'IP kedaluwarsa dibersihkan otomatis', 'wp-root-guard' ),
					$ip,
					esc_html__( 'Expired', 'wp-root-guard' )
				);
			}
		}

		if ( $changed ) {
			update_option( 'wp_root_guard_blocked_ips', $blocked_ips );
			self::sync_htaccess_blocked_ips( $blocked_ips );
		}

		return $count;
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
	 * OWASP A04:2021 — Insecure Design (CWE-362 Race Condition).
	 * Menggunakan transient lock untuk mencegah dua request paralel
	 * menulis .htaccess secara bersamaan.
	 *
	 * OWASP A09:2021 — Security Logging & Monitoring Failures.
	 * Kegagalan tulis dicatat ke Logger, bukan disembunyikan dengan @.
	 *
	 * @param array $blocked_ips Daftar IP terblokir.
	 * @return bool True jika berhasil menulis.
	 */
	public static function sync_htaccess_blocked_ips( $blocked_ips ) {
		if ( get_transient( self::HTACCESS_LOCK_KEY ) ) {
			return false;
		}
		set_transient( self::HTACCESS_LOCK_KEY, 1, 5 );

		try {
			$htaccess_file = ABSPATH . '.htaccess';
			if ( ! file_exists( $htaccess_file ) || ! is_writable( $htaccess_file ) ) {
				Logger::log(
					esc_html__( 'Berkas .htaccess tidak dapat ditulis', 'wp-root-guard' ),
					$htaccess_file,
					esc_html__( 'Error', 'wp-root-guard' )
				);
				delete_transient( self::HTACCESS_LOCK_KEY );
				return false;
			}

			$content = file_get_contents( $htaccess_file );
			if ( false === $content ) {
				Logger::log(
					esc_html__( 'Gagal membaca .htaccess', 'wp-root-guard' ),
					$htaccess_file,
					esc_html__( 'Error', 'wp-root-guard' )
				);
				delete_transient( self::HTACCESS_LOCK_KEY );
				return false;
			}

			$start_marker = '# BEGIN WP Root Guard Blocked IPs';
			$end_marker   = '# END WP Root Guard Blocked IPs';

			$block_rules = '';
			if ( ! empty( $blocked_ips ) ) {
				$block_rules  = $start_marker . "\n";
				$block_rules .= "<IfModule mod_authz_core.c>\n";
				$block_rules .= "    <RequireAll>\n";
				$block_rules .= "        Require all granted\n";
				foreach ( $blocked_ips as $ip_info ) {
					if ( isset( $ip_info['ip'] ) ) {
						$block_rules .= "        Require not ip " . $ip_info['ip'] . "\n";
					}
				}
				$block_rules .= "    </RequireAll>\n";
				$block_rules .= "</IfModule>\n";
				$block_rules .= "<IfModule !mod_authz_core.c>\n";
				$block_rules .= "    Order allow,deny\n";
				$block_rules .= "    Allow from all\n";
				foreach ( $blocked_ips as $ip_info ) {
					if ( isset( $ip_info['ip'] ) ) {
						$block_rules .= "    Deny from " . $ip_info['ip'] . "\n";
					}
				}
				$block_rules .= "</IfModule>\n";
				$block_rules .= $end_marker;
			}

			if ( false !== strpos( $content, $start_marker ) && false !== strpos( $content, $end_marker ) ) {
				$pattern = '/' . preg_quote( $start_marker, '/' ) . '.*?' . preg_quote( $end_marker, '/' ) . '/s';
				// Callback mencegah $ di block_rules diartikan sebagai backreference.
				$new_content = preg_replace_callback(
					$pattern,
					static function () use ( $block_rules ) {
						return $block_rules;
					},
					$content
				);
			} else {
				$new_content = ! empty( $block_rules ) ? $content . "\n\n" . $block_rules . "\n" : $content;
			}

			$written = file_put_contents( $htaccess_file, $new_content, LOCK_EX );
			if ( false === $written ) {
				Logger::log(
					esc_html__( 'Gagal menulis .htaccess', 'wp-root-guard' ),
					$htaccess_file,
					esc_html__( 'Error', 'wp-root-guard' )
				);
				delete_transient( self::HTACCESS_LOCK_KEY );
				return false;
			}

			delete_transient( self::HTACCESS_LOCK_KEY );
			return true;
		} catch ( \Exception $e ) {
			Logger::log(
				esc_html__( 'Exception saat sinkronisasi .htaccess', 'wp-root-guard' ),
				$e->getMessage(),
				esc_html__( 'Error', 'wp-root-guard' )
			);
			delete_transient( self::HTACCESS_LOCK_KEY );
			return false;
		}
	}
}
