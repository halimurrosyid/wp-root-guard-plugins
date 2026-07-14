<?php
/**
 * Memindai direktori root WordPress dan mencari folder mencurigakan/asing.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Scanner
 *
 * Melakukan pemindaian direktori root non-rekursif, mendeteksi folder asing,
 * menangani karantina otomatis, dan mengirimkan notifikasi peringatan.
 */
class Scanner {

	/**
	 * Melakukan pemindaian root directory.
	 *
	 * @return array Hasil pemindaian berupa status proteksi dan detail folder asing yang terdeteksi.
	 */
	public static function perform_scan() {
		// Dapatkan folder saat ini di root.
		$current_folders = Baseline::scan_root_folders();

		// Ambil baseline & whitelist.
		$baseline        = Baseline::get_baseline();
		$default_wl      = Settings::get_default_whitelist();
		$user_wl         = Settings::get_user_whitelist();
		$settings        = Settings::get_settings();

		// Gabungkan whitelist dan baseline untuk pengecekan.
		$known_folders = array_unique( array_merge( $baseline, $default_wl, $user_wl ) );

		$unknown_folders = array();

		foreach ( $current_folders as $folder ) {
			// Cek apakah folder terdaftar sebagai folder yang dikenal.
			if ( ! in_array( $folder, $known_folders, true ) ) {
				$full_path = ABSPATH . $folder;

				// Dapatkan waktu pembuatan folder jika memungkinkan.
				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $full_path ) ) {
					$ctime = filectime( $full_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$detection_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), current_time( 'timestamp' ) );
				$status_text    = esc_html__( 'Unknown Folder', 'wp-root-guard' );

				// Jika fitur karantina otomatis aktif, langsung amankan folder.
				if ( $settings['enable_auto_quarantine'] ) {
					$quarantine_name = self::quarantine_folder( $folder );
					if ( false !== $quarantine_name ) {
						$status_text = esc_html__( 'Quarantined Automatically', 'wp-root-guard' );
						$full_path   = ABSPATH . $quarantine_name;
					}
				} else {
					// Log kejadian penemuan folder asing (jika tidak dikarantina otomatis,
					// karena jika dikarantina, fungsi quarantine_folder sudah menulis log tersendiri).
					Logger::log(
						esc_html__( 'Folder asing terdeteksi', 'wp-root-guard' ),
						$folder,
						esc_html__( 'Unknown', 'wp-root-guard' )
					);
				}

				$unknown_folders[] = array(
					'name'           => $folder,
					'path'           => $full_path,
					'created_time'   => $created_time,
					'detection_time' => $detection_time,
					'status'         => $status_text,
				);
			}
		}

		// Kirim notifikasi jika ada ancaman baru.
		self::handle_threat_notifications( $unknown_folders );

		// Siapkan data hasil scan.
		$scan_results = array(
			'last_scan'       => current_time( 'mysql' ),
			'status'          => empty( $unknown_folders ) ? 'safe' : 'threat',
			'unknown_count'   => count( $unknown_folders ),
			'unknown_folders' => $unknown_folders,
		);

		// Simpan hasil scan ke WordPress Options.
		update_option( 'wp_root_guard_last_scan', $scan_results );
		update_option( 'wp_root_guard_unknown_folders', $unknown_folders );

		// Log status scan selesai.
		if ( empty( $unknown_folders ) ) {
			Logger::log(
				esc_html__( 'Pemindaian selesai', 'wp-root-guard' ),
				'-',
				esc_html__( 'Safe', 'wp-root-guard' )
			);
		} else {
			Logger::log(
				esc_html__( 'Pemindaian selesai dengan temuan ancaman', 'wp-root-guard' ),
				sprintf( /* translators: %d: jumlah folder */ esc_html__( '%d folder asing', 'wp-root-guard' ), count( $unknown_folders ) ),
				esc_html__( 'Threat Detected', 'wp-root-guard' )
			);
		}

		return $scan_results;
	}

	/**
	 * Melakukan karantina terhadap folder asing.
	 *
	 * @param string $folder Nama folder asing yang akan dikarantina.
	 * @return string|bool Nama folder karantina baru jika berhasil, false jika gagal.
	 */
	public static function quarantine_folder( $folder ) {
		$folder        = sanitize_text_field( $folder );
		$original_path = ABSPATH . $folder;

		if ( ! is_dir( $original_path ) ) {
			return false;
		}

		$quarantine_name = '__quarantine_' . $folder . '_' . time();
		$quarantine_path = ABSPATH . $quarantine_name;

		// Rename folder
		if ( @rename( $original_path, $quarantine_path ) ) {
			// Buat file .htaccess di dalam folder karantina untuk memblokir seluruh web access
			$htaccess_content  = "<Files *>\n";
			$htaccess_content .= "  <IfModule mod_authz_core.c>\n";
			$htaccess_content .= "    Require all denied\n";
			$htaccess_content .= "  </IfModule>\n";
			$htaccess_content .= "  <IfModule !mod_authz_core.c>\n";
			$htaccess_content .= "    Order deny,allow\n";
			$htaccess_content .= "    Deny from all\n";
			$htaccess_content .= "  </IfModule>\n";
			$htaccess_content .= "</Files>\n";

			@file_put_contents( $quarantine_path . '/.htaccess', $htaccess_content );

			// Simpan ke opsi daftar karantina
			$quarantines = get_option( 'wp_root_guard_quarantined_folders', array() );
			if ( ! is_array( $quarantines ) ) {
				$quarantines = array();
			}

			$quarantines[] = array(
				'original_name'   => $folder,
				'quarantine_name' => $quarantine_name,
				'original_path'   => $original_path,
				'quarantine_path' => $quarantine_path,
				'quarantine_time' => current_time( 'mysql' ),
			);

			update_option( 'wp_root_guard_quarantined_folders', $quarantines );

			// Log karantina
			Logger::log(
				esc_html__( 'Folder berhasil dikarantina otomatis', 'wp-root-guard' ),
				$folder,
				esc_html__( 'Quarantined', 'wp-root-guard' )
			);

			return $quarantine_name;
		}

		return false;
	}

	/**
	 * Mengembalikan folder yang dikarantina ke tempat semula.
	 *
	 * @param string $quarantine_name Nama folder karantina.
	 * @return bool True jika berhasil dikembalikan.
	 */
	public static function restore_quarantined_folder( $quarantine_name ) {
		$quarantine_name = sanitize_text_field( $quarantine_name );
		$quarantines     = get_option( 'wp_root_guard_quarantined_folders', array() );

		if ( ! is_array( $quarantines ) ) {
			return false;
		}

		$found_key = -1;
		foreach ( $quarantines as $key => $item ) {
			if ( $item['quarantine_name'] === $quarantine_name ) {
				$found_key = $key;
				break;
			}
		}

		if ( -1 === $found_key ) {
			return false;
		}

		$item            = $quarantines[ $found_key ];
		$quarantine_path = ABSPATH . $quarantine_name;
		$original_path   = ABSPATH . $item['original_name'];

		if ( ! is_dir( $quarantine_path ) ) {
			// Jika folder karantina sudah tidak ada, hapus saja dari database
			unset( $quarantines[ $found_key ] );
			update_option( 'wp_root_guard_quarantined_folders', array_values( $quarantines ) );
			return false;
		}

		// Hapus berkas .htaccess karantina jika ada
		if ( file_exists( $quarantine_path . '/.htaccess' ) ) {
			@unlink( $quarantine_path . '/.htaccess' );
		}

		// Rename kembali ke nama asli
		if ( @rename( $quarantine_path, $original_path ) ) {
			// Masukkan folder asli ini ke Whitelist Kustom secara otomatis agar tidak dikarantina kembali.
			Settings::add_to_whitelist( $item['original_name'] );

			// Hapus dari data karantina
			unset( $quarantines[ $found_key ] );
			update_option( 'wp_root_guard_quarantined_folders', array_values( $quarantines ) );

			Logger::log(
				esc_html__( 'Folder dikembalikan dari karantina', 'wp-root-guard' ),
				$item['original_name'],
				esc_html__( 'Restored', 'wp-root-guard' )
			);

			return true;
		}

		return false;
	}

	/**
	 * Menghapus folder karantina secara permanen dari server.
	 *
	 * @param string $quarantine_name Nama folder karantina.
	 * @return bool True jika berhasil dihapus.
	 */
	public static function delete_quarantined_folder_permanently( $quarantine_name ) {
		$quarantine_name = sanitize_text_field( $quarantine_name );
		$quarantines     = get_option( 'wp_root_guard_quarantined_folders', array() );

		if ( ! is_array( $quarantines ) ) {
			return false;
		}

		$found_key = -1;
		foreach ( $quarantines as $key => $item ) {
			if ( $item['quarantine_name'] === $quarantine_name ) {
				$found_key = $key;
				break;
			}
		}

		if ( -1 === $found_key ) {
			return false;
		}

		$item            = $quarantines[ $found_key ];
		$quarantine_path = ABSPATH . $quarantine_name;

		if ( is_dir( $quarantine_path ) ) {
			self::recursive_delete_dir( $quarantine_path );
		}

		// Hapus dari database
		unset( $quarantines[ $found_key ] );
		update_option( 'wp_root_guard_quarantined_folders', array_values( $quarantines ) );

		Logger::log(
			esc_html__( 'Folder karantina dihapus permanen', 'wp-root-guard' ),
			$item['original_name'],
			esc_html__( 'Deleted', 'wp-root-guard' )
		);

		return true;
	}

	/**
	 * Menghapus direktori secara rekursif.
	 *
	 * @param string $dir Path direktori.
	 * @return bool True jika berhasil.
	 */
	private static function recursive_delete_dir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return false;
		}
		$files = array_diff( scandir( $dir ), array( '.', '..' ) );
		foreach ( $files as $file ) {
			if ( is_dir( "$dir/$file" ) ) {
				self::recursive_delete_dir( "$dir/$file" );
			} else {
				@unlink( "$dir/$file" );
			}
		}
		return @rmdir( $dir );
	}

	/**
	 * Mengirim notifikasi Telegram ke Chat ID tertentu.
	 *
	 * @param string $token Token bot Telegram.
	 * @param string $chat_id Chat ID tujuan.
	 * @param string $message Isi pesan text.
	 * @return bool True jika berhasil terkirim.
	 */
	public static function send_telegram_message( $token, $chat_id, $message ) {
		if ( empty( $token ) || empty( $chat_id ) ) {
			return false;
		}

		$url  = "https://api.telegram.org/bot{$token}/sendMessage";
		$args = array(
			'body'    => array(
				'chat_id'                  => $chat_id,
				'text'                     => $message,
				'parse_mode'               => 'Markdown',
				'disable_web_page_preview' => true,
			),
			'timeout' => 10,
		);

		$response = wp_remote_post( $url, $args );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		return 200 === $code;
	}

	/**
	 * Mengirim notifikasi email dan Telegram jika ada ancaman baru yang belum dinotifikasi.
	 *
	 * @param array $unknown_folders Daftar folder asing saat ini.
	 */
	private static function handle_threat_notifications( $unknown_folders ) {
		$settings = Settings::get_settings();

		// Jika email maupun Telegram tidak diaktifkan, abaikan.
		if ( ! $settings['enable_email_notifications'] && ! $settings['enable_telegram_notifications'] ) {
			return;
		}

		if ( empty( $unknown_folders ) ) {
			// Jika sudah aman (tidak ada ancaman aktif), bersihkan daftar notifikasi
			delete_option( 'wp_root_guard_notified_threats' );
			return;
		}

		$notified = get_option( 'wp_root_guard_notified_threats', array() );
		if ( ! is_array( $notified ) ) {
			$notified = array();
		}

		$new_threats = array();
		foreach ( $unknown_folders as $folder ) {
			if ( ! in_array( $folder['name'], $notified, true ) ) {
				$new_threats[] = $folder;
				$notified[]    = $folder['name'];
			}
		}

		// Jika tidak ada ancaman baru yang belum dinotifikasi, keluar.
		if ( empty( $new_threats ) ) {
			return;
		}

		// Update daftar yang sudah dinotifikasi
		update_option( 'wp_root_guard_notified_threats', $notified );

		$site_name = get_bloginfo( 'name' );
		$site_url  = home_url();
		$count     = count( $new_threats );

		// 1. Kirim Email jika aktif
		if ( $settings['enable_email_notifications'] && ! empty( $settings['admin_email'] ) ) {
			$subject = sprintf( /* translators: %s: nama situs */ esc_html__( '[WP Root Guard] Ancaman Terdeteksi di %s', 'wp-root-guard' ), $site_name );

			$email_body  = esc_html__( 'Halo Administrator,', 'wp-root-guard' ) . "\r\n\r\n";
			$email_body .= sprintf( /* translators: %1$d: jumlah folder, %2$s: URL situs */ esc_html__( 'WP Root Guard mendeteksi %1$d folder asing baru pada root directory situs Anda (%2$s):', 'wp-root-guard' ), $count, $site_url ) . "\r\n\r\n";

			foreach ( $new_threats as $threat ) {
				$status_label = ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) === $threat['status'] ) ? esc_html__( 'Dikharantina Otomatis', 'wp-root-guard' ) : esc_html__( 'Belum Dikarantina', 'wp-root-guard' );
				
				$email_body .= "- " . sprintf( /* translators: %1$s: nama folder, %2$s: path */ esc_html__( 'Folder: %1$s (Path: %2$s)', 'wp-root-guard' ), $threat['name'], $threat['path'] ) . "\r\n";
				$email_body .= "  " . sprintf( /* translators: %s: status karantina */ esc_html__( 'Status: %s', 'wp-root-guard' ), $status_label ) . "\r\n";
				$email_body .= "  " . sprintf( /* translators: %s: waktu */ esc_html__( 'Waktu Terdeteksi: %s', 'wp-root-guard' ), $threat['detection_time'] ) . "\r\n\r\n";
			}

			$email_body .= esc_html__( 'Silakan segera masuk ke dasbor WordPress Anda untuk meninjau ancaman tersebut.', 'wp-root-guard' ) . "\r\n";
			$email_body .= admin_url( 'index.php?page=wp-root-guard' ) . "\r\n\r\n";
			$email_body .= esc_html__( 'Pesan ini dikirim secara otomatis oleh WP Root Guard.', 'wp-root-guard' );

			wp_mail( $settings['admin_email'], $subject, $email_body );
		}

		// 2. Kirim Telegram jika aktif
		if ( $settings['enable_telegram_notifications'] && ! empty( $settings['telegram_bot_token'] ) && ! empty( $settings['telegram_chat_id'] ) ) {
			$tg_msg  = "⚠️ *[WP Root Guard] Ancaman Terdeteksi!*\n\n";
			$tg_msg .= "Situs: *{$site_name}* ({$site_url})\n";
			$tg_msg .= "Ditemukan *{$count}* folder asing baru:\n\n";

			foreach ( $new_threats as $threat ) {
				$status_label = ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) === $threat['status'] ) ? "🔒 _Sudah Dikarantina Otomatis_" : "⚠️ *Belum Dikarantina*";
				
				$tg_msg .= "📂 *Folder*: `{$threat['name']}`\n";
				$tg_msg .= "📍 *Path*: `{$threat['path']}`\n";
				$tg_msg .= "🛡️ *Status*: {$status_label}\n";
				$tg_msg .= "⏱️ *Waktu*: {$threat['detection_time']}\n\n";
			}

			$tg_msg .= "🔗 [Buka Dashboard Root Guard](" . admin_url( 'index.php?page=wp-root-guard' ) . ")";

			self::send_telegram_message( $settings['telegram_bot_token'], $settings['telegram_chat_id'], $tg_msg );
		}
	}

	/**
	 * Mengambil data pemindaian terakhir.
	 *
	 * @return array Hasil pemindaian terakhir.
	 */
	public static function get_last_scan_results() {
		$default = array(
			'last_scan'       => '',
			'status'          => 'safe',
			'unknown_count'   => 0,
			'unknown_folders' => array(),
		);

		$results = get_option( 'wp_root_guard_last_scan', $default );
		return is_array( $results ) ? $results : $default;
	}

	/**
	 * Mengambil daftar folder asing yang saat ini terdeteksi.
	 *
	 * @return array Daftar folder asing.
	 */
	public static function get_unknown_folders() {
		$folders = get_option( 'wp_root_guard_unknown_folders', array() );
		return is_array( $folders ) ? $folders : array();
	}
}
