<?php
/**
 * Memindai direktori root WordPress dan mencari folder serta berkas mencurigakan/asing/dimodifikasi.
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
 * berkas asing, modifikasi berkas inti, menangani karantina otomatis, dan mengirimkan notifikasi.
 */
class Scanner {

	/**
	 * Melakukan pemindaian root directory secara menyeluruh (folder dan berkas).
	 *
	 * @return array Hasil pemindaian berupa status proteksi dan daftar ancaman terdeteksi.
	 */
	public static function perform_scan() {
		// 1. Dapatkan folder & berkas saat ini di root.
		$current_folders = Baseline::scan_root_folders();
		$current_files   = Baseline::scan_root_files();

		// 2. Ambil baseline & whitelist.
		$baseline_folders = Baseline::get_baseline_folders();
		$baseline_files   = Baseline::get_baseline_files();

		$default_folders  = Settings::get_default_whitelist();
		$default_files    = Settings::get_default_file_whitelist();

		$user_whitelist   = Settings::get_user_whitelist();
		$settings         = Settings::get_settings();

		// Gabungkan whitelist dan baseline untuk pengecekan.
		$known_folders    = array_unique( array_merge( $baseline_folders, $default_folders, $user_whitelist ) );
		$known_files      = array_unique( array_merge( array_keys( $baseline_files ), $default_files, $user_whitelist ) );

		$threats          = array();

		// ==========================================
		// A. PEMINDAIAN FOLDER
		// ==========================================
		foreach ( $current_folders as $folder ) {
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
					Logger::log(
						esc_html__( 'Folder asing terdeteksi', 'wp-root-guard' ),
						$folder,
						esc_html__( 'Unknown', 'wp-root-guard' )
					);
				}

				$threats[] = array(
					'type'              => 'folder',
					'name'              => $folder,
					'path'              => $full_path,
					'created_time'      => $created_time,
					'detection_time'    => $detection_time,
					'status'            => $status_text,
					'malware_indicator' => '-',
				);
			}
		}

		// ==========================================
		// B. PEMINDAIAN BERKAS (FILES)
		// ==========================================
		foreach ( $current_files as $file => $current_hash ) {
			$file_path = ABSPATH . $file;

			// Pengecekan 1: Berkas Asing (Tidak dikenal)
			if ( ! in_array( $file, $known_files, true ) ) {
				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $file_path ) ) {
					$ctime = filectime( $file_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$detection_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), current_time( 'timestamp' ) );
				$status_text    = esc_html__( 'Unknown File', 'wp-root-guard' );

				// Pindai tanda tangan malware (webshell)
				$malware_indicator = self::scan_file_for_webshell( $file_path );
				$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Bersih (Bukan Webshell)', 'wp-root-guard' );

				// Jalankan karantina otomatis jika aktif
				if ( $settings['enable_auto_quarantine'] ) {
					$quarantine_name = self::quarantine_file( $file );
					if ( false !== $quarantine_name ) {
						$status_text = esc_html__( 'Quarantined Automatically', 'wp-root-guard' );
						$file_path   = ABSPATH . $quarantine_name;
					}
				} else {
					Logger::log(
						$malware_indicator ? esc_html__( 'Berkas berbahaya terdeteksi', 'wp-root-guard' ) : esc_html__( 'Berkas asing terdeteksi', 'wp-root-guard' ),
						$file,
						$malware_indicator ? esc_html__( 'Malware Suspicious', 'wp-root-guard' ) : esc_html__( 'Unknown', 'wp-root-guard' )
					);
				}

				$threats[] = array(
					'type'              => 'file',
					'name'              => $file,
					'path'              => $file_path,
					'created_time'      => $created_time,
					'detection_time'    => $detection_time,
					'status'            => $status_text,
					'malware_indicator' => $malware_label,
				);

			// Pengecekan 2: Berkas Terdaftar tapi MD5 Hash Berbeda (Dimodifikasi / Diinjeksi)
			} elseif ( isset( $baseline_files[ $file ] ) && $baseline_files[ $file ] !== $current_hash ) {
				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $file_path ) ) {
					$ctime = filectime( $file_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$detection_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), current_time( 'timestamp' ) );
				$status_text    = esc_html__( 'Modified File', 'wp-root-guard' );

				// Pindai tanda tangan webshell
				$malware_indicator = self::scan_file_for_webshell( $file_path );
				$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Perubahan Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Integritas Berkas Berubah', 'wp-root-guard' );

				// Catatan: Untuk berkas inti yang dimodifikasi, kita JANGAN karantina agar website tidak rusak/mati.
				Logger::log(
					esc_html__( 'Integritas berkas berubah (Modifikasi)', 'wp-root-guard' ),
					$file,
					$malware_indicator ? esc_html__( 'Malware Suspicious', 'wp-root-guard' ) : esc_html__( 'Modified', 'wp-root-guard' )
				);

				$threats[] = array(
					'type'              => 'file',
					'name'              => $file,
					'path'              => $file_path,
					'created_time'      => $created_time,
					'detection_time'    => $detection_time,
					'status'            => $status_text,
					'malware_indicator' => $malware_label,
				);
			}
		}

		// Kirim notifikasi jika ada ancaman baru yang belum pernah dilaporkan.
		self::handle_threat_notifications( $threats );

		// Siapkan data hasil scan.
		$scan_results = array(
			'last_scan'       => current_time( 'mysql' ),
			'status'          => empty( $threats ) ? 'safe' : 'threat',
			'unknown_count'   => count( $threats ),
			'unknown_folders' => $threats, // Kita tetap gunakan nama index 'unknown_folders' untuk kompatibilitas dashboard/widget
		);

		// Simpan hasil scan ke WordPress Options.
		update_option( 'wp_root_guard_last_scan', $scan_results );
		update_option( 'wp_root_guard_unknown_folders', $threats );

		// Log status scan selesai.
		if ( empty( $threats ) ) {
			Logger::log(
				esc_html__( 'Pemindaian selesai', 'wp-root-guard' ),
				'-',
				esc_html__( 'Safe', 'wp-root-guard' )
			);
		} else {
			Logger::log(
				esc_html__( 'Pemindaian selesai dengan temuan ancaman', 'wp-root-guard' ),
				sprintf( /* translators: %d: jumlah temuan */ esc_html__( '%d berkas/folder asing', 'wp-root-guard' ), count( $threats ) ),
				esc_html__( 'Threat Detected', 'wp-root-guard' )
			);
		}

		return $scan_results;
	}

	/**
	 * Memindai konten berkas PHP untuk mencari fungsi webshell mencurigakan.
	 *
	 * @param string $file_path Path absolut berkas.
	 * @return string|bool String berisi indikator malware jika ditemukan, false jika bersih.
	 */
	public static function scan_file_for_webshell( $file_path ) {
		if ( ! file_exists( $file_path ) || is_dir( $file_path ) ) {
			return false;
		}

		// Hanya pindai berkas PHP atau berkas teks lainnya (seperti .htaccess)
		$ext = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
		if ( ! in_array( $ext, array( 'php', 'htaccess', 'html', 'txt' ), true ) ) {
			return false;
		}

		// Batasi pembacaan ukuran berkas maksimal 1MB agar cepat
		if ( filesize( $file_path ) > 1024 * 1024 ) {
			return false;
		}

		$content = @file_get_contents( $file_path );
		if ( empty( $content ) ) {
			return false;
		}

		$suspicious_patterns = array(
			'eval\('                   => 'eval()',
			'base64_decode\('          => 'base64_decode()',
			'shell_exec\('             => 'shell_exec()',
			'passthru\('               => 'passthru()',
			'system\('                 => 'system()',
			'gzuncompress\('           => 'gzuncompress()',
			'gzinflate\('              => 'gzinflate()',
			'str_rot13\('              => 'str_rot13()',
			'\$_POST\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\(' => 'Dynamic function execution via $_POST',
			'\$_GET\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\('  => 'Dynamic function execution via $_GET',
			'assert\('                 => 'assert()',
		);

		$found = array();
		foreach ( $suspicious_patterns as $pattern => $label ) {
			if ( preg_match( '/' . $pattern . '/i', $content ) ) {
				$found[] = $label;
			}
		}

		if ( ! empty( $found ) ) {
			return implode( ', ', $found );
		}

		return false;
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
				'type'            => 'folder',
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
	 * Melakukan karantina terhadap berkas asing.
	 *
	 * @param string $filename Nama berkas asing yang akan dikarantina.
	 * @return string|bool Nama berkas karantina baru jika berhasil, false jika gagal.
	 */
	public static function quarantine_file( $filename ) {
		$filename      = sanitize_text_field( $filename );
		$original_path = ABSPATH . $filename;

		if ( ! file_exists( $original_path ) || is_dir( $original_path ) ) {
			return false;
		}

		$quarantine_name = '__quarantine_' . $filename . '_' . time();
		$quarantine_path = ABSPATH . $quarantine_name;

		// Pindahkan berkas
		if ( @rename( $original_path, $quarantine_path ) ) {
			// Simpan ke opsi daftar karantina
			$quarantines = get_option( 'wp_root_guard_quarantined_folders', array() );
			if ( ! is_array( $quarantines ) ) {
				$quarantines = array();
			}

			$quarantines[] = array(
				'type'            => 'file',
				'original_name'   => $filename,
				'quarantine_name' => $quarantine_name,
				'original_path'   => $original_path,
				'quarantine_path' => $quarantine_path,
				'quarantine_time' => current_time( 'mysql' ),
			);

			update_option( 'wp_root_guard_quarantined_folders', $quarantines );

			// Log karantina
			Logger::log(
				esc_html__( 'Berkas berhasil dikarantina otomatis', 'wp-root-guard' ),
				$filename,
				esc_html__( 'Quarantined', 'wp-root-guard' )
			);

			return $quarantine_name;
		}

		return false;
	}

	/**
	 * Mengembalikan folder/berkas yang dikarantina ke tempat semula.
	 *
	 * @param string $quarantine_name Nama folder/berkas karantina.
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
		$type            = isset( $item['type'] ) ? $item['type'] : 'folder';

		if ( 'folder' === $type ) {
			if ( ! is_dir( $quarantine_path ) ) {
				unset( $quarantines[ $found_key ] );
				update_option( 'wp_root_guard_quarantined_folders', array_values( $quarantines ) );
				return false;
			}
			if ( file_exists( $quarantine_path . '/.htaccess' ) ) {
				@unlink( $quarantine_path . '/.htaccess' );
			}
		} else {
			if ( ! file_exists( $quarantine_path ) ) {
				unset( $quarantines[ $found_key ] );
				update_option( 'wp_root_guard_quarantined_folders', array_values( $quarantines ) );
				return false;
			}
		}

		// Rename kembali ke nama asli
		if ( @rename( $quarantine_path, $original_path ) ) {
			// Masukkan kembali ke Whitelist Kustom secara otomatis
			Settings::add_to_whitelist( $item['original_name'] );

			// Hapus dari data karantina
			unset( $quarantines[ $found_key ] );
			update_option( 'wp_root_guard_quarantined_folders', array_values( $quarantines ) );

			Logger::log(
				( 'folder' === $type ) ? esc_html__( 'Folder dikembalikan dari karantina', 'wp-root-guard' ) : esc_html__( 'Berkas dikembalikan dari karantina', 'wp-root-guard' ),
				$item['original_name'],
				esc_html__( 'Restored', 'wp-root-guard' )
			);

			return true;
		}

		return false;
	}

	/**
	 * Menghapus folder/berkas karantina secara permanen dari server.
	 *
	 * @param string $quarantine_name Nama folder/berkas karantina.
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
		$type            = isset( $item['type'] ) ? $item['type'] : 'folder';

		if ( 'folder' === $type ) {
			if ( is_dir( $quarantine_path ) ) {
				self::recursive_delete_dir( $quarantine_path );
			}
		} else {
			if ( file_exists( $quarantine_path ) ) {
				@unlink( $quarantine_path );
			}
		}

		// Hapus dari database
		unset( $quarantines[ $found_key ] );
		update_option( 'wp_root_guard_quarantined_folders', array_values( $quarantines ) );

		Logger::log(
			( 'folder' === $type ) ? esc_html__( 'Folder karantina dihapus permanen', 'wp-root-guard' ) : esc_html__( 'Berkas karantina dihapus permanen', 'wp-root-guard' ),
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
	 * @param array $threats Daftar ancaman terdeteksi saat ini.
	 */
	private static function handle_threat_notifications( $threats ) {
		$settings = Settings::get_settings();

		// Jika email maupun Telegram tidak diaktifkan, abaikan.
		if ( ! $settings['enable_email_notifications'] && ! $settings['enable_telegram_notifications'] ) {
			return;
		}

		if ( empty( $threats ) ) {
			// Jika sudah aman (tidak ada ancaman aktif), bersihkan daftar notifikasi
			delete_option( 'wp_root_guard_notified_threats' );
			return;
		}

		$notified = get_option( 'wp_root_guard_notified_threats', array() );
		if ( ! is_array( $notified ) ) {
			$notified = array();
		}

		$new_threats = array();
		foreach ( $threats as $threat ) {
			// Kita bedakan dengan type:name
			$threat_key = $threat['type'] . ':' . $threat['name'];
			if ( ! in_array( $threat_key, $notified, true ) ) {
				$new_threats[] = $threat;
				$notified[]    = $threat_key;
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
			$subject = sprintf( /* translators: %s: nama situs */ esc_html__( '[WP Root Guard] Ancaman Keamanan Baru di %s', 'wp-root-guard' ), $site_name );

			$email_body  = esc_html__( 'Halo Administrator,', 'wp-root-guard' ) . "\r\n\r\n";
			$email_body .= sprintf( /* translators: %1$d: jumlah temuan, %2$s: URL situs */ esc_html__( 'WP Root Guard mendeteksi %1$d berkas/folder asing atau dimodifikasi baru pada root directory situs Anda (%2$s):', 'wp-root-guard' ), $count, $site_url ) . "\r\n\r\n";

			foreach ( $new_threats as $threat ) {
				$type_label   = ( 'folder' === $threat['type'] ) ? esc_html__( 'Folder Asing', 'wp-root-guard' ) : esc_html__( 'Berkas', 'wp-root-guard' );
				$status_label = ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) === $threat['status'] ) ? esc_html__( 'Sudah Dikarantina Otomatis', 'wp-root-guard' ) : esc_html__( 'Belum Dikarantina', 'wp-root-guard' );
				
				$email_body .= "- " . sprintf( /* translators: %1$s: tipe, %2$s: nama */ esc_html__( '%1$s: %2$s', 'wp-root-guard' ), $type_label, $threat['name'] ) . "\r\n";
				$email_body .= "  " . sprintf( /* translators: %s: path */ esc_html__( 'Path: %s', 'wp-root-guard' ), $threat['path'] ) . "\r\n";
				$email_body .= "  " . sprintf( /* translators: %s: status */ esc_html__( 'Status: %s', 'wp-root-guard' ), $status_label ) . "\r\n";
				if ( '-' !== $threat['malware_indicator'] ) {
					$email_body .= "  " . sprintf( /* translators: %s: indikasi */ esc_html__( 'Indikasi: %s', 'wp-root-guard' ), $threat['malware_indicator'] ) . "\r\n";
				}
				$email_body .= "  " . sprintf( /* translators: %s: waktu */ esc_html__( 'Waktu Terdeteksi: %s', 'wp-root-guard' ), $threat['detection_time'] ) . "\r\n\r\n";
			}

			$email_body .= esc_html__( 'Silakan segera masuk ke dasbor WordPress Anda untuk mengambil tindakan.', 'wp-root-guard' ) . "\r\n";
			$email_body .= admin_url( 'index.php?page=wp-root-guard' ) . "\r\n\r\n";
			$email_body .= esc_html__( 'Pesan ini dikirim secara otomatis oleh WP Root Guard.', 'wp-root-guard' );

			wp_mail( $settings['admin_email'], $subject, $email_body );
		}

		// 2. Kirim Telegram jika aktif
		if ( $settings['enable_telegram_notifications'] && ! empty( $settings['telegram_bot_token'] ) && ! empty( $settings['telegram_chat_id'] ) ) {
			$tg_msg  = "⚠️ *[WP Root Guard] Ancaman Baru Terdeteksi!*\n\n";
			$tg_msg .= "Situs: *{$site_name}* ({$site_url})\n";
			$tg_msg .= "Ditemukan *{$count}* berkas/folder baru/dimodifikasi:\n\n";

			foreach ( $new_threats as $threat ) {
				$type_icon    = ( 'folder' === $threat['type'] ) ? "📂" : "📄";
				$status_label = ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) === $threat['status'] ) ? "🔒 _Sudah Dikarantina_" : "⚠️ *Belum Dikarantina*";
				
				$tg_msg .= "{$type_icon} *Nama*: `{$threat['name']}`\n";
				$tg_msg .= "📍 *Path*: `{$threat['path']}`\n";
				$tg_msg .= "🛡️ *Status*: {$status_label}\n";
				if ( '-' !== $threat['malware_indicator'] ) {
					$tg_msg .= "💀 *Indikasi*: `{$threat['malware_indicator']}`\n";
				}
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
	 * Mengambil daftar folder/berkas asing yang saat ini terdeteksi.
	 *
	 * @return array Daftar folder/berkas asing.
	 */
	public static function get_unknown_folders() {
		$folders = get_option( 'wp_root_guard_unknown_folders', array() );
		return is_array( $folders ) ? $folders : array();
	}
}
