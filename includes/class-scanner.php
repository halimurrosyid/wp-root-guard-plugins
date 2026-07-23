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
	 * Melakukan pemindaian root directory secara menyeluruh (folder, berkas root, dan integritas core).
	 *
	 * @return array Hasil pemindaian berupa status proteksi dan daftar ancaman terdeteksi.
	 */
	public static function perform_scan() {
		$detection_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), current_time( 'timestamp' ) );

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

				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $full_path ) ) {
					$ctime = filectime( $full_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$status_text    = esc_html__( 'Unknown Folder', 'wp-root-guard' );

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
		// B. PEMINDAIAN BERKAS (FILES) DI ROOT
		// ==========================================
		foreach ( $current_files as $file => $current_hash ) {
			$file_path = ABSPATH . $file;

			// Pengecekan: Berkas Asing di root (bukan bagian dari whitelist/baseline)
			if ( ! in_array( $file, $known_files, true ) ) {
				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $file_path ) ) {
					$ctime = filectime( $file_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$status_text    = esc_html__( 'Unknown File', 'wp-root-guard' );

				$malware_indicator = self::scan_file_for_webshell( $file_path );
				$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Bersih (Bukan Webshell)', 'wp-root-guard' );

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

			// Pengecekan: Berkas Terdaftar di baseline root tapi MD5 Hash Berbeda (Dimodifikasi)
			} elseif ( isset( $baseline_files[ $file ] ) && $baseline_files[ $file ] !== $current_hash ) {
				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $file_path ) ) {
					$ctime = filectime( $file_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$status_text    = esc_html__( 'Modified File', 'wp-root-guard' );
				$malware_indicator = self::scan_file_for_webshell( $file_path );
				$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Perubahan Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Integritas Berkas Berubah', 'wp-root-guard' );

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

		// ==========================================
		// C. PEMINDAIAN BERKAS CORE (INTEGRITY CHECK)
		// ==========================================
		$checksums = self::get_core_checksums();
		if ( is_array( $checksums ) && ! empty( $checksums ) ) {
			foreach ( $checksums as $relative_path => $expected_hash ) {
				$full_path = ABSPATH . $relative_path;

				// Hanya pindai berkas di wp-admin, wp-includes, dan berkas inti root (abaikan wp-content)
				if ( 0 === strpos( $relative_path, 'wp-content/' ) ) {
					continue;
				}

				// 1. Cek jika Berkas Hilang (Missing Core File)
				if ( ! file_exists( $full_path ) ) {
					$threats[] = array(
						'type'              => 'core_file',
						'name'              => $relative_path,
						'path'              => $full_path,
						'created_time'      => '-',
						'detection_time'    => $detection_time,
						'status'            => 'Missing Core File',
						'malware_indicator' => esc_html__( 'Berkas Inti Hilang', 'wp-root-guard' ),
					);

					Logger::log(
						esc_html__( 'Berkas inti WordPress hilang', 'wp-root-guard' ),
						$relative_path,
						esc_html__( 'Missing', 'wp-root-guard' )
					);

				// 2. Cek jika Berkas Modifikasi (Modified Core File)
				} else {
					$current_hash = md5_file( $full_path );
					if ( $current_hash !== $expected_hash ) {
						
						// Lewati jika berkas ini adalah berkas pengaturan pengguna yang wajar (seperti wp-config.php tidak masuk checksum, tapi just in case)
						if ( 'wp-config.php' === $relative_path ) {
							continue;
						}

						$malware_indicator = self::scan_file_for_webshell( $full_path );
						$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Perubahan Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Integritas Berkas Berubah', 'wp-root-guard' );

						$threats[] = array(
							'type'              => 'core_file',
							'name'              => $relative_path,
							'path'              => $full_path,
							'created_time'      => '-',
							'detection_time'    => $detection_time,
							'status'            => 'Modified Core File',
							'malware_indicator' => $malware_label,
						);

						Logger::log(
							esc_html__( 'Integritas berkas inti berubah (Modifikasi)', 'wp-root-guard' ),
							$relative_path,
							$malware_indicator ? esc_html__( 'Malware Suspicious', 'wp-root-guard' ) : esc_html__( 'Modified', 'wp-root-guard' )
						);
					}
				}
			}

			// 3. Deteksi File Penyusup (Injected Files) di wp-admin/ & wp-includes/
			$core_dirs = array( 'wp-admin', 'wp-includes' );
			foreach ( $core_dirs as $dir ) {
				$dir_path = ABSPATH . $dir;
				if ( is_dir( $dir_path ) ) {
					try {
						$directory = new \RecursiveDirectoryIterator( $dir_path );
						$iterator  = new \RecursiveIteratorIterator( $directory );
						foreach ( $iterator as $fileinfo ) {
							if ( $fileinfo->isFile() ) {
								$pathname = $fileinfo->getPathname();
								$rel_path = str_replace( ABSPATH, '', $pathname );
								$rel_path = str_replace( '\\', '/', $rel_path ); // Standardisasi Windows path

								// Jika berkas tidak terdaftar di daftar core resmi WordPress.org
								if ( ! isset( $checksums[ $rel_path ] ) ) {
									// Lewati berkas penanda karantina kita sendiri jika ada
									if ( 0 === strpos( basename( $pathname ), '__quarantine_' ) ) {
										continue;
									}

									$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
									$ctime = $fileinfo->getCTime();
									if ( false !== $ctime ) {
										$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
									}

									$status_text    = esc_html__( 'Suspicious Core Injection', 'wp-root-guard' );
									$malware_indicator = self::scan_file_for_webshell( $pathname );
									$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Penyusupan Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Berkas Penyusup di Folder Core', 'wp-root-guard' );

									// Karantina otomatis untuk berkas penyusup asing di folder core
									if ( $settings['enable_auto_quarantine'] ) {
										$quarantine_name = self::quarantine_core_file( $rel_path );
										if ( false !== $quarantine_name ) {
											$status_text = esc_html__( 'Quarantined Automatically', 'wp-root-guard' );
											$pathname    = ABSPATH . $quarantine_name;
										}
									} else {
										Logger::log(
											esc_html__( 'Penyusupan berkas core terdeteksi', 'wp-root-guard' ),
											$rel_path,
											$malware_indicator ? esc_html__( 'Malware Suspicious', 'wp-root-guard' ) : esc_html__( 'Unknown', 'wp-root-guard' )
										);
									}

									$threats[] = array(
										'type'              => 'core_file',
										'name'              => $rel_path,
										'path'              => $pathname,
										'created_time'      => $created_time,
										'detection_time'    => $detection_time,
										'status'            => $status_text,
										'malware_indicator' => $malware_label,
									);
								}
							}
						}
					} catch ( \Exception $e ) {
						// Abaikan error iterator
					}
				}
			}
		}

		// ==========================================
		// D. PEMINDAIAN BERKAS PHP DI FOLDER UPLOADS (wp-content/uploads)
		// ==========================================
		if ( ! isset( $settings['enable_uploads_php_scan'] ) || $settings['enable_uploads_php_scan'] ) {
			$uploads_php = self::scan_uploads_for_php_files();
			foreach ( $uploads_php as $php_file ) {
				$rel_path  = $php_file['name'];
				$file_path = $php_file['path'];

				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $file_path ) ) {
					$ctime = filectime( $file_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$status_text       = esc_html__( 'PHP File in Uploads', 'wp-root-guard' );
				$malware_indicator = self::scan_file_for_webshell( $file_path );
				$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Sangat Berbahaya (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Berkas PHP di Folder Uploads', 'wp-root-guard' );

				if ( $settings['enable_auto_quarantine'] ) {
					$quarantine_name = self::quarantine_core_file( $rel_path );
					if ( false !== $quarantine_name ) {
						$status_text = esc_html__( 'Quarantined Automatically', 'wp-root-guard' );
						$file_path   = ABSPATH . $quarantine_name;
					}
				} else {
					Logger::log(
						esc_html__( 'Berkas PHP terdeteksi di folder uploads', 'wp-root-guard' ),
						$rel_path,
						$malware_indicator ? esc_html__( 'Malware Suspicious', 'wp-root-guard' ) : esc_html__( 'Uploads PHP Threat', 'wp-root-guard' )
					);
				}

				$threats[] = array(
					'type'              => 'uploads_php',
					'name'              => $rel_path,
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
			'unknown_folders' => $threats,
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
	 * Mengambil daftar checksums resmi dari WordPress.org API.
	 *
	 * @return array|bool Array checksums resmi (relative_path => expected_md5) atau false jika gagal.
	 */
	public static function get_core_checksums() {
		global $wp_version;
		$locale        = get_locale();
		$transient_key = 'wp_root_guard_core_checksums';
		$cached        = get_transient( $transient_key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		$url      = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || empty( $data['checksums'] ) ) {
			return false;
		}

		// Simpan di cache transient selama 24 jam
		set_transient( $transient_key, $data['checksums'], DAY_IN_SECONDS );

		return $data['checksums'];
	}

	/**
	 * Mengembalikan berkas core WordPress ke keadaan asli dari SVN WordPress.org.
	 *
	 * @param string $relative_path Path relatif berkas terhadap ABSPATH (contoh: wp-login.php).
	 * @return bool True jika berhasil memulihkan berkas core.
	 */
	public static function restore_core_file( $relative_path ) {
		$relative_path = sanitize_text_field( $relative_path );
		global $wp_version;

		$url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}";
		$response = wp_remote_get( $url, array( 'timeout' => 20 ) );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return false;
		}

		$content = wp_remote_retrieve_body( $response );
		if ( empty( $content ) ) {
			return false;
		}

		$local_path = ABSPATH . $relative_path;
		
		// Pastikan folder penampung sudah ada
		$dir = dirname( $local_path );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		// Timpa berkas lokal dengan berkas core resmi
		if ( false !== @file_put_contents( $local_path, $content ) ) {
			Logger::log(
				esc_html__( 'Berkas core WordPress dipulihkan ke asli', 'wp-root-guard' ),
				$relative_path,
				esc_html__( 'Restored', 'wp-root-guard' )
			);
			return true;
		}

		return false;
	}

	/**
	 * Membandingkan kode berkas lokal dengan berkas asli resmi dan mengembalikan perbedaannya.
	 *
	 * @param string $relative_path Path relatif berkas core.
	 * @return array Hasil komparasi perbedaan baris kode.
	 */
	public static function get_file_diff( $relative_path ) {
		$relative_path = sanitize_text_field( $relative_path );
		$local_path    = ABSPATH . $relative_path;

		if ( ! file_exists( $local_path ) ) {
			return array( 'error' => esc_html__( 'Berkas lokal tidak ditemukan.', 'wp-root-guard' ) );
		}

		global $wp_version;
		$url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}";
		
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return array( 'error' => esc_html__( 'Gagal mengunduh versi asli berkas dari WordPress.org.', 'wp-root-guard' ) );
		}

		$original_content = wp_remote_retrieve_body( $response );
		$local_content    = @file_get_contents( $local_path );

		$original_lines = explode( "\n", str_replace( "\r", "", $original_content ) );
		$local_lines    = explode( "\n", str_replace( "\r", "", $local_content ) );

		$diff = array();
		$max  = max( count( $original_lines ), count( $local_lines ) );
		
		for ( $i = 0; $i < $max; $i++ ) {
			$orig_line = isset( $original_lines[$i] ) ? $original_lines[$i] : null;
			$loc_line  = isset( $local_lines[$i] ) ? $local_lines[$i] : null;

			if ( $orig_line !== $loc_line ) {
				$line_number = $i + 1;
				$diff[] = array(
					'line'     => $line_number,
					'original' => $orig_line,
					'local'    => $loc_line,
				);
			}
		}

		return $diff;
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

		$ext = strtolower( pathinfo( $file_path, PATHINFO_EXTENSION ) );
		if ( ! in_array( $ext, array( 'php', 'htaccess', 'html', 'txt' ), true ) ) {
			return false;
		}

		if ( filesize( $file_path ) > 1024 * 1024 ) {
			return false;
		}

		$content = @file_get_contents( $file_path );
		if ( empty( $content ) ) {
			return false;
		}

		$suspicious_patterns = array(
			'eval\('                         => 'eval()',
			'base64_decode\('                => 'base64_decode()',
			'shell_exec\('                   => 'shell_exec()',
			'passthru\('                     => 'passthru()',
			'system\('                       => 'system()',
			'exec\('                         => 'exec()',
			'popen\('                        => 'popen()',
			'proc_open\('                    => 'proc_open()',
			'pcntl_exec\('                   => 'pcntl_exec()',
			'gzuncompress\('                 => 'gzuncompress()',
			'gzinflate\('                    => 'gzinflate()',
			'str_rot13\('                    => 'str_rot13()',
			'convert_uudecode\('             => 'convert_uudecode()',
			'create_function\('              => 'create_function()',
			'call_user_func\('               => 'call_user_func()',
			'assert\('                       => 'assert()',
			'\$_POST\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\(' => 'Dynamic $_POST call',
			'\$_GET\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\('  => 'Dynamic $_GET call',
			'c99shell'                       => 'C99 Webshell',
			'r57shell'                       => 'R57 Webshell',
			'b374k'                          => 'b374k Webshell',
			'wso_version'                    => 'WSO Webshell',
			'marvins'                        => 'Marvins Webshell',
			'alfa_data'                      => 'ALFA Webshell',
		);

		$found = array();
		foreach ( $suspicious_patterns as $pattern => $label ) {
			if ( preg_match( '/' . $pattern . '/i', $content ) ) {
				$found[] = $label;
			}
		}

		if ( ! empty( $found ) ) {
			return implode( ', ', array_unique( $found ) );
		}

		return false;
	}

	/**
	 * Membaca isi berkas secara aman dan menganalisis setiap baris untuk tanda tangan bahaya.
	 *
	 * @param string $rel_path Path relatif berkas.
	 * @return array Data analisis baris berkas.
	 */
	public static function inspect_file_content( $rel_path ) {
		$rel_path = sanitize_text_field( $rel_path );
		$abs_path = str_replace( '\\', '/', ABSPATH . $rel_path );

		if ( false !== strpos( $rel_path, '..' ) || ! file_exists( $abs_path ) || is_dir( $abs_path ) ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Berkas tidak ditemukan atau path tidak valid.', 'wp-root-guard' ),
			);
		}

		if ( filesize( $abs_path ) > 2 * 1024 * 1024 ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Berkas terlalu besar untuk diinspeksi di browser (> 2MB).', 'wp-root-guard' ),
			);
		}

		$content = @file_get_contents( $abs_path );
		if ( false === $content ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Gagal membaca isi berkas dari server.', 'wp-root-guard' ),
			);
		}

		$patterns = array(
			'eval\('                         => 'eval()',
			'base64_decode\('                => 'base64_decode()',
			'shell_exec\('                   => 'shell_exec()',
			'passthru\('                     => 'passthru()',
			'system\('                       => 'system()',
			'exec\('                         => 'exec()',
			'popen\('                        => 'popen()',
			'proc_open\('                    => 'proc_open()',
			'pcntl_exec\('                   => 'pcntl_exec()',
			'gzuncompress\('                 => 'gzuncompress()',
			'gzinflate\('                    => 'gzinflate()',
			'str_rot13\('                    => 'str_rot13()',
			'convert_uudecode\('             => 'convert_uudecode()',
			'create_function\('              => 'create_function()',
			'call_user_func\('               => 'call_user_func()',
			'assert\('                       => 'assert()',
			'\$_POST\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\(' => 'Dynamic $_POST call',
			'\$_GET\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\('  => 'Dynamic $_GET call',
			'c99shell'                       => 'C99 Webshell',
			'r57shell'                       => 'R57 Webshell',
			'b374k'                          => 'b374k Webshell',
			'wso_version'                    => 'WSO Webshell',
			'marvins'                        => 'Marvins Webshell',
			'alfa_data'                      => 'ALFA Webshell',
		);

		$raw_lines     = explode( "\n", $content );
		$lines         = array();
		$total_dangers = 0;

		foreach ( $raw_lines as $index => $line ) {
			$line_num = $index + 1;
			$matched  = array();

			foreach ( $patterns as $pattern => $label ) {
				if ( preg_match( '/' . $pattern . '/i', $line ) ) {
					$matched[] = $label;
				}
			}

			if ( ! empty( $matched ) ) {
				$total_dangers += count( $matched );
			}

			$lines[] = array(
				'line_number' => $line_num,
				'code'        => $line,
				'dangers'     => array_values( array_unique( $matched ) ),
			);
		}

		return array(
			'success'       => true,
			'file_name'     => $rel_path,
			'file_path'     => $abs_path,
			'total_lines'   => count( $lines ),
			'total_dangers' => $total_dangers,
			'lines'         => $lines,
		);
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

		if ( @rename( $original_path, $quarantine_path ) ) {
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
	 * Melakukan karantina terhadap berkas asing di root.
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

		if ( @rename( $original_path, $quarantine_path ) ) {
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
	 * Melakukan karantina berkas penyusup asing di dalam folder core (wp-admin/wp-includes).
	 *
	 * @param string $rel_path Path relatif berkas asing di folder core (contoh: wp-includes/malware.php).
	 * @return string|bool Nama berkas karantina jika berhasil.
	 */
	public static function quarantine_core_file( $rel_path ) {
		$rel_path      = sanitize_text_field( $rel_path );
		$original_path = ABSPATH . $rel_path;

		if ( ! file_exists( $original_path ) || is_dir( $original_path ) ) {
			return false;
		}

		// Buat nama karantina unik dengan meratakan path pemisah '/' menjadi '_'
		$clean_name      = str_replace( '/', '_', $rel_path );
		$quarantine_name = '__quarantine_' . $clean_name . '_' . time();
		$quarantine_path = ABSPATH . $quarantine_name;

		if ( @rename( $original_path, $quarantine_path ) ) {
			$quarantines = get_option( 'wp_root_guard_quarantined_folders', array() );
			if ( ! is_array( $quarantines ) ) {
				$quarantines = array();
			}

			$quarantines[] = array(
				'type'            => 'file',
				'original_name'   => $rel_path,
				'quarantine_name' => $quarantine_name,
				'original_path'   => $original_path,
				'quarantine_path' => $quarantine_path,
				'quarantine_time' => current_time( 'mysql' ),
			);

			update_option( 'wp_root_guard_quarantined_folders', $quarantines );

			Logger::log(
				esc_html__( 'Berkas penyusup core berhasil dikarantina otomatis', 'wp-root-guard' ),
				$rel_path,
				esc_html__( 'Quarantined', 'wp-root-guard' )
			);

			return $quarantine_name;
		}

		return false;
	}

	/**
	 * Menghapus berkas asing atau penyusup secara langsung dan permanen dari server.
	 *
	 * @param string $rel_path Path relatif berkas dari ABSPATH.
	 * @return bool True jika berhasil dihapus.
	 */
	public static function delete_file_directly( $rel_path ) {
		$rel_path  = sanitize_text_field( $rel_path );
		$file_path = ABSPATH . $rel_path;

		// Hindari penyeberangan direktori atau berkas tidak ada.
		if ( false !== strpos( $rel_path, '..' ) || ! file_exists( $file_path ) || is_dir( $file_path ) ) {
			return false;
		}

		if ( @unlink( $file_path ) || ( function_exists( 'wp_delete_file' ) && wp_delete_file( $file_path ) ) ) {
			// Hapus dari daftar aktif yang terdeteksi di database.
			$active_files = get_option( 'wp_root_guard_active_files', array() );
			if ( is_array( $active_files ) ) {
				foreach ( $active_files as $key => $file ) {
					if ( isset( $file['name'] ) && $file['name'] === $rel_path ) {
						unset( $active_files[ $key ] );
					}
				}
				update_option( 'wp_root_guard_active_files', array_values( $active_files ) );
			}

			$active_core = get_option( 'wp_root_guard_active_core_threats', array() );
			if ( is_array( $active_core ) ) {
				foreach ( $active_core as $key => $file ) {
					if ( isset( $file['name'] ) && $file['name'] === $rel_path ) {
						unset( $active_core[ $key ] );
					}
				}
				update_option( 'wp_root_guard_active_core_threats', array_values( $active_core ) );
			}

			Logger::log(
				esc_html__( 'Berkas asing dihapus secara permanen', 'wp-root-guard' ),
				$rel_path,
				esc_html__( 'Deleted', 'wp-root-guard' )
			);

			return true;
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

		// Pastikan direktori tujuan ada (berguna jika karantina berasal dari subfolder core)
		$dir = dirname( $original_path );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		if ( @rename( $quarantine_path, $original_path ) ) {
			Settings::add_to_whitelist( $item['original_name'] );

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
	 * Mengirim notifikasi email dan Telegram jika ada ancaman baru yang belum dinotifikasi.
	 *
	 * @param array $threats Daftar ancaman terdeteksi saat ini.
	 */
	private static function handle_threat_notifications( $threats ) {
		$settings = Settings::get_settings();

		if ( ! $settings['enable_email_notifications'] && ! $settings['enable_telegram_notifications'] ) {
			return;
		}

		if ( empty( $threats ) ) {
			delete_option( 'wp_root_guard_notified_threats' );
			return;
		}

		$notified = get_option( 'wp_root_guard_notified_threats', array() );
		if ( ! is_array( $notified ) ) {
			$notified = array();
		}

		$new_threats = array();
		foreach ( $threats as $threat ) {
			$threat_key = $threat['type'] . ':' . $threat['name'];
			if ( ! in_array( $threat_key, $notified, true ) ) {
				$new_threats[] = $threat;
				$notified[]    = $threat_key;
			}
		}

		if ( empty( $new_threats ) ) {
			return;
		}

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
				$type_label   = ( 'folder' === $threat['type'] ) ? esc_html__( 'Folder Asing', 'wp-root-guard' ) : esc_html__( 'Berkas/Integritas Core', 'wp-root-guard' );
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

	/**
	 * Memindai direktori wp-content/uploads/ secara rekursif untuk mencari berkas PHP mencurigakan.
	 *
	 * @return array Daftar berkas PHP yang ditemukan di folder uploads.
	 */
	public static function scan_uploads_for_php_files() {
		$upload_dir = wp_upload_dir();
		$base_dir   = isset( $upload_dir['basedir'] ) ? $upload_dir['basedir'] : '';

		if ( empty( $base_dir ) || ! file_exists( $base_dir ) || ! is_dir( $base_dir ) ) {
			return array();
		}

		$php_files      = array();
		$user_whitelist = Settings::get_user_whitelist();

		try {
			$directory = new \RecursiveDirectoryIterator( $base_dir, \RecursiveDirectoryIterator::SKIP_DOTS );
			$iterator  = new \RecursiveIteratorIterator( $directory, \RecursiveIteratorIterator::SELF_FIRST );

			foreach ( $iterator as $item ) {
				if ( $item->isFile() ) {
					$ext = strtolower( pathinfo( $item->getFilename(), PATHINFO_EXTENSION ) );
					if ( in_array( $ext, array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'inc' ), true ) ) {
						$abs_path = str_replace( '\\', '/', $item->getPathname() );
						$rel_path = str_replace( str_replace( '\\', '/', ABSPATH ), '', $abs_path );

						if ( in_array( $rel_path, $user_whitelist, true ) || in_array( $abs_path, $user_whitelist, true ) ) {
							continue;
						}

						$php_files[] = array(
							'name'     => $rel_path,
							'path'     => $abs_path,
							'filename' => $item->getFilename(),
						);
					}
				}
			}
		} catch ( \Exception $e ) {
			// Abaikan error eksepsi iterator
		}

		return $php_files;
	}
}
