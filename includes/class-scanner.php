<?php
/**
 * Mesin pemindaian keamanan untuk WP Root Guard.
 *
 * Berkas ini berisi class Scanner yang menangani seluruh operasi
 * deteksi ancaman, karantina, self-healing, dan notifikasi.
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
 * Class Scanner
 *
 * Mesin utama pemindaian keamanan WP Root Guard. Bertanggung jawab untuk:
 *
 * 1. Pemindaian folder asing di root directory (non-rekursif).
 * 2. Pemindaian berkas asing dan terduga di root directory.
 * 3. Pengecekan integritas berkas core WordPress via API Checksums resmi.
 * 4. Deteksi berkas penyusup di dalam wp-admin/ dan wp-includes/.
 * 5. Pemindaian berkas PHP berbahaya di wp-content/uploads/.
 * 6. Deteksi signature webshell pada berkas yang dicurigai.
 * 7. Karantina otomatis berkas/folder ancaman ke vault terisolasi.
 * 8. Pemulihan berkas core dari SVN resmi WordPress.org (self-healing).
 * 9. Perbandingan kode lokal vs upstream (diff viewer).
 * 10. Notifikasi ancaman via Telegram Bot dan Email Administrator.
 *
 * Semua operasi karantina, penghapusan, dan pemulihan divalidasi
 * terhadap path traversal dan symlink sebelum dieksekusi.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Scanner {

	/** Scope errors collected during the current run. */
	private static $scope_errors = array();

	/**
	 * Option yang menyimpan checkpoint eksekusi scan terakhir.
	 */
	const SCAN_STATE_OPTION = 'wp_root_guard_scan_state';

	/**
	 * Mendapatkan string tanggal dan waktu berformat WIB (Waktu Indonesia Barat / Asia/Jakarta UTC+7).
	 *
	 * @param int|string|null $time Unix timestamp atau string mysql time.
	 * @return string Tanggal dan waktu berformat WIB (contoh: 24 Juli 2026 15:12 WIB).
	 */
	public static function get_wib_time( $time = null ) {
		if ( null === $time || '' === $time ) {
			$timestamp = time();
		} elseif ( is_numeric( $time ) ) {
			$timestamp = (int) $time;
		} else {
			$timestamp = strtotime( $time );
			if ( false === $timestamp ) {
				$timestamp = time();
			}
		}

		try {
			$dt = new \DateTime( '@' . $timestamp );
			$dt->setTimezone( new \DateTimeZone( 'Asia/Jakarta' ) );

			$bulan = array(
				1  => 'Januari',
				2  => 'Februari',
				3  => 'Maret',
				4  => 'April',
				5  => 'Mei',
				6  => 'Juni',
				7  => 'Juli',
				8  => 'Agustus',
				9  => 'September',
				10 => 'Oktober',
				11 => 'November',
				12 => 'Desember',
			);

			$day   = $dt->format( 'j' );
			$month = $bulan[ (int) $dt->format( 'n' ) ];
			$year  = $dt->format( 'Y' );
			$clock = $dt->format( 'H:i' );

			return "{$day} {$month} {$year} {$clock} WIB";
		} catch ( \Exception $e ) {
			return date_i18n( 'j F Y H:i', current_time( 'timestamp' ) ) . ' WIB';
		}
	}

	/**
	 * Melakukan pemindaian root directory secara menyeluruh (folder, berkas root, dan integritas core).
	 *
	 * @return array Hasil pemindaian berupa status proteksi dan daftar ancaman terdeteksi.
	 */
	public static function perform_scan( $context = 'unknown' ) {
		// P0.3 runner performs one resumable batch per invocation. The legacy
		// monolithic implementation remains below only for backward-compatible
		// helper methods until its removal in a later major release.
		if ( class_exists( __NAMESPACE__ . '\\ScanBatchRunner' ) ) {
			return ScanBatchRunner::run( $context );
		}

		$lock = new ScanLock();
		$lock_state = $lock->acquire( $context );

		if ( false === $lock_state ) {
			return array(
				'last_scan'        => '',
				'status'           => 'deferred',
				'security_status'  => ScanResult::SECURITY_PENDING,
				'coverage_status'  => ScanResult::COVERAGE_DEGRADED,
				'execution_state' => ScanResult::EXECUTION_DEFERRED,
				'unknown_count'    => 0,
				'unknown_folders'  => array(),
				'error'            => esc_html__( 'Pemindaian ditunda karena scan lain masih berjalan.', 'wp-root-guard' ),
			);
		}

		$run_id       = isset( $lock_state['run_id'] ) ? $lock_state['run_id'] : wp_generate_uuid4();
		$queue_state  = class_exists( __NAMESPACE__ . '\\ScanQueue' ) ? ScanQueue::create_run( 'full', 0, 0, array( 'context' => $context ) ) : null;
		$queue_token  = ( is_array( $queue_state ) && isset( $queue_state['fencing_token'] ) ) ? $queue_state['fencing_token'] : '';
		$started_at   = microtime( true );
		$started_gmt  = gmdate( 'Y-m-d H:i:s' );

		self::update_scan_state(
			array(
				'status'           => 'running',
				'run_id'           => $run_id,
				'started_at_gmt'   => $started_gmt,
				'completed_at_gmt' => '',
				'last_heartbeat'   => $started_gmt,
				'duration_ms'      => 0,
				'found_count'      => 0,
				'error'            => '',
			)
		);

		try {
			if ( $queue_token ) {
				ScanQueue::heartbeat( $queue_token );
			}
			$results = self::perform_scan_internal( $run_id );
			$is_deferred = ScanResult::EXECUTION_DEFERRED === ( $results['execution_state'] ?? '' );
			if ( $is_deferred ) {
				self::update_scan_state(
					array(
						'status'         => 'deferred',
						'last_heartbeat' => gmdate( 'Y-m-d H:i:s' ),
						'error'          => esc_html__( 'Pemindaian menunggu kondisi aman untuk dilanjutkan.', 'wp-root-guard' ),
					)
				);
				if ( class_exists( __NAMESPACE__ . '\\Cron' ) ) {
					Cron::schedule_scan_continuation();
				}
				$lock->release( $lock_state['run_id'], $lock_state['fencing_token'] );
				if ( $queue_token ) {
					ScanQueue::update_next_batch( $queue_token, array( 'status' => 'paused', 'errors' => array( 'deferred' ) ) );
				}
				return ScanResult::normalize( $results );
			}
			$completed_gmt = gmdate( 'Y-m-d H:i:s' );

			self::update_scan_state(
				array(
					'status'           => 'completed',
					'run_id'           => $run_id,
					'started_at_gmt'   => $started_gmt,
					'completed_at_gmt' => $completed_gmt,
					'last_heartbeat'   => $completed_gmt,
					'duration_ms'      => (int) round( ( microtime( true ) - $started_at ) * 1000 ),
					'found_count'      => isset( $results['unknown_count'] ) ? (int) $results['unknown_count'] : 0,
					'error'            => '',
				)
			);

			$results = ScanResult::normalize(
				array_merge(
					$results,
					array(
						'execution_state' => ScanResult::EXECUTION_COMPLETED,
					)
				)
			);
			$lock->release( $lock_state['run_id'], $lock_state['fencing_token'] );
			if ( $queue_token ) {
				ScanQueue::finish( $queue_token, 'completed', array( 'findings_summary' => array( 'threat_count' => isset( $results['unknown_count'] ) ? (int) $results['unknown_count'] : 0 ) ) );
			}

			return $results;
		} catch ( \Throwable $exception ) {
			$error = sanitize_text_field( $exception->getMessage() );
			self::update_scan_state(
				array(
					'status'           => 'failed',
					'run_id'           => $run_id,
					'started_at_gmt'   => $started_gmt,
					'completed_at_gmt' => '',
					'last_heartbeat'   => gmdate( 'Y-m-d H:i:s' ),
					'duration_ms'      => (int) round( ( microtime( true ) - $started_at ) * 1000 ),
					'found_count'      => 0,
					'error'            => $error,
				)
			);

			Logger::log(
				esc_html__( 'Pemindaian gagal dieksekusi', 'wp-root-guard' ),
				$error,
				esc_html__( 'Error', 'wp-root-guard' )
			);

			$lock->release( $lock_state['run_id'], $lock_state['fencing_token'] );
			if ( $queue_token ) {
				ScanQueue::finish( $queue_token, 'failed', array( 'errors' => array( $error ) ) );
			}

			return array(
				'last_scan'       => '',
				'status'          => 'failed',
				'security_status' => ScanResult::SECURITY_PENDING,
				'coverage_status' => ScanResult::COVERAGE_FAILED,
				'execution_state' => ScanResult::EXECUTION_FAILED,
				'unknown_count'   => 0,
				'unknown_folders' => array(),
			);
		}
	}

	/**
	 * Isi lama scanner dipisahkan agar seluruh jalur scan (manual dan cron)
	 * selalu melewati checkpoint perform_scan().
	 *
	 * @return array Hasil pemindaian.
	 */
	private static function perform_scan_internal( $run_id = '' ) {
		$coverage_status = ScanResult::COVERAGE_COMPLETE;
		$scope_errors     = array();
		self::$scope_errors = array();

		// 0. Maintenance Guard: Tunda pemindaian jika WordPress core update sedang berlangsung.
		if ( self::is_core_update_in_progress() ) {
			Logger::log(
				esc_html__( 'Pemindaian integritas ditunda: WordPress sedang dalam proses pembaruan (maintenance mode).', 'wp-root-guard' ),
				'.maintenance',
				esc_html__( 'Info', 'wp-root-guard' )
			);
			return array(
				'last_scan'       => current_time( 'mysql' ),
				'status'          => 'degraded',
				'security_status' => ScanResult::SECURITY_PENDING,
				'coverage_status' => ScanResult::COVERAGE_DEGRADED,
				'execution_state' => ScanResult::EXECUTION_DEFERRED,
				'unknown_count'   => 0,
				'unknown_folders' => array(),
			);
		}

		$detection_time = self::get_wib_time();

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
		$auto_quarantine  = self::can_auto_quarantine( false );
		$uploads_quarantine = self::can_auto_quarantine( true );
		if ( ! empty( $settings['enable_auto_quarantine'] ) && ! $auto_quarantine ) {
			$scope_errors[] = 'quarantine_storage_unavailable';
		}
		if ( ! empty( $settings['enable_uploads_auto_quarantine'] ) && ! $uploads_quarantine ) {
			$scope_errors[] = 'uploads_quarantine_unverified';
		}

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

				$status_text    = __( 'Unknown Folder', 'wp-root-guard' );

				if ( $settings['enable_auto_quarantine'] && $auto_quarantine ) {
					$quarantine_name = self::quarantine_folder( $folder );
					if ( false !== $quarantine_name ) {
						$status_text = __( 'Quarantined Automatically', 'wp-root-guard' );
						$full_path   = self::get_quarantine_dir() . $quarantine_name;
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

				$status_text    = __( 'Unknown File', 'wp-root-guard' );

				$malware_indicator = self::scan_file_for_webshell( $file_path );
				$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Bersih (Bukan Webshell)', 'wp-root-guard' );

				if ( $settings['enable_auto_quarantine'] && $auto_quarantine ) {
					$quarantine_name = self::quarantine_file( $file );
					if ( false !== $quarantine_name ) {
						$status_text = __( 'Quarantined Automatically', 'wp-root-guard' );
						$file_path   = self::get_quarantine_dir() . $quarantine_name;
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
			} elseif ( ! in_array( $file, $user_whitelist, true ) && isset( $baseline_files[ $file ] ) && $baseline_files[ $file ] !== $current_hash ) {
				$local_content = @file_get_contents( $file_path );
				if ( ! empty( $local_content ) ) {
					$normalized_hash = md5( str_replace( "\r\n", "\n", $local_content ) );
					if ( isset( $baseline_files[ $file ] ) && $baseline_files[ $file ] === $normalized_hash ) {
						continue;
					}
				}

				$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
				if ( file_exists( $file_path ) ) {
					$ctime = filectime( $file_path );
					if ( false !== $ctime ) {
						$created_time = date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $ctime );
					}
				}

				$status_text    = __( 'Modified File', 'wp-root-guard' );
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

				// Hanya pindai berkas di wp-admin, wp-includes, dan berkas inti root (abaikan wp-content & berkas di whitelist)
				if ( 0 === strpos( $relative_path, 'wp-content/' ) || in_array( $relative_path, $user_whitelist, true ) ) {
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
						
						// Normalisasi line-ending (\r\n ke \n) untuk kompatibilitas server Windows/Linux/FTP
						$local_content = @file_get_contents( $full_path );
						if ( ! empty( $local_content ) ) {
							$normalized_hash = md5( str_replace( "\r\n", "\n", $local_content ) );
							if ( $normalized_hash === $expected_hash ) {
								continue;
							}
						}

						// Lewati jika berkas ini adalah berkas pengaturan pengguna yang wajar (seperti wp-config.php)
						if ( 'wp-config.php' === $relative_path ) {
							continue;
						}

						$file_mtime        = file_exists( $full_path ) ? filemtime( $full_path ) : false;
						$mod_time          = $file_mtime ? self::get_wib_time( $file_mtime ) : $detection_time;
						$malware_indicator = self::scan_file_for_webshell( $full_path );
						$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Perubahan Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Integritas Berkas Berubah', 'wp-root-guard' );

						$threats[] = array(
							'type'              => 'core_file',
							'name'              => $relative_path,
							'path'              => $full_path,
							'created_time'      => $mod_time,
							'detection_time'    => $mod_time,
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
									// Lewati berkas di whitelist dan penanda karantina
									if ( in_array( $rel_path, $user_whitelist, true ) || 0 === strpos( basename( $pathname ), '__quarantine_' ) ) {
										continue;
									}

									$created_time = esc_html__( 'Tidak diketahui', 'wp-root-guard' );
									$mtime        = $fileinfo->getMTime();
									if ( false !== $mtime ) {
										$created_time = self::get_wib_time( $mtime );
									}

									$status_text       = __( 'Suspicious Core Injection', 'wp-root-guard' );
									$malware_indicator = self::scan_file_for_webshell( $pathname );
									$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Penyusupan Mencurigakan (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Berkas Penyusup di Folder Core', 'wp-root-guard' );

									// Karantina otomatis untuk berkas penyusup asing di folder core
					if ( $settings['enable_auto_quarantine'] && $auto_quarantine ) {
										$quarantine_name = self::quarantine_core_file( $rel_path );
										if ( false !== $quarantine_name ) {
											$status_text = __( 'Quarantined Automatically', 'wp-root-guard' );
											$pathname    = self::get_quarantine_dir() . $quarantine_name;
										}
									} else {
										Logger::log(
											esc_html__( 'Berkas penyusup asing di folder core terdeteksi', 'wp-root-guard' ),
											$rel_path,
											$malware_indicator ? esc_html__( 'Malware Suspicious', 'wp-root-guard' ) : esc_html__( 'Unknown', 'wp-root-guard' )
										);
									}

									$threats[] = array(
										'type'              => 'core_file',
										'name'              => $rel_path,
										'path'              => $pathname,
										'created_time'      => $created_time,
										'detection_time'    => $created_time,
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
		} else {
			$coverage_status = ScanResult::COVERAGE_DEGRADED;
			$scope_errors[]   = 'core_checksums_unavailable';
			Logger::log(
				esc_html__( 'Verifikasi checksum core tidak tersedia; hasil scan berstatus degraded.', 'wp-root-guard' ),
				'core_checksums',
				esc_html__( 'Degraded', 'wp-root-guard' )
			);
		}

		// ==========================================
		// D. PEMINDAIAN BERKAS PHP DI FOLDER UPLOADS (wp-content/uploads)
		// ==========================================
		if ( ! isset( $settings['enable_uploads_php_scan'] ) || $settings['enable_uploads_php_scan'] ) {
			$uploads_php = self::scan_uploads_for_php_files();
			if ( is_wp_error( $uploads_php ) ) {
				$coverage_status = ScanResult::COVERAGE_DEGRADED;
				$scope_errors[]   = 'uploads_scan_failed';
				$uploads_php      = array();
			}
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

				$status_text       = __( 'PHP File in Uploads', 'wp-root-guard' );
				$malware_indicator = self::scan_file_for_webshell( $file_path );
				$malware_label     = $malware_indicator ? sprintf( /* translators: %s: nama signature */ esc_html__( 'Sangat Berbahaya (%s)', 'wp-root-guard' ), $malware_indicator ) : esc_html__( 'Berkas PHP di Folder Uploads', 'wp-root-guard' );

					$quarantined = false;
					if ( ( ! empty( $settings['enable_uploads_auto_quarantine'] ) || ! empty( $settings['enable_auto_quarantine'] ) ) && $uploads_quarantine ) {
						$quarantine_name = self::quarantine_core_file( $rel_path );
						if ( false !== $quarantine_name ) {
							$status_text = __( 'Quarantined Automatically', 'wp-root-guard' );
							$file_path   = self::get_quarantine_dir() . $quarantine_name;
							$quarantined = true;
						} else {
							Logger::log(
								esc_html__( 'Gagal mengarantina berkas PHP di folder uploads', 'wp-root-guard' ),
								$rel_path,
								esc_html__( 'Error', 'wp-root-guard' )
							);
						}
					}

					if ( ! $quarantined ) {
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
		$scope_errors = array_values( array_unique( array_merge( $scope_errors, self::$scope_errors ) ) );
		if ( ! empty( $scope_errors ) ) {
			$coverage_status = ScanResult::COVERAGE_DEGRADED;
		}

		$scan_results = array(
			'last_scan'       => current_time( 'mysql' ),
			'status'          => empty( $threats ) ? ( ScanResult::COVERAGE_COMPLETE === $coverage_status ? 'safe' : 'degraded' ) : 'threat',
			'security_status' => empty( $threats ) ? ScanResult::SECURITY_SAFE : ScanResult::SECURITY_THREAT,
			'coverage_status' => $coverage_status,
			'execution_state' => ScanResult::EXECUTION_COMPLETED,
			'scope_errors'    => $scope_errors,
			'unknown_count'   => count( $threats ),
			'unknown_folders' => $threats,
		);

		// Simpan hasil scan ke WordPress Options.
		update_option( 'wp_root_guard_last_scan', $scan_results );
		update_option( 'wp_root_guard_unknown_folders', $threats );

		// Keep an audit-safe, deduplicated finding record for this run. Paths are
		// hashed in the database; the dashboard continues using the legacy option.
		if ( '' !== $run_id && class_exists( __NAMESPACE__ . '\\ScanStore' ) ) {
			foreach ( $threats as $threat ) {
				$path = is_array( $threat ) ? (string) ( $threat['path'] ?? $threat['name'] ?? '' ) : (string) $threat;
				$type = is_array( $threat ) ? (string) ( $threat['type'] ?? 'unknown' ) : 'unknown';
				ScanStore::save_finding( $run_id, 'full', $path, 'threat', array( 'type' => sanitize_text_field( $type ) ) );
			}
		}

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
	 * Mengambil checkpoint scan terakhir.
	 *
	 * @return array Checkpoint scan.
	 */
	public static function get_scan_state() {
		$default = array(
			'status'           => 'idle',
			'run_id'           => '',
			'started_at_gmt'   => '',
			'completed_at_gmt' => '',
			'last_heartbeat'   => '',
			'duration_ms'      => 0,
			'found_count'      => 0,
			'error'            => '',
		);

		$state = get_option( self::SCAN_STATE_OPTION, $default );
		return is_array( $state ) ? array_merge( $default, $state ) : $default;
	}

	/**
	 * Menyimpan checkpoint scan tanpa autoload agar tidak membebani request umum.
	 *
	 * @param array $state Data checkpoint parsial.
	 * @return void
	 */
	private static function update_scan_state( $state ) {
		$current = self::get_scan_state();
		update_option( self::SCAN_STATE_OPTION, array_merge( $current, $state ), false );
	}

	/**
	 * Memastikan auto-quarantine hanya aktif bila storage dan execution guard aman.
	 *
	 * @param bool $uploads Apakah target berada di uploads.
	 * @return bool
	 */
	private static function can_auto_quarantine( $uploads = false ) {
		if ( ! class_exists( __NAMESPACE__ . '\\QuarantineStorage' ) ) {
			return false;
		}
		$storage = QuarantineStorage::resolve_directory();
		if ( 'ready' !== $storage['status'] ) {
			return false;
		}
		if ( $uploads && 'uploads_fallback' === $storage['source'] ) {
			if ( ! class_exists( __NAMESPACE__ . '\\ServerGuard' ) || 'verified' !== ServerGuard::get_status()['status'] ) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Mengambil daftar checksums resmi dari WordPress.org API.
	/**
	 * Memeriksa apakah WordPress sedang dalam proses pembaruan core / maintenance mode.
	 *
	 * @return bool True jika update sedang berjalan, false jika aman.
	 */
	public static function is_core_update_in_progress() {
		if ( function_exists( 'wp_is_maintenance_mode' ) && wp_is_maintenance_mode() ) {
			return true;
		}

		$maintenance_file = ABSPATH . '.maintenance';
		if ( file_exists( $maintenance_file ) ) {
			$mtime = filemtime( $maintenance_file );
			if ( false !== $mtime && ( time() - $mtime ) < 600 ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Mendapatkan kunci transient checksums yang terikat pada versi WordPress dan locale.
	 *
	 * @param string|null $version Versi WordPress (opsional).
	 * @param string|null $locale  Locale WordPress (opsional).
	 * @return string Kunci transient dinamis (maks 64 karakter).
	 */
	public static function get_core_checksum_transient_key( $version = null, $locale = null ) {
		global $wp_version;
		$v = ! empty( $version ) ? (string) $version : (string) $wp_version;
		$l = ! empty( $locale ) ? (string) $locale : get_locale();
		return 'wp_rg_chk_' . substr( md5( $v . '_' . $l ), 0, 20 );
	}

	/**
	 * Menghapus cache transient checksums saat core diupdate atau di-refresh manual.
	 *
	 * @param string|null $version Versi WordPress spesifik, atau null untuk versi saat ini.
	 * @return void
	 */
	public static function invalidate_core_checksums_cache( $version = null ) {
		global $wp_version;
		$v = ! empty( $version ) ? (string) $version : (string) $wp_version;
		$transient_key = self::get_core_checksum_transient_key( $v );
		delete_transient( $transient_key );
		delete_transient( 'wp_root_guard_core_checksums' );
		if ( is_multisite() ) {
			delete_site_transient( $transient_key );
			delete_site_transient( 'wp_root_guard_core_checksums' );
		}
		delete_transient( 'wp_rg_chk_fail_' . substr( md5( $v . '_' . get_locale() ), 0, 20 ) );
	}

	/**
	 * Mengambil daftar checksums resmi dari WordPress.org API.
	 * Menggunakan dynamic versioned transient key dan circuit breaker untuk mencegah overhead saat w.org down.
	 *
	 * @return array|bool Array checksums resmi (relative_path => expected_md5) atau false jika gagal.
	 */
	public static function get_core_checksums() {
		global $wp_version;
		$locale        = get_locale();
		$transient_key = self::get_core_checksum_transient_key( $wp_version, $locale );
		$cached        = get_transient( $transient_key );

		if ( is_array( $cached ) ) {
			return $cached;
		}

		// Cek circuit breaker transient jika API baru saja gagal dalam 15 menit terakhir
		$fail_key = 'wp_rg_chk_fail_' . substr( md5( (string) $wp_version . '_' . $locale ), 0, 20 );
		if ( get_transient( $fail_key ) ) {
			return false;
		}

		$url      = "https://api.wordpress.org/core/checksums/1.0/?version={$wp_version}&locale={$locale}";
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			set_transient( $fail_key, 1, 15 * MINUTE_IN_SECONDS );
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			set_transient( $fail_key, 1, 15 * MINUTE_IN_SECONDS );
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body, true );

		if ( ! is_array( $data ) || empty( $data['checksums'] ) ) {
			set_transient( $fail_key, 1, 15 * MINUTE_IN_SECONDS );
			return false;
		}

		// Simpan di cache transient selama 24 jam (dinamis & legacy)
		set_transient( $transient_key, $data['checksums'], DAY_IN_SECONDS );
		set_transient( 'wp_root_guard_core_checksums', $data['checksums'], DAY_IN_SECONDS );

		return $data['checksums'];
	}

	/**
	 * Mengambil konten berkas resmi core dengan dual-source fallback (SVN WordPress.org -> GitHub Official Mirror).
	 *
	 * @param string $relative_path Path relatif berkas core.
	 * @return array{success: bool, content: string, source: string, error: string}
	 */
	public static function fetch_remote_core_file( $relative_path ) {
		global $wp_version;
		$clean_version = preg_replace( '/-.*$/', '', (string) $wp_version );

		$sources = array(
			'svn'          => "https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}",
			'svn_clean'    => "https://core.svn.wordpress.org/tags/{$clean_version}/{$relative_path}",
			'github'       => "https://raw.githubusercontent.com/WordPress/WordPress/{$wp_version}/{$relative_path}",
			'github_clean' => "https://raw.githubusercontent.com/WordPress/WordPress/{$clean_version}/{$relative_path}",
		);

		$sources    = array_unique( $sources );
		$last_error = '';

		foreach ( $sources as $type => $url ) {
			$response = wp_remote_get( $url, array( 'timeout' => 15 ) );
			if ( is_wp_error( $response ) ) {
				$last_error = $response->get_error_message();
				continue;
			}

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				$body = wp_remote_retrieve_body( $response );
				if ( ! empty( $body ) ) {
					return array(
						'success' => true,
						'content' => $body,
						'source'  => $type,
						'error'   => '',
					);
				}
			}
		}

		return array(
			'success' => false,
			'content' => '',
			'source'  => '',
			'error'   => ! empty( $last_error ) ? $last_error : esc_html__( 'Gagal mengunduh berkas core dari SVN maupun GitHub Mirror resmi.', 'wp-root-guard' ),
		);
	}

	/**
	 * Mengembalikan berkas core WordPress ke keadaan asli dari SVN WordPress.org.
	 *
	 * @param string $relative_path Path relatif berkas terhadap ABSPATH (contoh: wp-login.php).
	 * @return bool True jika berhasil memulihkan berkas core.
	 */
	/**
	 * Mengunduh berkas core asli dari repository resmi SVN WordPress.org dan menimpa berkas lokal yang rusak/dimodifikasi.
	 *
	 * @param string $relative_path Path relatif berkas core (misal: wp-blog-header.php atau wp-includes/version.php).
	 * @return array Status keberhasilan (success => bool, message => string).
	 */
	public static function restore_core_file( $relative_path ) {
		$relative_path = sanitize_text_field( $relative_path );
		global $wp_version;

		// Keamanan: hanya izinkan path yang berada di dalam folder core WordPress resmi
		$allowed_prefixes = array( 'wp-admin/', 'wp-includes/', 'wp-login.php', 'wp-blog-header.php', 'wp-settings.php', 'wp-load.php', 'wp-cron.php', 'wp-mail.php', 'wp-comments-post.php', 'wp-activate.php', 'wp-signup.php', 'wp-trackback.php', 'wp-links-opml.php', 'index.php', 'xmlrpc.php' );
		$is_allowed = false;
		foreach ( $allowed_prefixes as $prefix ) {
			if ( 0 === strpos( $relative_path, $prefix ) ) {
				$is_allowed = true;
				break;
			}
		}
		if ( ! $is_allowed ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Berkas tidak diizinkan untuk dipulihkan otomatis (Bukan berkas core WordPress resmi).', 'wp-root-guard' ),
			);
		}

		// Validasi path final dengan realpath untuk cegah path traversal
		if ( false !== strpos( $relative_path, '..' ) || 0 === strpos( $relative_path, '/' ) || 0 === strpos( $relative_path, '\\' ) ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Path berkas tidak valid atau terdeteksi potensi Path Traversal.', 'wp-root-guard' ),
			);
		}

		$local_path = ABSPATH . $relative_path;
		$real_base  = realpath( ABSPATH );

		if ( file_exists( $local_path ) ) {
			$real_local = realpath( $local_path );
			if ( ! $real_local || ! $real_base || 0 !== strpos( $real_local, $real_base ) ) {
				return array(
					'success' => false,
					'message' => esc_html__( 'Path berkas tidak valid atau terdeteksi potensi Path Traversal.', 'wp-root-guard' ),
				);
			}
		}

		// Validasi direktori sebelum mkdir untuk memastikan berada di dalam ABSPATH
		$dir          = dirname( $local_path );
		$existing_dir = $dir;
		while ( ! file_exists( $existing_dir ) && strlen( $existing_dir ) >= strlen( $real_base ) ) {
			$existing_dir = dirname( $existing_dir );
		}
		$real_existing_dir = realpath( $existing_dir );
		if ( ! $real_existing_dir || ! $real_base || 0 !== strpos( $real_existing_dir, $real_base ) ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Path berkas tidak valid atau terdeteksi potensi Path Traversal.', 'wp-root-guard' ),
			);
		}

		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		$remote = self::fetch_remote_core_file( $relative_path );
		if ( ! $remote['success'] ) {
			Logger::log(
				esc_html__( 'Gagal mengunduh berkas core resmi', 'wp-root-guard' ),
				$relative_path . ' (' . $remote['error'] . ')',
				esc_html__( 'Failed', 'wp-root-guard' )
			);
			return array(
				'success' => false,
				'message' => sprintf(
					/* translators: 1: error message, 2: WP version */
					esc_html__( 'Gagal mengunduh berkas core resmi untuk WordPress v%2$s: %1$s. Periksa koneksi internet / outbound HTTP server Anda.', 'wp-root-guard' ),
					$remote['error'],
					$wp_version
				),
			);
		}

		$content = $remote['content'];
		if ( empty( $content ) ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Konten berkas asli dari repositori resmi diterima dalam keadaan kosong.', 'wp-root-guard' ),
			);
		}

		$checksums = self::get_core_checksums();
		if ( ! is_array( $checksums ) || empty( $checksums[ $relative_path ] ) || ! hash_equals( strtolower( (string) $checksums[ $relative_path ] ), strtolower( md5( $content ) ) ) ) {
			Logger::log(
				esc_html__( 'Restore core ditolak karena checksum remote tidak cocok.', 'wp-root-guard' ),
				$relative_path,
				esc_html__( 'Checksum Failed', 'wp-root-guard' )
			);
			return array(
				'success' => false,
				'message' => esc_html__( 'Restore ditolak: checksum berkas remote tidak cocok dengan checksum resmi WordPress.', 'wp-root-guard' ),
			);
		}
		if ( ! class_exists( __NAMESPACE__ . '\\QuarantineManager' ) || ! QuarantineManager::is_available_for_automatic_containment() ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Restore otomatis ditolak karena vault karantina aman tidak tersedia untuk recovery kegagalan verifikasi.', 'wp-root-guard' ),
			);
		}

		// Tulis temporary file lalu atomic rename agar file lama tetap utuh jika proses terputus.
		$existing_mode = file_exists( $local_path ) ? (int) @fileperms( $local_path ) & 0777 : 0644;
		$write_result = class_exists( __NAMESPACE__ . '\\AtomicWriter' )
			? AtomicWriter::write( $local_path, $content, $existing_mode )
			: new \WP_Error( 'atomic_writer_missing', __( 'Atomic writer tidak tersedia.', 'wp-root-guard' ) );
		if ( true === $write_result && hash_equals( strtolower( (string) $checksums[ $relative_path ] ), strtolower( (string) @md5_file( $local_path ) ) ) ) {
			Logger::log(
				esc_html__( 'Berkas core WordPress dipulihkan ke asli', 'wp-root-guard' ),
				$relative_path,
				esc_html__( 'Restored', 'wp-root-guard' )
			);

			return array(
				'success' => true,
				'message' => sprintf( /* translators: %1$s: path, %2$s: WP version */ esc_html__( 'Berkas %1$s BERHASIL dipulihkan ke versi asli resmi dari SVN WordPress.org (v%2$s)!', 'wp-root-guard' ), $relative_path, $wp_version ),
			);
		} else {
			// The path was atomically replaced but cannot be proven trustworthy.
			// Contain it immediately; never claim a successful restore.
			$contained = true === $write_result ? QuarantineManager::quarantine( $local_path, $relative_path, 'file' ) : new \WP_Error( 'atomic_write_failed', __( 'Atomic write gagal sebelum target diganti.', 'wp-root-guard' ) );
			$containment_status = is_wp_error( $contained ) ? $contained->get_error_code() : 'contained';
			Logger::log(
				esc_html__( 'Restore core gagal verifikasi; artefak hasil tulis dikarantina', 'wp-root-guard' ),
				$relative_path . ' (' . $containment_status . ')',
				esc_html__( 'Restore Verification Failed', 'wp-root-guard' )
			);
			$last_scan = self::get_last_scan_results();
			$last_scan['status'] = 'degraded';
			$last_scan['security_status'] = ScanResult::SECURITY_PENDING;
			$last_scan['coverage_status'] = ScanResult::COVERAGE_DEGRADED;
			$last_scan['scope_errors'] = array_values( array_unique( array_merge( (array) ( $last_scan['scope_errors'] ?? array() ), array( 'core_restore_verification_failed' ) ) ) );
			update_option( 'wp_root_guard_last_scan', $last_scan, false );
			return array(
				'success' => false,
				'message' => sprintf( /* translators: %s: path */ esc_html__( 'Restore %s gagal diverifikasi; hasil tulis telah ditahan untuk investigasi.', 'wp-root-guard' ), $relative_path ),
			);
		}
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

		// Validasi realpath untuk cegah path traversal
		$real_base  = realpath( ABSPATH );
		$real_local = realpath( $local_path );
		if ( ! $real_base || ! $real_local || 0 !== strpos( $real_local, $real_base ) ) {
			return array( 'error' => esc_html__( 'Berkas lokal tidak ditemukan.', 'wp-root-guard' ) );
		}
		$local_path = $real_local;

		if ( ! file_exists( $local_path ) ) {
			return array( 'error' => esc_html__( 'Berkas lokal tidak ditemukan.', 'wp-root-guard' ) );
		}

		$remote = self::fetch_remote_core_file( $relative_path );
		if ( ! $remote['success'] ) {
			return array(
				'error' => sprintf(
					/* translators: %s: error reason */
					esc_html__( 'Gagal mengunduh versi asli berkas dari repositori resmi: %s', 'wp-root-guard' ),
					$remote['error']
				),
			);
		}

		$original_content = $remote['content'];
		$local_content    = @file_get_contents( $local_path );

		$original_lines = explode( "\n", str_replace( "\r", "", $original_content ) );
		$local_lines    = explode( "\n", str_replace( "\r", "", $local_content ) );

		$diff     = array();
		$max      = max( count( $original_lines ), count( $local_lines ) );
		$max_diff = 300; // Batasi maksimal 300 baris perbedaan agar tidak lambat di berkas besar
		$truncated = false;
		
		for ( $i = 0; $i < $max; $i++ ) {
			$orig_line = isset( $original_lines[ $i ] ) ? $original_lines[ $i ] : null;
			$loc_line  = isset( $local_lines[ $i ] ) ? $local_lines[ $i ] : null;

			if ( $orig_line !== $loc_line ) {
				if ( count( $diff ) >= $max_diff ) {
					$truncated = true;
					break;
				}
				$line_number = $i + 1;
				$diff[] = array(
					'line'     => $line_number,
					'original' => $orig_line,
					'local'    => $loc_line,
				);
			}
		}

		if ( $truncated ) {
			$diff[] = array(
				'line'     => '...',
				'original' => sprintf( /* translators: %d: max diff lines */ esc_html__( '[Tampilan dibatasi %d baris perbedaan. Unduh berkas asli untuk melihat selengkapnya.]', 'wp-root-guard' ), $max_diff ),
				'local'    => null,
			);
		}

		return $diff;
	}

	/**
	 * Mendapatkan daftar pola (signature) webshell dan fungsi berbahaya dengan regex word boundary.
	 *
	 * @return array Array pola regex => label nama bahaya.
	 */
	private static function get_webshell_patterns() {
		$boundary = '(?:^|[^a-zA-Z0-9_])';

		return array(
			$boundary . 'eval\('                         => 'eval()',
			$boundary . 'base64_decode\('                => 'base64_decode()',
			$boundary . 'shell_exec\('                   => 'shell_exec()',
			$boundary . 'passthru\('                     => 'passthru()',
			$boundary . 'system\('                       => 'system()',
			$boundary . 'exec\('                         => 'exec()',
			$boundary . 'popen\('                        => 'popen()',
			$boundary . 'proc_open\('                    => 'proc_open()',
			$boundary . 'pcntl_exec\('                   => 'pcntl_exec()',
			$boundary . 'gzuncompress\('                 => 'gzuncompress()',
			$boundary . 'gzinflate\('                    => 'gzinflate()',
			$boundary . 'str_rot13\('                    => 'str_rot13()',
			$boundary . 'convert_uudecode\('             => 'convert_uudecode()',
			$boundary . 'create_function\('              => 'create_function()',
			$boundary . 'call_user_func\('               => 'call_user_func()',
			$boundary . 'assert\('                       => 'assert()',
			$boundary . '\$_POST\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\(' => 'Dynamic $_POST call',
			$boundary . '\$_GET\s*\[\s*[\'"]\s*[a-zA-Z0-9_\-]+\s*[\'"]\s*\]\s*\('  => 'Dynamic $_GET call',
			$boundary . 'c99shell'                       => 'C99 Webshell',
			$boundary . 'r57shell'                       => 'R57 Webshell',
			$boundary . 'b374k'                          => 'b374k Webshell',
			$boundary . 'wso_version'                    => 'WSO Webshell',
			$boundary . 'marvins'                        => 'Marvins Webshell',
			$boundary . 'alfa_data'                      => 'ALFA Webshell',
		);
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

		$suspicious_patterns = self::get_webshell_patterns();

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

		// Validasi path menggunakan realpath() untuk mencegah path traversal termasuk encoded atau double-slash
		$abs_path  = ABSPATH . $rel_path;
		$real_base = realpath( ABSPATH );
		$real_path = realpath( $abs_path );
		if ( ! $real_path ) {
			$quarantines = get_option( 'wp_root_guard_quarantined_folders', array() );
			if ( is_array( $quarantines ) ) {
				foreach ( $quarantines as $item ) {
					if ( isset( $item['quarantine_name'] ) && $item['quarantine_name'] === $rel_path ) {
						$resolved = self::resolve_quarantine_item_path( $item, $rel_path );
						if ( '' !== $resolved ) {
							$real_path = realpath( $resolved );
						}
						break;
					}
				}
			}
		}

		$inside_webroot = $real_base && $real_path && ( 0 === strpos( $real_path, rtrim( $real_base, '/\\' ) . DIRECTORY_SEPARATOR ) || $real_path === $real_base );
		$inside_vault = false;
		if ( $real_path && class_exists( __NAMESPACE__ . '\\QuarantineStorage' ) ) {
			$storage = QuarantineStorage::resolve_directory();
			$inside_vault = ! empty( $storage['directory'] ) && QuarantineStorage::is_path_within( $real_path, $storage['directory'], false );
		}

		if ( ! $real_path || ( ! $inside_webroot && ! $inside_vault ) || is_dir( $real_path ) ) {
			return array(
				'success' => false,
				'message' => esc_html__( 'Berkas tidak ditemukan atau path tidak valid.', 'wp-root-guard' ),
			);
		}
		$abs_path = $real_path;

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

		$patterns = self::get_webshell_patterns();

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
	 * Mendapatkan path absolut ke direktori karantina khusus dan memastikannya terlindungi.
	 *
	 * @return string Path absolut folder karantina.
	 */
	public static function get_quarantine_dir() {
		$storage = QuarantineStorage::resolve_directory();
		if ( 'ready' !== $storage['status'] || empty( $storage['directory'] ) ) {
			return '';
		}

		return trailingslashit( $storage['directory'] );
	}

	/**
	 * Resolve metadata path only inside the current or legacy known vault.
	 *
	 * @param array  $item Metadata item.
	 * @param string $name Quarantine item name.
	 * @return string Safe absolute path or empty string.
	 */
	private static function resolve_quarantine_item_path( $item, $name ) {
		$storage = class_exists( __NAMESPACE__ . '\\QuarantineStorage' ) ? QuarantineStorage::resolve_directory() : array();
		$allowed = array();
		if ( ! empty( $storage['directory'] ) ) {
			$allowed[] = $storage['directory'];
		}
		$legacy = str_replace( '\\', '/', WP_CONTENT_DIR . '/uploads/wp-root-guard-quarantine' );
		$allowed[] = $legacy;

		$candidate = isset( $item['quarantine_path'] ) ? (string) $item['quarantine_path'] : '';
		if ( '' === $candidate ) {
			$candidate = self::get_quarantine_dir() . ltrim( $name, '/\\' );
		}
		$candidate = str_replace( '\\', '/', $candidate );

		foreach ( $allowed as $base ) {
			if ( '' !== $base && QuarantineStorage::is_path_within( $candidate, $base, false ) ) {
				return $candidate;
			}
		}

		return '';
	}

	/**
	 * Melakukan karantina terhadap folder asing.
	 *
	 * @param string $folder Nama folder asing yang akan dikarantina.
	 * @return string|bool Nama folder karantina baru jika berhasil, false jika gagal.
	 */
	public static function quarantine_folder( $folder ) {
		$folder = sanitize_text_field( $folder );

		// Validasi path traversal (cek .., slash, whitelist regex, dan realpath)
		if ( empty( $folder ) || false !== strpos( $folder, '..' ) || false !== strpos( $folder, '/' ) || false !== strpos( $folder, '\\' ) ) {
			return false;
		}

		if ( ! preg_match( '/^[a-zA-Z0-9_.\-]+$/', $folder ) ) {
			return false;
		}

		$original_path = ABSPATH . $folder;
		$real_base     = realpath( ABSPATH );
		$real_path     = realpath( $original_path );

		if ( ! $real_base || ! $real_path || 0 !== strpos( $real_path, $real_base ) || $real_path === $real_base || ! is_dir( $real_path ) ) {
			return false;
		}

		if ( is_link( $original_path ) ) {
			return false;
		}

		$record = self::quarantine_validated_path( $real_path, $folder, 'folder' );
		if ( is_array( $record ) ) {

			Logger::log(
				esc_html__( 'Folder berhasil dikarantina otomatis', 'wp-root-guard' ),
				$folder,
				esc_html__( 'Quarantined', 'wp-root-guard' )
			);

			return $record['quarantine_name'];
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
		$filename = sanitize_text_field( $filename );

		// Validasi path traversal (cek .., slash, whitelist regex, dan realpath)
		if ( empty( $filename ) || false !== strpos( $filename, '..' ) || false !== strpos( $filename, '/' ) || false !== strpos( $filename, '\\' ) ) {
			return false;
		}

		if ( ! preg_match( '/^[a-zA-Z0-9_.\-]+$/', $filename ) ) {
			return false;
		}

		$original_path = ABSPATH . $filename;
		$real_base     = realpath( ABSPATH );
		$real_path     = realpath( $original_path );

		if ( ! $real_base || ! $real_path || 0 !== strpos( $real_path, $real_base ) || is_dir( $real_path ) ) {
			return false;
		}

		if ( dirname( $real_path ) !== $real_base ) {
			return false;
		}

		if ( is_link( $original_path ) ) {
			return false;
		}

		$record = self::quarantine_validated_path( $real_path, $filename, 'file' );
		if ( is_array( $record ) ) {

			Logger::log(
				esc_html__( 'Berkas berhasil dikarantina otomatis', 'wp-root-guard' ),
				$filename,
				esc_html__( 'Quarantined', 'wp-root-guard' )
			);

			return $record['quarantine_name'];
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
		$rel_path = sanitize_text_field( $rel_path );
		$rel_path = str_replace( '\\', '/', $rel_path );

		// Validasi path traversal (cek .., slash tidak valid, whitelist regex, dan realpath)
		if ( empty( $rel_path ) || false !== strpos( $rel_path, '..' ) || 0 === strpos( $rel_path, '/' ) || false !== strpos( $rel_path, '//' ) ) {
			return false;
		}

		if ( ! preg_match( '/^[a-zA-Z0-9_.\-\/]+$/', $rel_path ) ) {
			return false;
		}

		$original_path = ABSPATH . $rel_path;
		$real_base     = realpath( ABSPATH );
		$real_path     = realpath( $original_path );

		if ( ! $real_base || ! $real_path || 0 !== strpos( $real_path, $real_base ) || $real_path === $real_base || is_dir( $real_path ) ) {
			return false;
		}

		if ( is_link( $original_path ) ) {
			return false;
		}

		$record = self::quarantine_validated_path( $real_path, $rel_path, 'file' );
		if ( is_array( $record ) ) {

			Logger::log(
				esc_html__( 'Berkas penyusup core berhasil dikarantina otomatis', 'wp-root-guard' ),
				$rel_path,
				esc_html__( 'Quarantined', 'wp-root-guard' )
			);

			return $record['quarantine_name'];
		}

		return false;
	}

	/**
	 * Commit a validated target to the vault and retain legacy display metadata.
	 * The database record is authoritative; the option remains for existing
	 * dashboard rendering until its UI is migrated to quarantine IDs.
	 *
	 * @param string $path Canonical source path.
	 * @param string $name Original relative name.
	 * @param string $type file or folder.
	 * @return array|false
	 */
	private static function quarantine_validated_path( $path, $name, $type ) {
		if ( ! class_exists( __NAMESPACE__ . '\\QuarantineManager' ) ) {
			return false;
		}
		$record = QuarantineManager::quarantine( $path, $name, $type );
		if ( is_wp_error( $record ) || ! is_array( $record ) ) {
			return false;
		}

		$quarantines = get_option( 'wp_root_guard_quarantined_folders', array() );
		$quarantines = is_array( $quarantines ) ? $quarantines : array();
		$quarantines[] = array(
			'id'              => $record['id'],
			'type'            => $record['type'],
			'original_name'   => $name,
			'quarantine_name' => $record['quarantine_name'],
			'original_path'   => $record['original_path'],
			'quarantine_path' => $record['quarantine_path'],
			'quarantine_time' => self::get_wib_time(),
			'sha256'          => $record['sha256'],
			'storage_id'      => hash( 'sha256', $record['storage_directory'] ),
		);
		update_option( 'wp_root_guard_quarantined_folders', $quarantines, false );
		return $record;
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

		// Validasi realpath untuk cegah path traversal (termasuk encoded dan double-slash)
		$real_base = realpath( ABSPATH );
		$real_file = realpath( $file_path );
		if ( ! $real_base || ! $real_file || 0 !== strpos( $real_file, $real_base ) || is_dir( $real_file ) ) {
			return false;
		}
		$file_path = $real_file;

		if ( @unlink( $file_path ) || ( function_exists( 'wp_delete_file' ) && wp_delete_file( $file_path ) ) ) {
			// Hapus dari daftar aktif yang terdeteksi di database.
			$unknown_folders = get_option( 'wp_root_guard_unknown_folders', array() );
			if ( is_array( $unknown_folders ) ) {
				foreach ( $unknown_folders as $key => $file ) {
					if ( isset( $file['name'] ) && $file['name'] === $rel_path ) {
						unset( $unknown_folders[ $key ] );
					}
				}
				$unknown_folders = array_values( $unknown_folders );
				update_option( 'wp_root_guard_unknown_folders', $unknown_folders );

				$last_scan = get_option( 'wp_root_guard_last_scan', array() );
				if ( is_array( $last_scan ) ) {
					$last_scan['unknown_count']   = count( $unknown_folders );
					$last_scan['unknown_folders'] = $unknown_folders;
					$last_scan['status']          = empty( $unknown_folders ) ? 'pending' : 'threat';
					$last_scan['security_status'] = empty( $unknown_folders ) ? ScanResult::SECURITY_PENDING : ScanResult::SECURITY_THREAT;
					$last_scan['coverage_status'] = empty( $unknown_folders ) ? ScanResult::COVERAGE_DEGRADED : ( isset( $last_scan['coverage_status'] ) ? $last_scan['coverage_status'] : ScanResult::COVERAGE_DEGRADED );
					$last_scan['execution_state'] = ScanResult::EXECUTION_DEFERRED;
					update_option( 'wp_root_guard_last_scan', $last_scan );
				}
			}

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
		$quarantine_path = self::resolve_quarantine_item_path( $item, $quarantine_name );
		if ( '' === $quarantine_path ) {
			return false;
		}
		$original_path   = ABSPATH . $item['original_name'];
		$type            = isset( $item['type'] ) ? $item['type'] : 'folder';
		$original_name   = str_replace( '\\', '/', (string) $item['original_name'] );
		if ( '' === $original_name || false !== strpos( $original_name, '..' ) || 0 === strpos( $original_name, '/' ) || false !== strpos( $original_name, '//' ) ) {
			return false;
		}

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
			if ( ! empty( $item['sha256'] ) && ! hash_equals( (string) $item['sha256'], (string) @hash_file( 'sha256', $quarantine_path ) ) ) {
				Logger::log( esc_html__( 'Restore ditolak karena checksum item karantina berubah', 'wp-root-guard' ), $original_name, esc_html__( 'Checksum Failed', 'wp-root-guard' ) );
				return false;
			}
		}

		// Pastikan direktori tujuan ada (berguna jika karantina berasal dari subfolder core)
		$dir = dirname( $original_path );
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}

		if ( @rename( $quarantine_path, $original_path ) ) {
			// PHP di uploads tidak boleh otomatis masuk whitelist saat dipulihkan.
			// Jika memang legitimate, admin harus memilih "Trust File" secara sadar.
			$is_uploads_executable = (bool) preg_match(
				'/^wp-content\/uploads\/.*\.(php|phtml|php3|php4|php5|php7|phps|phar|inc)$/i',
				(string) $item['original_name']
			);
			if ( ! $is_uploads_executable ) {
				Settings::add_to_whitelist( $item['original_name'] );
			}

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
		$quarantine_path = self::resolve_quarantine_item_path( $item, $quarantine_name );
		if ( '' === $quarantine_path ) {
			return false;
		}
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
		if ( ! is_dir( $dir ) || is_link( $dir ) ) {
			if ( is_link( $dir ) ) {
				return @unlink( $dir );
			}
			return false;
		}

		$files = array_diff( scandir( $dir ), array( '.', '..' ) );
		foreach ( $files as $file ) {
			$item = "$dir/$file";
			if ( is_link( $item ) ) {
				@unlink( $item );
			} elseif ( is_dir( $item ) ) {
				self::recursive_delete_dir( $item );
			} else {
				@unlink( $item );
			}
		}

		return @rmdir( $dir );
	}

	/**
	 * Mengirim notifikasi email dan Telegram jika ada ancaman baru yang belum dinotifikasi.
	 *
	 * @param array $threats Daftar ancaman terdeteksi saat ini.
	 */
	/**
	 * Send deduplicated notifications after a batch run has fully finalized.
	 *
	 * @param array $threats Final finding list.
	 * @return void
	 */
	public static function notify_scan_findings( $threats ) {
		self::handle_threat_notifications( is_array( $threats ) ? $threats : array() );
	}

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
		// Bangun daftar key ancaman yang aktif saat ini
		$active_keys = array();
		foreach ( $threats as $threat ) {
			if ( is_array( $threat ) && isset( $threat['type'], $threat['name'] ) ) {
				$active_keys[] = self::get_threat_notification_key( $threat );
			}
		}

		// Clean $notified agar hanya berisi string saja (cegah TypeError array to string conversion)
		$clean_notified = array();
		foreach ( $notified as $item ) {
			if ( is_string( $item ) ) {
				$clean_notified[] = $item;
			}
		}

		// Bersihkan key notifikasi lama yang ancamannya sudah tidak aktif
		// agar ancaman baru yang muncul menggantikan ancaman lama tetap dinotifikasi
		$notified = array_intersect( $clean_notified, $active_keys );

		foreach ( $threats as $threat ) {
			$threat_key = self::get_threat_notification_key( $threat );
			if ( ! in_array( $threat_key, $notified, true ) ) {
				$new_threats[] = $threat;
			}
		}

		if ( empty( $new_threats ) ) {
			return;
		}

		$site_name = get_bloginfo( 'name' );
		$site_url  = home_url();
		$count     = count( $new_threats );
		$delivery_success = false;

		// 1. Kirim Email jika aktif
		if ( $settings['enable_email_notifications'] && ! empty( $settings['admin_email'] ) ) {
			$subject = sprintf( /* translators: %s: nama situs */ esc_html__( '[WP Root Guard] Ancaman Keamanan Baru di %s', 'wp-root-guard' ), $site_name );

			$email_body  = esc_html__( 'Halo Administrator,', 'wp-root-guard' ) . "\r\n\r\n";
			$email_body .= sprintf( /* translators: %1$d: jumlah temuan, %2$s: URL situs */ esc_html__( 'WP Root Guard mendeteksi %1$d berkas/folder asing atau dimodifikasi baru pada root directory situs Anda (%2$s):', 'wp-root-guard' ), $count, $site_url ) . "\r\n\r\n";

			foreach ( $new_threats as $threat ) {
				$type_label   = ( 'folder' === $threat['type'] ) ? esc_html__( 'Folder Asing', 'wp-root-guard' ) : ( 'uploads_php' === $threat['type'] ? esc_html__( 'PHP di Folder Uploads', 'wp-root-guard' ) : esc_html__( 'Berkas/Integritas Core', 'wp-root-guard' ) );
				$status_label = ( __( 'Quarantined Automatically', 'wp-root-guard' ) === $threat['status'] ) ? esc_html__( 'Sudah Dikarantina Otomatis', 'wp-root-guard' ) : esc_html__( 'Belum Dikarantina', 'wp-root-guard' );
				
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

			$email_sent = wp_mail( $settings['admin_email'], $subject, $email_body );
			if ( $email_sent ) {
				$delivery_success = true;
			} else {
				Logger::log(
					esc_html__( 'Notifikasi email gagal dikirim', 'wp-root-guard' ),
					$settings['admin_email'],
					esc_html__( 'Error', 'wp-root-guard' )
				);
			}
		}

		// 2. Kirim Telegram jika aktif
		if ( $settings['enable_telegram_notifications'] && ! empty( $settings['telegram_bot_token'] ) && ! empty( $settings['telegram_chat_id'] ) ) {
			$safe_site_name = self::escape_telegram_markdown( $site_name );
			$tg_msg  = "⚠️ *[WP Root Guard] Ancaman Baru Terdeteksi!*\n\n";
			$tg_msg .= "Situs: *{$safe_site_name}* ({$site_url})\n";
			$tg_msg .= "Ditemukan *{$count}* berkas/folder baru/dimodifikasi:\n\n";

			foreach ( $new_threats as $threat ) {
				$type_icon    = ( 'folder' === $threat['type'] ) ? "📂" : "📄";
				$status_label = ( __( 'Quarantined Automatically', 'wp-root-guard' ) === $threat['status'] ) ? "🔒 _Sudah Dikarantina_" : "⚠️ *Belum Dikarantina*";
				
				$safe_name = self::escape_telegram_markdown( $threat['name'] );
				$safe_path = self::escape_telegram_markdown( $threat['path'] );

				$tg_msg .= "{$type_icon} *Nama*: `{$safe_name}`\n";
				$tg_msg .= "📍 *Path*: `{$safe_path}`\n";
				$tg_msg .= "🛡️ *Status*: {$status_label}\n";
				if ( '-' !== $threat['malware_indicator'] ) {
					$safe_indicator = self::escape_telegram_markdown( $threat['malware_indicator'] );
					$tg_msg .= "💀 *Indikasi*: `{$safe_indicator}`\n";
				}
				$tg_msg .= "⏱️ *Waktu*: {$threat['detection_time']}\n\n";
			}

			$tg_msg .= "🔗 [Buka Dashboard Root Guard](" . admin_url( 'index.php?page=wp-root-guard' ) . ")";

			if ( self::send_telegram_message( $settings['telegram_bot_token'], $settings['telegram_chat_id'], $tg_msg ) ) {
				$delivery_success = true;
			}
		}

		// Tandai hanya setelah minimal satu kanal benar-benar berhasil.
		// Jika semua kanal gagal, scan berikutnya akan mencoba lagi.
		if ( $delivery_success ) {
			foreach ( $new_threats as $threat ) {
				$notified[] = self::get_threat_notification_key( $threat );
			}
			update_option( 'wp_root_guard_notified_threats', array_values( array_unique( $notified ) ), false );
		}
	}

	/**
	 * Membuat identifier notifikasi yang berubah jika isi file berubah.
	 *
	 * @param array $threat Data ancaman.
	 * @return string Identifier stabil untuk anti-spam.
	 */
	private static function get_threat_notification_key( $threat ) {
		$type = isset( $threat['type'] ) ? (string) $threat['type'] : 'unknown';
		$name = isset( $threat['name'] ) ? (string) $threat['name'] : 'unknown';
		$key  = $type . ':' . $name;
		$path = isset( $threat['path'] ) ? (string) $threat['path'] : '';

		if ( $path && is_file( $path ) && is_readable( $path ) ) {
			$hash = @hash_file( 'sha256', $path );
			if ( $hash ) {
				$key .= ':' . $hash;
			}
		}

		return $key;
	}

	/**
	 * Melakukan escape terhadap karakter kontrol format Markdown Telegram (legacy mode).
	 *
	 * @param string $text Teks yang akan di-escape.
	 * @return string Teks yang sudah aman untuk parser Markdown Telegram.
	 */
	public static function escape_telegram_markdown( $text ) {
		if ( empty( $text ) ) {
			return '';
		}

		return str_replace(
			array( '_', '*', '`', '[' ),
			array( '\_', '\*', '\`', '\[' ),
			(string) $text
		);
	}

	/**
	 * Mengirim pesan HTTP POST ke API Telegram Bot.
	 *
	 * @param string $token Bot token Telegram.
	 * @param string $chat_id Chat ID Telegram.
	 * @param string $message Pesan yang akan dikirim.
	 * @return bool True jika berhasil terkirim.
	 */
	public static function send_telegram_message( $token, $chat_id, $message ) {
		$token   = trim( $token );
		$chat_id = trim( $chat_id );

		if ( empty( $token ) || empty( $chat_id ) || empty( $message ) ) {
			return false;
		}

		$url  = "https://api.telegram.org/bot{$token}/sendMessage";
		$body = array(
			'chat_id'                  => $chat_id,
			'text'                     => $message,
			'parse_mode'               => 'Markdown',
			'disable_web_page_preview' => true,
		);

		$args = array(
			'body'        => $body,
			'timeout'     => 15,
			'redirection' => 5,
			'blocking'    => true,
			'headers'     => array(
				'Content-Type' => 'application/x-www-form-urlencoded',
			),
			'sslverify'   => true,
		);

		$response = wp_remote_post( $url, $args );

		if ( is_wp_error( $response ) ) {
			Logger::log(
				esc_html__( 'Gagal mengontak API Telegram', 'wp-root-guard' ),
				$response->get_error_message(),
				esc_html__( 'Error', 'wp-root-guard' )
			);
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 === $code ) {
			return true;
		}

		$response_body = wp_remote_retrieve_body( $response );
		Logger::log(
			esc_html__( 'Respon error dari API Telegram', 'wp-root-guard' ),
			'HTTP ' . $code . ': ' . substr( $response_body, 0, 100 ),
			esc_html__( 'Error', 'wp-root-guard' )
		);

		return false;
	}

	/**
	 * Mengambil data pemindaian terakhir.
	 *
	 * @return array Hasil pemindaian terakhir.
	 */
	public static function get_last_scan_results() {
		$default = array(
			'last_scan'       => '',
			'status'          => 'pending',
			'security_status' => ScanResult::SECURITY_PENDING,
			'coverage_status' => ScanResult::COVERAGE_DEGRADED,
			'execution_state' => ScanResult::EXECUTION_DEFERRED,
			'unknown_count'   => 0,
			'unknown_folders' => array(),
		);

		$results = get_option( 'wp_root_guard_last_scan', $default );
		return ScanResult::normalize( is_array( $results ) ? $results : $default );
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

		// Path folder karantina dan folder data baseline plugin — dieksklusi dari pemindaian agar tidak false positive
		$storage = class_exists( __NAMESPACE__ . '\\QuarantineStorage' ) ? QuarantineStorage::resolve_directory() : array();
		$quarantine_path = isset( $storage['directory'] ) ? str_replace( '\\', '/', $storage['directory'] ) : '';
		$baseline_path   = class_exists( __NAMESPACE__ . '\\Baseline' )
			? str_replace( '\\', '/', Baseline::get_baseline_dir() )
			: str_replace( '\\', '/', WP_CONTENT_DIR . '/uploads/wp-root-guard' );

		try {
			$directory = new \RecursiveDirectoryIterator( $base_dir, \RecursiveDirectoryIterator::SKIP_DOTS );
			$iterator  = new \RecursiveIteratorIterator( $directory, \RecursiveIteratorIterator::SELF_FIRST );

			foreach ( $iterator as $item ) {
				if ( $item->isFile() ) {
					$abs_path = str_replace( '\\', '/', $item->getPathname() );

					// Lewati semua berkas di dalam folder karantina dan folder baseline plugin
					if ( 0 === strpos( $abs_path, $quarantine_path ) || ( ! empty( $baseline_path ) && 0 === strpos( $abs_path, $baseline_path ) ) ) {
						continue;
					}

					$ext = strtolower( pathinfo( $item->getFilename(), PATHINFO_EXTENSION ) );
					if ( in_array( $ext, array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'inc' ), true ) ) {
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
			self::$scope_errors[] = 'uploads_iterator:' . sanitize_key( $e->getMessage() );
			return new \WP_Error( 'uploads_iterator_failed', $e->getMessage() );
		}

		return $php_files;
	}
}
