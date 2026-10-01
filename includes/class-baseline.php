<?php
/**
 * Pengelola baseline integritas direktori dan berkas root WordPress.
 *
 * Berkas ini berisi class Baseline yang bertanggung jawab untuk:
 * 1. Membuat golden baseline snapshot (folder dan berkas root ABSPATH beserta MD5).
 * 2. Mengamankan berkas baseline menggunakan HMAC-SHA256 untuk proteksi anti-tampering.
 * 3. Memverifikasi integritas berkas baseline sebelum dibaca oleh Scanner.
 * 4. Memindai direktori dan berkas root secara non-rekursif dengan proteksi symlink & limit ukuran berkas (DoS prevention).
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
 * Class Baseline
 *
 * Mengelola berkas baseline.json di direktori wp-content/uploads/wp-root-guard/.
 * Menyimpan snapshot kondisi awal website dengan verifikasi HMAC kriptografis.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Baseline {

	/**
	 * Nama berkas penyimpanan snapshot baseline.
	 */
	const BASELINE_FILENAME = 'baseline.json';

	/** Candidate baseline awaiting explicit administrator approval. */
	const PENDING_FILENAME = 'baseline-pending.json';

	/**
	 * Nama direktori penyimpanan baseline di dalam direktori uploads WordPress.
	 */
	const BASELINE_DIRNAME = 'wp-root-guard';

	/**
	 * Nama berkas lock eksklusif untuk mencegah race condition.
	 */
	const LOCK_FILENAME = '.baseline.lock';

	/**
	 * Cache in-memory untuk baseline dalam satu request PHP.
	 *
	 * @var array|null
	 */
	private static $memory_cache = null;

	/**
	 * Context salt untuk signing HMAC berkas baseline.
	 */
	const HMAC_CONTEXT = 'wp_root_guard_baseline';

	/**
	 * Batas maksimal ukuran berkas root yang dipindai (5 MB dalam bytes).
	 * Mencegah exhaustion memori dan DoS akibat pemrosesan berkas raksasa.
	 */
	const MAX_FILE_SIZE = 5242880;

	/**
	 * Mendapatkan path absolut ke direktori penyimpanan baseline.
	 * Otomatis membuat folder dan berkas index.php kosong jika belum ada demi keamanan.
	 *
	 * @return string Path direktori baseline, atau string kosong jika wp_upload_dir gagal.
	 */
	public static function get_baseline_dir() {
		$uploads = wp_upload_dir();
		$dir     = isset( $uploads['basedir'] ) ? rtrim( $uploads['basedir'], '/\\' ) . '/' . self::BASELINE_DIRNAME : '';

		if ( empty( $dir ) ) {
			return '';
		}

		// Buat folder jika belum ada.
		if ( ! file_exists( $dir ) ) {
			if ( function_exists( 'wp_mkdir_p' ) ) {
				wp_mkdir_p( $dir );
			} else {
				@mkdir( $dir, 0755, true );
			}
		}

		// Tambahkan berkas index.php kosong demi keamanan (directory listing prevention).
		$index_file = $dir . '/index.php';
		if ( is_dir( $dir ) && ! file_exists( $index_file ) ) {
			if ( class_exists( __NAMESPACE__ . '\\AtomicWriter' ) ) {
				AtomicWriter::write( $index_file, "<?php\n// Silence is golden.\n", 0644 );
			}
		}

		return $dir;
	}

	/**
	 * Mendapatkan path absolut ke berkas baseline.json.
	 *
	 * @return string Path berkas baseline.json, atau string kosong jika direktori tidak tersedia.
	 */
	public static function get_baseline_file() {
		$dir = self::get_baseline_dir();
		return ! empty( $dir ) ? $dir . '/' . self::BASELINE_FILENAME : '';
	}

	/**
	 * Alias backward-compatible untuk get_baseline_file().
	 *
	 * @return string Path berkas baseline.json.
	 */
	public static function get_baseline_path() {
		return self::get_baseline_file();
	}

	/** @return string Pending baseline path. */
	public static function get_pending_baseline_path() {
		$dir = self::get_baseline_dir();
		return ! empty( $dir ) ? $dir . '/' . self::PENDING_FILENAME : '';
	}

	/**
	 * Mendapatkan path berkas lock eksklusif untuk operasi baseline.
	 *
	 * @return string Path berkas lock.
	 */
	public static function get_lock_file() {
		$dir = self::get_baseline_dir();
		return ! empty( $dir ) ? $dir . '/' . self::LOCK_FILENAME : '';
	}

	/**
	 * Menghapus cache transient checksums resmi WordPress.org.
	 * Kompatibel dengan Single Site dan Multisite Network.
	 *
	 * @return void
	 */
	public static function invalidate_checksums_cache() {
		delete_transient( 'wp_root_guard_core_checksums' );
		if ( is_multisite() ) {
			delete_site_transient( 'wp_root_guard_core_checksums' );
		}
		if ( class_exists( '\WPRootGuard\Scanner' ) && method_exists( '\WPRootGuard\Scanner', 'invalidate_core_checksums_cache' ) ) {
			\WPRootGuard\Scanner::invalidate_core_checksums_cache();
		}
	}

	/**
	 * Mendapatkan versi WordPress saat ini secara andal.
	 *
	 * @return string Versi WP string.
	 */
	public static function get_current_wp_version() {
		global $wp_version;
		if ( ! empty( $wp_version ) ) {
			return (string) $wp_version;
		}
		if ( function_exists( 'get_bloginfo' ) ) {
			return (string) get_bloginfo( 'version' );
		}
		return '';
	}

	/**
	 * Reset/invalidation cache in-memory baseline.
	 */
	public static function clear_memory_cache() {
		self::$memory_cache = null;
	}

	/**
	 * Handler publik saat event core update dipicu dari hook listener.
	 *
	 * @param string $new_version Versi WordPress target baru.
	 * @param string $source      Sumber pemicu (contoh: hook, cli).
	 * @return bool True jika baseline berhasil disinkronkan.
	 */
	public static function handle_core_update( $new_version = '', $source = 'hook' ) {
		// A core update changes official checksums, not the trusted root
		// filesystem baseline. Rebuilding here could bless a compromised root.
		self::invalidate_checksums_cache();
		Logger::log( __( 'Core WordPress diperbarui; baseline root tidak diubah dan menunggu review administrator.', 'wp-root-guard' ), sanitize_text_field( $source ), 'Info' );
		return true;
	}

	/**
	 * Membuat baseline dari folder dan berkas root saat ini.
	 *
	 * @return bool True jika baseline berhasil ditulis, false jika gagal.
	 */
	public static function create_baseline() {
		return is_array( self::generate_pending_baseline( 'manual' ) );
	}

	/** Build a signed candidate only; it cannot be used as an active baseline. */
	public static function generate_pending_baseline( $run_id = '' ) {
		self::clear_memory_cache();
		$data = array(
			'created_at' => current_time( 'mysql' ),
			'wp_version' => self::get_current_wp_version(),
			'folders'    => self::scan_root_folders(),
			'files'      => self::scan_root_files(),
			'run_id'     => sanitize_text_field( $run_id ),
			'kind'       => 'pending',
		);
		$data['hmac'] = self::sign( $data );
		$json = wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		$written = AtomicWriter::write( self::get_pending_baseline_path(), $json, 0600 );
		if ( is_wp_error( $written ) ) {
			Logger::log( __( 'Gagal menulis kandidat baseline', 'wp-root-guard' ), $written->get_error_code(), 'Error' );
			return false;
		}
		Logger::log( __( 'Kandidat baseline dibuat dan menunggu persetujuan administrator', 'wp-root-guard' ), '-', 'Pending Approval' );
		return $data;
	}

	/** Read and HMAC-verify pending candidate. */
	public static function read_pending_baseline() {
		$path = self::get_pending_baseline_path();
		$content = $path ? @file_get_contents( $path ) : false;
		$data = is_string( $content ) ? json_decode( $content, true ) : array();
		return is_array( $data ) && 'pending' === ( $data['kind'] ?? '' ) && self::verify( $data ) ? $data : array();
	}

	/** Freshly scan and atomically promote a candidate approved by an admin. */
	public static function approve_pending_baseline() {
		$pending = self::read_pending_baseline();
		if ( empty( $pending ) ) {
			return new \WP_Error( 'baseline_pending_invalid', __( 'Kandidat baseline tidak tersedia atau integritasnya gagal.', 'wp-root-guard' ) );
		}
		if ( ! class_exists( __NAMESPACE__ . '\\Scanner' ) ) {
			return new \WP_Error( 'baseline_scanner_missing', __( 'Scanner tidak tersedia untuk verifikasi baseline.', 'wp-root-guard' ) );
		}
		$result = Scanner::perform_scan( 'baseline_approval' );
		if ( 'safe' !== ( $result['security_status'] ?? '' ) || 'complete' !== ( $result['coverage_status'] ?? '' ) || 'completed' !== ( $result['execution_state'] ?? '' ) || ! empty( $result['unknown_count'] ) ) {
			return new \WP_Error( 'baseline_scan_not_clean', __( 'Persetujuan ditolak: scan verifikasi tidak lengkap atau masih memiliki temuan.', 'wp-root-guard' ) );
		}
		$current = array(
			'folders' => self::scan_root_folders(),
			'files'   => self::scan_root_files(),
		);
		if ( wp_json_encode( $pending['folders'] ) !== wp_json_encode( $current['folders'] ) || wp_json_encode( $pending['files'] ) !== wp_json_encode( $current['files'] ) ) {
			return new \WP_Error( 'baseline_candidate_stale', __( 'Kandidat baseline berubah sejak dibuat; buat kandidat baru setelah review.', 'wp-root-guard' ) );
		}
		$active = array(
			'created_at' => current_time( 'mysql' ),
			'wp_version' => self::get_current_wp_version(),
			'folders'    => $current['folders'],
			'files'      => $current['files'],
			'approved_run_id' => sanitize_text_field( $pending['run_id'] ?? '' ),
			'approved_by' => get_current_user_id(),
		);
		$active['hmac'] = self::sign( $active );
		$written = AtomicWriter::write( self::get_baseline_path(), wp_json_encode( $active, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ), 0600 );
		if ( is_wp_error( $written ) ) {
			return $written;
		}
		@unlink( self::get_pending_baseline_path() );
		self::$memory_cache = $active;
		Logger::log( __( 'Baseline root disetujui administrator setelah scan verifikasi bersih', 'wp-root-guard' ), '-', 'Approved' );
		return true;
	}

	/**
	 * Membaca dan memverifikasi integritas berkas baseline.json.
	 * Dilengkapi deteksi fallback versi WordPress core.
	 *
	 * @param bool $skip_fallback Set true untuk menonaktifkan pengecekan fallback (mencegah loop rekursif).
	 * @return array Data snapshot baseline jika valid, atau array kosong jika tidak valid/tampered.
	 */
	public static function read_baseline( $skip_fallback = false ) {
		// Gunakan cache in-memory jika tersedia
		if ( null !== self::$memory_cache && ! $skip_fallback ) {
			return self::$memory_cache;
		}

		$file_path = self::get_baseline_file();
		if ( empty( $file_path ) || ! file_exists( $file_path ) ) {
			return array();
		}

		$content = @file_get_contents( $file_path );
		if ( false === $content || '' === trim( $content ) ) {
			return array();
		}

		$data = json_decode( $content, true );

		// 1. Verifikasi integritas kriptografis HMAC terlebih dahulu (OWASP A08:2021).
		if ( ! is_array( $data ) || ! self::verify( $data ) ) {
			Logger::log(
				__( 'Integritas berkas baseline gagal diverifikasi: berkas telah dimodifikasi atau HMAC tidak valid', 'wp-root-guard' ),
				self::BASELINE_FILENAME,
				'Tampered'
			);
			return array();
		}

		self::$memory_cache = $data;
		return $data;
	}

	/**
	 * Melakukan sinkronisasi baseline saat versi WordPress core berubah.
	 * Menggunakan Double-Checked Locking dengan file lock eksklusif untuk mencegah race condition.
	 *
	 * @param string $new_version Versi WordPress target.
	 * @param string $source      Sumber pemicu sinkronisasi ('hook' atau 'fallback_version_detection').
	 * @param string $old_version Versi sebelumnya (opsional).
	 * @return array|false Data snapshot baseline baru, atau false jika gagal.
	 */
	public static function sync_baseline_version( $new_version, $source = 'hook', $old_version = '' ) {
		// Core version changes must never rewrite the trusted root inventory.
		if ( 'manual_create' !== $source ) {
			self::invalidate_checksums_cache();
			return self::read_baseline( true );
		}
		$lock_file = self::get_lock_file();
		if ( empty( $lock_file ) ) {
			return false;
		}

		$lock_fp = @fopen( $lock_file, 'c+' );
		if ( ! $lock_fp ) {
			return false;
		}

		// Dapatkan exclusive lock (blocking dengan aman)
		if ( ! @flock( $lock_fp, LOCK_EX ) ) {
			@fclose( $lock_fp );
			return false;
		}

		try {
			// DOUBLE-CHECK PATTERN: Baca kembali file dari disk setelah lock berhasil diperoleh.
			// Mencegah duplicate rebuild jika proses concurrent lain baru saja menyelesaikannya.
			$fresh_data = self::read_baseline( true ); // true = skip_fallback untuk mencegah loop

			if ( ! empty( $fresh_data )
				&& isset( $fresh_data['wp_version'] )
				&& $fresh_data['wp_version'] === $new_version
				&& 'manual_create' !== $source ) {
				
				// Baseline sudah diperbarui oleh proses lain! Invalidate cache & return.
				self::$memory_cache = $fresh_data;
				@flock( $lock_fp, LOCK_UN );
				@fclose( $lock_fp );
				return $fresh_data;
			}

			if ( empty( $old_version ) && isset( $fresh_data['wp_version'] ) ) {
				$old_version = (string) $fresh_data['wp_version'];
			}

			// Jalankan Rebuild Snapshot Root
			$folders = self::scan_root_folders();
			$files   = self::scan_root_files();

			$new_data = array(
				'created_at' => function_exists( 'current_time' ) ? current_time( 'mysql' ) : gmdate( 'Y-m-d H:i:s' ),
				'wp_version' => $new_version,
				'folders'    => $folders,
				'files'      => $files,
				'kind'       => 'pending',
			);

			// Tanda tangani dengan HMAC-SHA256
			$new_data['hmac'] = self::sign( $new_data );

			$json_data = function_exists( 'wp_json_encode' )
				? wp_json_encode( $new_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES )
				: json_encode( $new_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

			$target_file = self::get_pending_baseline_path();
			$written     = class_exists( __NAMESPACE__ . '\\AtomicWriter' )
				? AtomicWriter::write( $target_file, $json_data, 0600 )
				: new \WP_Error( 'atomic_writer_missing', __( 'Atomic writer tidak tersedia.', 'wp-root-guard' ) );

			if ( false === $written || is_wp_error( $written ) ) {
				Logger::log(
					sprintf(
						/* translators: %s: versi wordpress */
						esc_html__( 'Gagal menulis berkas baseline baru setelah core update ke versi %s', 'wp-root-guard' ),
						$new_version
					),
					self::BASELINE_FILENAME,
					'Warning'
				);
				@flock( $lock_fp, LOCK_UN );
				@fclose( $lock_fp );
				return false;
			}

			// Invalidate transient checksums resmi
			self::invalidate_checksums_cache();

			// Invalidate & perbarui in-memory cache
			self::$memory_cache = $new_data;

			// Audit logging (jika bukan manual_create awal)
			if ( 'manual_create' !== $source ) {
				$log_message = sprintf(
					/* translators: 1: versi lama, 2: versi baru, 3: pemicu */
					esc_html__( 'WordPress core diperbarui dari v%1$s ke v%2$s (pemicu: %3$s). Baseline dan cache checksums otomatis diperbarui.', 'wp-root-guard' ),
					! empty( $old_version ) ? $old_version : esc_html__( 'tidak diketahui', 'wp-root-guard' ),
					$new_version,
					$source
				);
				Logger::log( $log_message, 'WordPress Core', 'Safe' );
			}

			@flock( $lock_fp, LOCK_UN );
			@fclose( $lock_fp );

			return $new_data;

		} catch ( \Exception $e ) {
			@flock( $lock_fp, LOCK_UN );
			@fclose( $lock_fp );
			return false;
		}
	}

	/**
	 * Membaca daftar folder baseline yang telah terverifikasi.
	 *
	 * @return array Daftar nama folder baseline, atau array kosong jika belum ada/tampered.
	 */
	public static function get_baseline_folders() {
		$data = self::read_baseline();
		return ( isset( $data['folders'] ) && is_array( $data['folders'] ) ) ? $data['folders'] : array();
	}

	/**
	 * Membaca daftar berkas beserta MD5 hash baseline yang telah terverifikasi.
	 *
	 * @return array Asosiatif array berkas rujukan (nama_berkas => hash_md5), atau array kosong jika belum ada/tampered.
	 */
	public static function get_baseline_files() {
		$data = self::read_baseline();
		return ( isset( $data['files'] ) && is_array( $data['files'] ) ) ? $data['files'] : array();
	}

	/**
	 * Memindai folder di root (ABSPATH) secara non-rekursif.
	 *
	 * Proteksi keamanan:
	 * 1. Mengabaikan symlink (is_link) untuk mencegah symlink traversal attack.
	 * 2. Mengabaikan entri direktori '.' dan '..'.
	 * 3. Mengabaikan direktori karantina internal (__quarantine_*).
	 *
	 * @return array Daftar nama direktori level pertama di root WordPress terurut alfabetis.
	 */
	public static function scan_root_folders() {
		$folders = array();
		$path    = defined( 'ABSPATH' ) ? ABSPATH : '';

		if ( empty( $path ) || ! is_dir( $path ) ) {
			return $folders;
		}

		try {
			$iterator = new \DirectoryIterator( $path );
			foreach ( $iterator as $fileinfo ) {
				// Lewati dot entries (. dan ..).
				if ( $fileinfo->isDot() || '.' === $fileinfo->getFilename() || '..' === $fileinfo->getFilename() ) {
					continue;
				}

				$pathname = $fileinfo->getPathname();

				// Lewati symlink untuk mencegah symlink traversal attack.
				if ( is_link( $pathname ) || $fileinfo->isLink() ) {
					continue;
				}

				if ( $fileinfo->isDir() ) {
					$foldername = $fileinfo->getFilename();

					// Abaikan folder karantina internal plugin.
					if ( 0 === strpos( $foldername, '__quarantine_' ) ) {
						continue;
					}

					$folders[] = $foldername;
				}
			}
		} catch ( \Exception $e ) {
			// Abaikan exception filesystem iterator.
		}

		sort( $folders );
		return array_values( array_unique( $folders ) );
	}

	/**
	 * Memindai berkas di root (ABSPATH) secara non-rekursif dan menghitung hash MD5.
	 *
	 * Proteksi keamanan:
	 * 1. Mengabaikan symlink (is_link) untuk mencegah symlink traversal / arbitrary read.
	 * 2. Mengabaikan berkas berukuran > 5 MB (MAX_FILE_SIZE) untuk mencegah DoS & memory exhaustion.
	 * 3. Mengabaikan berkas internal plugin (wp-root-guard.zip, __quarantine_*).
	 *
	 * @return array Asosiatif array berkas rujukan (nama_berkas => hash_md5) terurut alfabetis berdasarkan nama berkas.
	 */
	public static function scan_root_files() {
		$files = array();
		$path  = defined( 'ABSPATH' ) ? ABSPATH : '';

		if ( empty( $path ) || ! is_dir( $path ) ) {
			return $files;
		}

		try {
			$iterator = new \DirectoryIterator( $path );
			foreach ( $iterator as $fileinfo ) {
				// Lewati dot entries (. dan ..).
				if ( $fileinfo->isDot() || '.' === $fileinfo->getFilename() || '..' === $fileinfo->getFilename() ) {
					continue;
				}

				$pathname = $fileinfo->getPathname();

				// Lewati symlink untuk mencegah symlink traversal / arbitrary read.
				if ( is_link( $pathname ) || $fileinfo->isLink() ) {
					continue;
				}

				if ( $fileinfo->isFile() ) {
					$filename = $fileinfo->getFilename();

					// Abaikan berkas zip plugin yang dibuat oleh sistem jika ada di root.
					if ( 'wp-root-guard.zip' === $filename ) {
						continue;
					}

					// Abaikan berkas sementara karantina yang diawali dengan '__quarantine_'.
					if ( 0 === strpos( $filename, '__quarantine_' ) ) {
						continue;
					}

					// Proteksi DoS: skip berkas berukuran lebih dari 5 MB.
					$size = @filesize( $pathname );
					if ( false === $size || $size > self::MAX_FILE_SIZE ) {
						continue;
					}

					$hash = @md5_file( $pathname );
					if ( false !== $hash ) {
						$files[ $filename ] = $hash;
					}
				}
			}
		} catch ( \Exception $e ) {
			// Abaikan exception filesystem iterator.
		}

		// Urutkan alfabetis berdasarkan nama berkas.
		ksort( $files );
		return $files;
	}

	/**
	 * Menghapus berkas baseline.json dari filesystem.
	 *
	 * @return bool True jika berkas berhasil dihapus atau berkas memang tidak ada, false jika gagal menghapus.
	 */
	public static function delete_baseline() {
		self::clear_memory_cache();
		$file_path = self::get_baseline_file();
		$pending_path = self::get_pending_baseline_path();
		$active_deleted = empty( $file_path ) || ! file_exists( $file_path ) || @unlink( $file_path );
		$pending_deleted = empty( $pending_path ) || ! file_exists( $pending_path ) || @unlink( $pending_path );
		return $active_deleted && $pending_deleted;
	}

	/**
	 * Membangun ulang (rebuild) baseline dengan membaca folder dan berkas root saat ini.
	 *
	 * Method backward-compatible yang memanggil create_baseline().
	 *
	 * @return bool True jika baseline berhasil dibuat ulang.
	 */
	public static function rebuild_baseline() {
		return self::create_baseline();
	}

	/**
	 * Mereset baseline dengan menghapus berkas baseline.json.
	 *
	 * Method backward-compatible yang memanggil delete_baseline().
	 *
	 * @return bool True jika baseline berhasil direset/dihapus.
	 */
	public static function reset_baseline() {
		return self::delete_baseline();
	}

	/**
	 * Membaca folder baseline saat ini dari berkas baseline.json.
	 *
	 * Method backward-compatible yang memanggil get_baseline_folders().
	 *
	 * @return array List folder baseline.
	 */
	public static function get_baseline() {
		return self::get_baseline_folders();
	}

	/**
	 * Menandatangani data baseline dengan HMAC-SHA256.
	 *
	 * OWASP A08:2021 — Software & Data Integrity Failures (CWE-345).
	 *
	 * @param array $data Data snapshot baseline tanpa field 'hmac'.
	 * @return string Signature HMAC hex.
	 */
	public static function sign( array $data ) {
		unset( $data['hmac'] );
		ksort( $data );
		$payload = function_exists( 'wp_json_encode' ) ? wp_json_encode( $data ) : json_encode( $data );
		$key     = function_exists( 'wp_salt' ) ? wp_salt( self::HMAC_CONTEXT ) : self::HMAC_CONTEXT;
		return hash_hmac( 'sha256', $payload, $key );
	}

	/**
	 * Memverifikasi signature HMAC pada data baseline.
	 *
	 * OWASP A08:2021 — Software & Data Integrity Failures (CWE-345).
	 *
	 * @param array $data Data snapshot baseline yang memuat field 'hmac'.
	 * @return bool True jika signature valid dan otentik.
	 */
	public static function verify( array $data ) {
		if ( ! isset( $data['hmac'] ) || ! is_string( $data['hmac'] ) ) {
			return false;
		}

		$provided_hmac = $data['hmac'];
		$expected_hmac = self::sign( $data );

		return hash_equals( $expected_hmac, $provided_hmac );
	}
}
