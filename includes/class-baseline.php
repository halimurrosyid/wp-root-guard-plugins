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
			@file_put_contents( $index_file, "<?php\n// Silence is golden.\n" );
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
		if ( empty( $new_version ) ) {
			$new_version = self::get_current_wp_version();
		}

		$result = self::sync_baseline_version( $new_version, $source );
		return is_array( $result );
	}

	/**
	 * Membuat baseline dari folder dan berkas root saat ini.
	 *
	 * @return bool True jika baseline berhasil ditulis, false jika gagal.
	 */
	public static function create_baseline() {
		self::clear_memory_cache();
		$current_version = self::get_current_wp_version();
		$synced          = self::sync_baseline_version( $current_version, 'manual_create' );
		return is_array( $synced );
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

		// 2. Fallback Version Detection: Cek perbedaan versi WordPress core.
		if ( ! $skip_fallback ) {
			$current_version = self::get_current_wp_version();
			$stored_version  = isset( $data['wp_version'] ) ? (string) $data['wp_version'] : '';

			if ( ! empty( $current_version ) && ! empty( $stored_version ) && $current_version !== $stored_version ) {
				$synced_data = self::sync_baseline_version( $current_version, 'fallback_version_detection', $stored_version );
				if ( is_array( $synced_data ) && ! empty( $synced_data ) ) {
					self::$memory_cache = $synced_data;
					return $synced_data;
				}
			}
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
			);

			// Tanda tangani dengan HMAC-SHA256
			$new_data['hmac'] = self::sign( $new_data );

			$json_data = function_exists( 'wp_json_encode' )
				? wp_json_encode( $new_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES )
				: json_encode( $new_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

			$target_file = self::get_baseline_file();
			$written     = @file_put_contents( $target_file, $json_data, LOCK_EX );

			if ( false === $written ) {
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
		if ( ! empty( $file_path ) && file_exists( $file_path ) ) {
			return @unlink( $file_path );
		}
		return true;
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
