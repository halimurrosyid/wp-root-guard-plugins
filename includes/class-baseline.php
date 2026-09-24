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
	 * Membuat baseline dari folder dan berkas root saat ini.
	 *
	 * Membaca seluruh direktori dan berkas level pertama di ABSPATH,
	 * menambahkan HMAC signature untuk integritas data, dan menyimpannya ke berkas baseline.json
	 * dengan exclusive file lock (LOCK_EX).
	 *
	 * @return bool True jika baseline berhasil ditulis, false jika gagal.
	 */
	public static function create_baseline() {
		$file_path = self::get_baseline_file();
		if ( empty( $file_path ) ) {
			return false;
		}

		global $wp_version;

		$folders = self::scan_root_folders();
		$files   = self::scan_root_files();

		$data = array(
			'created_at' => function_exists( 'current_time' ) ? current_time( 'mysql' ) : gmdate( 'Y-m-d H:i:s' ),
			'wp_version' => ! empty( $wp_version ) ? (string) $wp_version : ( function_exists( 'get_bloginfo' ) ? (string) get_bloginfo( 'version' ) : '' ),
			'folders'    => $folders,
			'files'      => $files,
		);

		$data['hmac'] = self::sign( $data );

		$json_data = function_exists( 'wp_json_encode' )
			? wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES )
			: json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );

		return false !== @file_put_contents( $file_path, $json_data, LOCK_EX );
	}

	/**
	 * Membaca dan memverifikasi integritas berkas baseline.json.
	 *
	 * OWASP A08:2021 — Software & Data Integrity Failures.
	 * Membaca berkas dan memverifikasi HMAC signature via verify().
	 * Jika verifikasi gagal (file dimodifikasi/rusak), catat ke Logger sebagai Tampered dan kembalikan array kosong.
	 *
	 * @return array Data snapshot baseline jika valid, atau array kosong jika tidak ditemukan / tidak valid.
	 */
	public static function read_baseline() {
		$file_path = self::get_baseline_file();
		if ( empty( $file_path ) || ! file_exists( $file_path ) ) {
			return array();
		}

		$content = @file_get_contents( $file_path );
		if ( false === $content || '' === trim( $content ) ) {
			return array();
		}

		$data = json_decode( $content, true );
		if ( ! is_array( $data ) || ! self::verify( $data ) ) {
			Logger::log(
				__( 'Integritas berkas baseline gagal diverifikasi: berkas telah dimodifikasi atau HMAC tidak valid', 'wp-root-guard' ),
				self::BASELINE_FILENAME,
				'Tampered'
			);
			return array();
		}

		return $data;
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
	private static function sign( array $data ) {
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
	private static function verify( array $data ) {
		if ( ! isset( $data['hmac'] ) || ! is_string( $data['hmac'] ) ) {
			return false;
		}

		$provided_hmac = $data['hmac'];
		$expected_hmac = self::sign( $data );

		return hash_equals( $expected_hmac, $provided_hmac );
	}
}
