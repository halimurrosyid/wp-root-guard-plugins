<?php
/**
 * Mengelola pembuatan, pembacaan, dan pembaruan baseline folder dan berkas root.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Baseline
 *
 * Mengelola file baseline.json di folder wp-content/uploads/wp-root-guard/.
 * Menyimpan nama folder, nama berkas, dan MD5 hash berkas.
 */
class Baseline {

	/**
	 * Mendapatkan path absolut ke direktori penyimpanan baseline.
	 *
	 * @return string Path direktori.
	 */
	public static function get_baseline_dir() {
		$uploads = wp_upload_dir();
		return isset( $uploads['basedir'] ) ? $uploads['basedir'] . '/wp-root-guard' : '';
	}

	/**
	 * Mendapatkan path absolut ke file baseline.json.
	 *
	 * @return string Path file JSON.
	 */
	public static function get_baseline_path() {
		$dir = self::get_baseline_dir();
		return $dir ? $dir . '/baseline.json' : '';
	}

	/**
	 * Membuat baseline dari folder dan berkas root saat ini.
	 * Membaca semua direktori dan berkas level pertama di ABSPATH dan menyimpannya ke JSON.
	 *
	 * @return bool True jika sukses, false jika gagal.
	 */
	public static function create_baseline() {
		$dir_path = self::get_baseline_dir();
		if ( empty( $dir_path ) ) {
			return false;
		}

		// Buat folder jika belum ada.
		if ( ! file_exists( $dir_path ) ) {
			wp_mkdir_p( $dir_path );
			// Tambahkan file index.php kosong demi keamanan.
			@file_put_contents( $dir_path . '/index.php', '<?php // Silence is golden.' );
		}

		$folders = self::scan_root_folders();
		$files   = self::scan_root_files();

		// Simpan folder & berkas ke baseline.json.
		$json_path = self::get_baseline_path();
		$json_data = wp_json_encode(
			array(
				'created_at' => current_time( 'mysql' ),
				'folders'    => $folders,
				'files'      => $files,
			)
		);

		return false !== @file_put_contents( $json_path, $json_data );
	}

	/**
	 * Membaca folder baseline saat ini dari file baseline.json.
	 *
	 * @return array List folder baseline.
	 */
	public static function get_baseline() {
		return self::get_baseline_folders();
	}

	/**
	 * Membaca folder baseline saat ini dari file baseline.json.
	 *
	 * @return array List folder baseline. Mengembalikan array kosong jika file tidak ada/rusak.
	 */
	public static function get_baseline_folders() {
		$json_path = self::get_baseline_path();
		if ( ! file_exists( $json_path ) ) {
			return array();
		}

		$content = @file_get_contents( $json_path );
		if ( ! $content ) {
			return array();
		}

		$data = json_decode( $content, true );
		if ( ! is_array( $data ) || ! isset( $data['folders'] ) ) {
			return array();
		}

		return $data['folders'];
	}

	/**
	 * Membaca berkas beserta MD5 hash baseline saat ini dari file baseline.json.
	 *
	 * @return array Asosiatif array berkas rujukan (nama_berkas => hash_md5).
	 */
	public static function get_baseline_files() {
		$json_path = self::get_baseline_path();
		if ( ! file_exists( $json_path ) ) {
			return array();
		}

		$content = @file_get_contents( $json_path );
		if ( ! $content ) {
			return array();
		}

		$data = json_decode( $content, true );
		if ( ! is_array( $data ) || ! isset( $data['files'] ) ) {
			return array();
		}

		return $data['files'];
	}

	/**
	 * Membangun ulang (rebuild) baseline dengan membaca folder dan berkas root saat ini.
	 *
	 * @return bool True jika berhasil.
	 */
	public static function rebuild_baseline() {
		return self::create_baseline();
	}

	/**
	 * Menghapus file baseline.json.
	 *
	 * @return bool True jika berhasil dihapus.
	 */
	public static function reset_baseline() {
		$json_path = self::get_baseline_path();
		if ( file_exists( $json_path ) ) {
			return @unlink( $json_path );
		}
		return true;
	}

	/**
	 * Memindai folder root (ABSPATH) secara non-rekursif.
	 * Mengambil semua nama folder saja (mengabaikan file dan folder karantina).
	 *
	 * @return array Daftar nama folder di root WordPress.
	 */
	public static function scan_root_folders() {
		$folders = array();
		$path    = ABSPATH;

		if ( is_dir( $path ) ) {
			try {
				$iterator = new \DirectoryIterator( $path );
				foreach ( $iterator as $fileinfo ) {
					if ( $fileinfo->isDir() && ! $fileinfo->isDot() ) {
						$foldername = $fileinfo->getFilename();
						// Jangan masukkan folder karantina ke daftar folder root aktif
						if ( 0 === strpos( $foldername, '__quarantine_' ) ) {
							continue;
						}
						$folders[] = $foldername;
					}
				}
			} catch ( \Exception $e ) {
				// Abaikan error iterator
			}
		}

		// Urutkan alfabetis
		sort( $folders );
		return $folders;
	}

	/**
	 * Memindai berkas di root (ABSPATH) secara non-rekursif dan menghitung MD5 hash-nya.
	 *
	 * @return array Asosiatif array berisi: nama_file => md5_hash.
	 */
	public static function scan_root_files() {
		$files = array();
		$path  = ABSPATH;

		if ( is_dir( $path ) ) {
			try {
				$iterator = new \DirectoryIterator( $path );
				foreach ( $iterator as $fileinfo ) {
					if ( $fileinfo->isFile() ) {
						$filename = $fileinfo->getFilename();
						
						// Abaikan berkas zip plugin yang dibuat oleh kita sendiri jika ada di root
						if ( 'wp-root-guard.zip' === $filename ) {
							continue;
						}

						// Abaikan berkas sementara karantina yang diawali dengan '__quarantine_'
						if ( 0 === strpos( $filename, '__quarantine_' ) ) {
							continue;
						}

						$file_path = $fileinfo->getPathname();
						$hash      = @md5_file( $file_path );
						if ( false !== $hash ) {
							$files[ $filename ] = $hash;
						}
					}
				}
			} catch ( \Exception $e ) {
				// Abaikan error iterator
			}
		}

		// Urutkan alfabetis berdasarkan nama berkas
		ksort( $files );
		return $files;
	}
}
