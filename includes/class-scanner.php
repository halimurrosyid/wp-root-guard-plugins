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
 * dan menyimpan hasilnya di WordPress Options.
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

				$unknown_folders[] = array(
					'name'           => $folder,
					'path'           => $full_path,
					'created_time'   => $created_time,
					'detection_time' => $detection_time,
					'status'         => esc_html__( 'Unknown Folder', 'wp-root-guard' ),
				);

				// Log kejadian penemuan folder asing.
				Logger::log(
					esc_html__( 'Folder asing terdeteksi', 'wp-root-guard' ),
					$folder,
					esc_html__( 'Unknown', 'wp-root-guard' )
				);
			}
		}

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
