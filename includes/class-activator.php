<?php
/**
 * Logika aktivasi plugin WP Root Guard.
 *
 * Berkas ini berisi class Activator yang dijalankan saat plugin diaktifkan
 * melalui register_activation_hook. Bertanggung jawab untuk inisialisasi versi,
 * pencatatan log aktivasi, pembuatan baseline awal, dan penjadwalan WP-Cron.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

namespace WPRootGuard;

// Mencegah akses langsung ke file.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Activator
 *
 * Menangani inisialisasi pada saat aktivasi plugin.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Activator {

	/**
	 * Logika aktivasi plugin.
	 *
	 * Menginisialisasi versi plugin, mencatat audit log, membuat baseline
	 * snapshot direktori root bila belum ada, dan menjadwalkan event WP-Cron.
	 *
	 * @return void
	 */
	public static function activate() {
		// 1. Simpan atau perbarui versi plugin di database.
		$version = defined( 'WP_ROOT_GUARD_VERSION' ) ? WP_ROOT_GUARD_VERSION : '1.0.0';
		update_option( 'wp_root_guard_version', $version, false );

		// 2. Catat log riwayat bahwa plugin telah diaktifkan.
		if ( class_exists( __NAMESPACE__ . '\\Logger' ) ) {
			Logger::log( esc_html__( 'Plugin diaktifkan', 'wp-root-guard' ), '-', esc_html__( 'Active', 'wp-root-guard' ) );
		}

		// 3. Buat baseline folder jika belum ada file baseline.
		if ( class_exists( __NAMESPACE__ . '\\Baseline' ) ) {
			if ( ! file_exists( Baseline::get_baseline_path() ) ) {
				Baseline::create_baseline();
				if ( class_exists( __NAMESPACE__ . '\\Logger' ) ) {
					Logger::log( esc_html__( 'Baseline awal berhasil dibuat', 'wp-root-guard' ), '-', esc_html__( 'Success', 'wp-root-guard' ) );
				}
			}
		}

		// 4. Daftarkan dan jadwalkan event cron pemindaian otomatis dan prune IP.
		if ( class_exists( __NAMESPACE__ . '\\Cron' ) ) {
			Cron::schedule_event();
		}

		// 5. Jalankan pemindaian pertama secara langsung jika kelas scanner tersedia.
		if ( class_exists( __NAMESPACE__ . '\\Scanner' ) ) {
			Scanner::perform_scan();
		}
	}
}
