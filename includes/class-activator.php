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
		// Operational scan and quarantine metadata must exist before the first
		// activation scan starts. Failure is handled fail-closed by the scanner.
		if ( class_exists( __NAMESPACE__ . '\\ScanStore' ) ) {
			ScanStore::ensure_schema( true );
		}

		// 1. Simpan atau perbarui versi plugin di database.
		$version = defined( 'WP_ROOT_GUARD_VERSION' ) ? WP_ROOT_GUARD_VERSION : '1.0.0';
		update_option( 'wp_root_guard_version', $version, false );

		// 2. Catat log riwayat bahwa plugin telah diaktifkan.
		if ( class_exists( __NAMESPACE__ . '\\Logger' ) ) {
			Logger::log( esc_html__( 'Plugin diaktifkan', 'wp-root-guard' ), '-', esc_html__( 'Active', 'wp-root-guard' ) );
		}

		// 3. Daftarkan dan jadwalkan event cron pemindaian otomatis dan prune IP.
		if ( class_exists( __NAMESPACE__ . '\\Cron' ) ) {
			Cron::schedule_event();
		}

		// 4. Jalankan verifikasi awal. Baseline dibuat oleh scanner hanya setelah
		// seluruh scope critical selesai dan tidak ada threat yang belum ditinjau.
		if ( class_exists( __NAMESPACE__ . '\\Scanner' ) ) {
			Scanner::perform_scan( 'activation' );
		}
	}
}
