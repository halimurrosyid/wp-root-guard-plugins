<?php
/**
 * Logika deaktivasi plugin WP Root Guard.
 *
 * Berkas ini berisi class Deactivator yang dijalankan saat plugin dinonaktifkan
 * melalui register_deactivation_hook. Bertanggung jawab untuk membatalkan
 * seluruh event WP-Cron terjadwal dan mencatat riwayat log deaktivasi.
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
 * Class Deactivator
 *
 * Menangani pembersihan event cron terjadwal dan pencatatan audit log
 * saat plugin dinonaktifkan oleh administrator.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Deactivator {

	/**
	 * Logika deaktivasi plugin.
	 *
	 * Membatalkan jadwal cron dan mencatat aktivitas deaktivasi ke audit log.
	 *
	 * @return void
	 */
	public static function deactivate() {
		// 1. Batalkan jadwal event cron agar tidak membebani server saat tidak aktif.
		if ( class_exists( __NAMESPACE__ . '\\Cron' ) ) {
			Cron::unschedule_event();
		}

		// 2. Catat riwayat log deaktivasi.
		if ( class_exists( __NAMESPACE__ . '\\Logger' ) ) {
			Logger::log( esc_html__( 'Plugin dinonaktifkan', 'wp-root-guard' ), '-', esc_html__( 'Inactive', 'wp-root-guard' ) );
		}
	}
}
