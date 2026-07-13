<?php
/**
 * Dijalankan saat deaktivas plugin.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Deactivator
 *
 * Menangani pembersihan event cron terjadwal saat plugin dinonaktifkan.
 */
class Deactivator {

	/**
	 * Logika deaktivasi plugin.
	 */
	public static function deactivate() {
		// 1. Batalkan jadwal event cron scan agar tidak membebani server saat tidak aktif.
		Cron::unschedule_event();

		// 2. Catat riwayat log deaktivasi.
		Logger::log( esc_html__( 'Plugin dinonaktifkan', 'wp-root-guard' ), '-', esc_html__( 'Inactive', 'wp-root-guard' ) );
	}
}
