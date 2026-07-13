<?php
/**
 * Mengelola penjadwalan WP Cron untuk melakukan pemindaian otomatis setiap 5 menit.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Cron
 *
 * Menangani penambahan interval kustom 5 menit ke WP Cron, menjadwalkan event scan,
 * serta mengeksekusi scan di latar belakang.
 */
class Cron {

	/**
	 * Mendaftarkan filter dan action untuk WP Cron.
	 */
	public function init() {
		add_filter( 'cron_schedules', array( $this, 'add_cron_interval' ) );
		add_action( 'wp_root_guard_cron_scan', array( $this, 'run_background_scan' ) );
	}

	/**
	 * Menambahkan interval kustom 5 menit ke daftar jadwal cron WordPress.
	 *
	 * @param array $schedules Daftar jadwal cron saat ini.
	 * @return array Daftar jadwal cron setelah ditambah interval 5 menit.
	 */
	public function add_cron_interval( $schedules ) {
		$schedules['every_5_minutes'] = array(
			'interval' => 300, // 5 menit dalam hitungan detik.
			'display'  => esc_html__( 'Setiap 5 Menit', 'wp-root-guard' ),
		);
		return $schedules;
	}

	/**
	 * Menjadwalkan pemindaian otomatis jika belum terdaftar.
	 */
	public static function schedule_event() {
		if ( ! wp_next_scheduled( 'wp_root_guard_cron_scan' ) ) {
			wp_schedule_event( time(), 'every_5_minutes', 'wp_root_guard_cron_scan' );
		}
	}

	/**
	 * Membatalkan jadwal pemindaian otomatis (misal saat deaktivas / reset).
	 */
	public static function unschedule_event() {
		$timestamp = wp_next_scheduled( 'wp_root_guard_cron_scan' );
		if ( $timestamp ) {
			wp_unschedule_event( $timestamp, 'wp_root_guard_cron_scan' );
		}
	}

	/**
	 * Callback yang dieksekusi oleh WP Cron untuk memindai root folder di latar belakang.
	 */
	public function run_background_scan() {
		Scanner::perform_scan();
	}
}
