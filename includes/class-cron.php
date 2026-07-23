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
	 * Menambahkan interval kustom (5 menit, 15 menit, 30 menit) ke daftar jadwal cron WordPress.
	 *
	 * @param array $schedules Daftar jadwal cron saat ini.
	 * @return array Daftar jadwal cron setelah ditambah interval kustom.
	 */
	public function add_cron_interval( $schedules ) {
		$schedules['every_5_minutes'] = array(
			'interval' => 300,
			'display'  => esc_html__( 'Setiap 5 Menit', 'wp-root-guard' ),
		);
		$schedules['every_15_minutes'] = array(
			'interval' => 900,
			'display'  => esc_html__( 'Setiap 15 Menit', 'wp-root-guard' ),
		);
		$schedules['every_30_minutes'] = array(
			'interval' => 1800,
			'display'  => esc_html__( 'Setiap 30 Menit', 'wp-root-guard' ),
		);
		return $schedules;
	}

	/**
	 * Menjadwalkan pemindaian otomatis berdasarkan interval di pengaturan.
	 */
	public static function schedule_event() {
		$settings = Settings::get_settings();
		$interval = ! empty( $settings['scan_interval'] ) ? $settings['scan_interval'] : 'every_5_minutes';

		if ( ! wp_next_scheduled( 'wp_root_guard_cron_scan' ) ) {
			wp_schedule_event( time(), $interval, 'wp_root_guard_cron_scan' );
		}
	}

	/**
	 * Menjadwalkan ulang event cron saat opsi interval diubah di pengaturan.
	 *
	 * @param string $new_interval Interval baru yang dipilih user.
	 */
	public static function reschedule_event( $new_interval ) {
		self::unschedule_event();
		wp_schedule_event( time(), $new_interval, 'wp_root_guard_cron_scan' );
	}

	/**
	 * Membatalkan jadwal pemindaian otomatis (misal saat deaktivasi / reset).
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
