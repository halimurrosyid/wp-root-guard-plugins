<?php
/**
 * Pengelola penjadwalan WP-Cron untuk pemindaian berkala dan pembersihan IP.
 *
 * Berkas ini berisi class Cron yang bertanggung jawab untuk:
 * 1. Menambahkan interval kustom ke WP-Cron (5 menit, 15 menit, 30 menit).
 * 2. Menjadwalkan dan membatalkan cron event pemindaian dan prune IP secara idempoten.
 * 3. Menangani callback eksekusi pemindaian latar belakang (background scan).
 * 4. Menangani penjadwalan ulang saat interval scan diubah di pengaturan.
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
 * Class Cron
 *
 * Mengelola penjadwalan WP-Cron, interval kustom, dan eksekusi tugas di latar belakang.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Cron {

	/**
	 * Nama hook cron untuk pemindaian root directory.
	 */
	const SCAN_HOOK = 'wp_root_guard_cron_scan';

	/**
	 * Nama hook cron untuk pembersihan IP terblokir yang telah kedaluwarsa.
	 */
	const PRUNE_HOOK = 'wp_root_guard_prune_ips';

	/**
	 * Mendaftarkan filter dan action untuk WP-Cron.
	 *
	 * @return void
	 */
	public function init() {
		add_filter( 'cron_schedules', array( $this, 'add_cron_interval' ) );
		add_action( self::SCAN_HOOK, array( $this, 'run_background_scan' ) );
		add_action( self::PRUNE_HOOK, array( __NAMESPACE__ . '\\Blocker', 'prune_expired_ips' ) );
	}

	/**
	 * Menambahkan interval kustom (5 menit, 15 menit, 30 menit) ke daftar jadwal cron WordPress.
	 *
	 * @param array $schedules Daftar jadwal cron saat ini.
	 * @return array Daftar jadwal cron setelah ditambah interval kustom.
	 */
	public function add_cron_interval( $schedules ) {
		if ( ! is_array( $schedules ) ) {
			$schedules = array();
		}

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
	 * Menjadwalkan pemindaian otomatis dan pembersihan IP berdasarkan interval di pengaturan.
	 *
	 * Method ini bersifat idempoten; tidak akan membuat duplikat jadwal
	 * jika event sudah terdaftar di WP-Cron.
	 *
	 * @return void
	 */
	public static function schedule_event() {
		$interval = 'every_5_minutes';
		if ( class_exists( __NAMESPACE__ . '\\Settings' ) ) {
			$settings = Settings::get_settings();
			if ( ! empty( $settings['scan_interval'] ) ) {
				$interval = $settings['scan_interval'];
			}
		}

		if ( ! wp_next_scheduled( self::SCAN_HOOK ) ) {
			wp_schedule_event( time(), $interval, self::SCAN_HOOK );
		}

		if ( ! wp_next_scheduled( self::PRUNE_HOOK ) ) {
			wp_schedule_event( time(), 'hourly', self::PRUNE_HOOK );
		}
	}

	/**
	 * Menjadwalkan ulang event cron pemindaian saat opsi interval diubah di pengaturan.
	 *
	 * @param string $new_interval Interval baru yang dipilih user.
	 * @return void
	 */
	public static function reschedule_event( $new_interval ) {
		$scan_timestamp = wp_next_scheduled( self::SCAN_HOOK );
		if ( $scan_timestamp ) {
			wp_unschedule_event( $scan_timestamp, self::SCAN_HOOK );
		}
		wp_clear_scheduled_hook( self::SCAN_HOOK );

		$valid_interval = sanitize_key( $new_interval );
		if ( empty( $valid_interval ) ) {
			$valid_interval = 'every_5_minutes';
		}

		wp_schedule_event( time(), $valid_interval, self::SCAN_HOOK );

		// Pastikan hook prune IP tetap terjadwal.
		if ( ! wp_next_scheduled( self::PRUNE_HOOK ) ) {
			wp_schedule_event( time(), 'hourly', self::PRUNE_HOOK );
		}
	}

	/**
	 * Membatalkan jadwal pemindaian otomatis dan pembersihan IP (misal saat deaktivasi atau reset).
	 *
	 * @return void
	 */
	public static function unschedule_event() {
		$scan_timestamp = wp_next_scheduled( self::SCAN_HOOK );
		if ( $scan_timestamp ) {
			wp_unschedule_event( $scan_timestamp, self::SCAN_HOOK );
		}
		wp_clear_scheduled_hook( self::SCAN_HOOK );

		$prune_timestamp = wp_next_scheduled( self::PRUNE_HOOK );
		if ( $prune_timestamp ) {
			wp_unschedule_event( $prune_timestamp, self::PRUNE_HOOK );
		}
		wp_clear_scheduled_hook( self::PRUNE_HOOK );
	}

	/**
	 * Callback yang dieksekusi oleh WP-Cron untuk memindai root folder di latar belakang.
	 *
	 * @return void
	 */
	public function run_background_scan() {
		if ( ! class_exists( __NAMESPACE__ . '\\Settings' ) || ! class_exists( __NAMESPACE__ . '\\Scanner' ) ) {
			return;
		}

		$settings = Settings::get_settings();
		if ( empty( $settings ) ) {
			return;
		}

		Scanner::perform_scan();
	}
}
