<?php
/**
 * Dijalankan saat aktivasi plugin.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Activator
 *
 * Menangani pembuatan baseline pertama dan penjadwalan pemindaian rutin.
 */
class Activator {

	/**
	 * Logika aktivasi plugin.
	 */
	public static function activate() {
		// 1. Tulis log pertama kali bahwa plugin telah diaktifkan.
		Logger::log( esc_html__( 'Plugin diaktifkan', 'wp-root-guard' ), '-', esc_html__( 'Active', 'wp-root-guard' ) );

		// 2. Buat baseline folder jika belum ada file baseline.
		if ( ! file_exists( Baseline::get_baseline_path() ) ) {
			Baseline::create_baseline();
			Logger::log( esc_html__( 'Baseline awal berhasil dibuat', 'wp-root-guard' ), '-', esc_html__( 'Success', 'wp-root-guard' ) );
		}

		// 3. Daftarkan dan jadwalkan cron scan otomatis setiap 5 menit.
		// Catatan: Karena filter cron_schedules mungkin belum terdaftar saat hooks aktivasi dipanggil,
		// kita jadwalkan event langsung, dan filter interval akan diproses ketika WP memuat plugin secara berkala.
		Cron::schedule_event();

		// 4. Jalankan pemindaian pertama secara langsung di latar belakang/insidental.
		Scanner::perform_scan();
	}
}
