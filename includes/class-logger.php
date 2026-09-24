<?php
/**
 * Log audit aktivitas keamanan WP Root Guard.
 *
 * Berkas ini berisi class Logger yang bertanggung jawab untuk:
 * 1. Mencatat riwayat aktivitas keamanan ke WordPress Options API.
 * 2. Menandatangani setiap entri log dengan HMAC-SHA256 untuk deteksi tampering.
 * 3. Menyimpan log dengan rolling buffer (maksimal 100 entri).
 * 4. Menyediakan method pembacaan dan pembersihan log.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Logger
 *
 * Mengelola audit trail riwayat aktivitas keamanan dengan integritas
 * terjamin via HMAC-SHA256.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Logger {

	/**
	 * Nama option untuk menyimpan log.
	 */
	const OPTION_KEY = 'wp_root_guard_logs';

	/**
	 * Batas maksimal entri log (rolling buffer).
	 */
	const MAX_ENTRIES = 100;

	/**
	 * Context HMAC untuk signing entri log.
	 */
	const HMAC_CONTEXT = 'wp_root_guard_log';

	/**
	 * Menambahkan entri baru ke log.
	 *
	 * OWASP A08:2021 — Software & Data Integrity Failures (CWE-345).
	 * Setiap entri ditandatangani dengan HMAC-SHA256 sehingga modifikasi
	 * oleh malware atau attacker dapat terdeteksi saat pembacaan.
	 *
	 * OWASP A09:2021 — Security Logging & Monitoring Failures.
	 *
	 * @param string $event  Deskripsi event.
	 * @param string $target Target (nama berkas, IP, dll).
	 * @param string $status Status (Safe, Threat Detected, Blocked, dll).
	 * @return void
	 */
	public static function log( $event, $target = '-', $status = 'Info' ) {
		$logs = self::get_raw_logs();

		$entry = array(
			'time'   => Scanner::get_wib_time(),
			'event'  => (string) $event,
			'target' => (string) $target,
			'status' => (string) $status,
		);

		$entry['hmac'] = self::sign_entry( $entry );

		// Sisipkan di awal array (terbaru di depan).
		array_unshift( $logs, $entry );

		// Rolling buffer.
		if ( count( $logs ) > self::MAX_ENTRIES ) {
			$logs = array_slice( $logs, 0, self::MAX_ENTRIES );
		}

		update_option( self::OPTION_KEY, $logs, false );
	}

	/**
	 * Mendapatkan seluruh entri log dengan verifikasi HMAC.
	 *
	 * OWASP A08:2021 — Software & Data Integrity Failures.
	 * Entri yang HMAC-nya tidak valid ditandai sebagai TAMPERED.
	 *
	 * @return array Daftar entri log yang sudah diverifikasi.
	 */
	public static function get_logs() {
		$logs = self::get_raw_logs();

		foreach ( $logs as $index => $entry ) {
			if ( ! is_array( $entry ) ) {
				unset( $logs[ $index ] );
				continue;
			}

			$is_valid = self::verify_entry( $entry );

			if ( ! $is_valid ) {
				$logs[ $index ]['status'] = '⚠️ TAMPERED';
				$logs[ $index ]['event']  = __( 'Entri log telah dimodifikasi (HMAC tidak valid)', 'wp-root-guard' );
			}
		}

		return array_values( $logs );
	}

	/**
	 * Menghapus seluruh entri log.
	 *
	 * @return bool True jika berhasil.
	 */
	public static function clear_logs() {
		return delete_option( self::OPTION_KEY );
	}

	/**
	 * Mendapatkan entri log mentah dari database tanpa verifikasi.
	 *
	 * @return array
	 */
	private static function get_raw_logs() {
		$logs = get_option( self::OPTION_KEY, array() );
		return is_array( $logs ) ? $logs : array();
	}

	/**
	 * Menandatangani entri log dengan HMAC-SHA256.
	 *
	 * @param array $entry Entri log tanpa field 'hmac'.
	 * @return string Signature HMAC hex.
	 */
	private static function sign_entry( $entry ) {
		unset( $entry['hmac'] );
		$payload = wp_json_encode( $entry );
		$key     = wp_salt( self::HMAC_CONTEXT );
		return hash_hmac( 'sha256', $payload, $key );
	}

	/**
	 * Memverifikasi signature HMAC pada entri log.
	 *
	 * @param array $entry Entri log dengan field 'hmac'.
	 * @return bool True jika valid.
	 */
	private static function verify_entry( $entry ) {
		if ( ! isset( $entry['hmac'] ) || ! is_string( $entry['hmac'] ) ) {
			return false;
		}

		$expected = self::sign_entry( $entry );
		return hash_equals( $expected, $entry['hmac'] );
	}
}
