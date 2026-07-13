<?php
/**
 * Mengelola logging aktivitas pemindaian dan deteksi folder asing.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Logger
 *
 * Menyimpan dan mengambil riwayat log deteksi folder di Options API.
 */
class Logger {

	/**
	 * Batas maksimal jumlah entri log yang disimpan.
	 */
	const MAX_LOGS = 100;

	/**
	 * Menambahkan baris log baru ke database.
	 *
	 * @param string $event Nama kejadian (contoh: "Scan Completed", "Folder detected").
	 * @param string $folder_name Nama folder terkait (jika ada).
	 * @param string $status Status atau deskripsi tambahan (contoh: "Unknown", "Safe").
	 * @return bool True jika berhasil diperbarui.
	 */
	public static function log( $event, $folder_name = '-', $status = '-' ) {
		$logs = get_option( 'wp_root_guard_logs', array() );
		if ( ! is_array( $logs ) ) {
			$logs = array();
		}

		$new_entry = array(
			'time'        => current_time( 'mysql' ),
			'event'       => sanitize_text_field( $event ),
			'folder_name' => sanitize_text_field( $folder_name ),
			'status'      => sanitize_text_field( $status ),
		);

		// Taruh entri terbaru di paling atas.
		array_unshift( $logs, $new_entry );

		// Batasi ukuran log agar database tetap ramping.
		if ( count( $logs ) > self::MAX_LOGS ) {
			$logs = array_slice( $logs, 0, self::MAX_LOGS );
		}

		return update_option( 'wp_root_guard_logs', $logs );
	}

	/**
	 * Mengambil semua riwayat log.
	 *
	 * @return array Daftar log terurut dari yang terbaru.
	 */
	public static function get_logs() {
		$logs = get_option( 'wp_root_guard_logs', array() );
		return is_array( $logs ) ? $logs : array();
	}

	/**
	 * Menghapus seluruh riwayat log.
	 *
	 * @return bool True jika berhasil dihapus.
	 */
	public static function clear_logs() {
		return delete_option( 'wp_root_guard_logs' );
	}
}
