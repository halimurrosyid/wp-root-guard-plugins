<?php
/**
 * WP Root Guard Uninstall
 *
 * File ini dijalankan ketika plugin dihapus (uninstall) oleh user.
 * Ini akan menghapus semua opsi, jadwal cron, log, dan file baseline
 * untuk memastikan tidak ada database atau file sampah yang tersisa.
 *
 * @package WPRootGuard
 */

// Jika uninstall tidak dipanggil dari WordPress, keluar.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// 1. Hapus jadwal cron.
$timestamp = wp_next_scheduled( 'wp_root_guard_cron_scan' );
if ( $timestamp ) {
	wp_unschedule_event( $timestamp, 'wp_root_guard_cron_scan' );
}

// 2. Hapus Semua Opsi dari database (WordPress Options API).
delete_option( 'wp_root_guard_settings' );
delete_option( 'wp_root_guard_whitelist' );
delete_option( 'wp_root_guard_logs' );
delete_option( 'wp_root_guard_last_scan' );
delete_option( 'wp_root_guard_unknown_folders' );
delete_option( 'wp_root_guard_quarantined_folders' );
delete_option( 'wp_root_guard_notified_threats' );
delete_option( 'wp_root_guard_blocked_ips' );
delete_option( 'wp_root_guard_active_files' );
delete_option( 'wp_root_guard_active_core_threats' );
delete_option( 'wp_root_guard_baseline_folders' );
delete_option( 'wp_root_guard_baseline_files' );
delete_transient( 'wp_root_guard_core_checksums' );

// 3. Bersihkan blok IP dari root .htaccess.
$htaccess_file = ABSPATH . '.htaccess';
if ( file_exists( $htaccess_file ) && is_writable( $htaccess_file ) ) {
	$content      = file_get_contents( $htaccess_file );
	$start_marker = '# BEGIN WP Root Guard Blocked IPs';
	$end_marker   = '# END WP Root Guard Blocked IPs';
	if ( false !== strpos( $content, $start_marker ) && false !== strpos( $content, $end_marker ) ) {
		$pattern     = '/' . preg_quote( $start_marker, '/' ) . '.*?' . preg_quote( $end_marker, '/' ) . '/s';
		$new_content = preg_replace( $pattern, '', $content );
		$new_content = preg_replace( '/\n{3,}/', "\n\n", $new_content ); // Bersihkan baris kosong berlebih
		file_put_contents( $htaccess_file, $new_content );
	}
}

// 4. Hapus folder baseline dan isinya.
$wp_uploads   = wp_upload_dir();
$upload_dir   = isset( $wp_uploads['basedir'] ) ? $wp_uploads['basedir'] : '';
$baseline_dir = $upload_dir . '/wp-root-guard';
$json_file    = $baseline_dir . '/baseline.json';

if ( ! empty( $upload_dir ) && file_exists( $json_file ) ) {
	@unlink( $json_file );
}

if ( ! empty( $upload_dir ) && is_dir( $baseline_dir ) ) {
	@rmdir( $baseline_dir );
}
