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

// 2. Hapus Opsi dari database (WordPress Options API).
delete_option( 'wp_root_guard_settings' );
delete_option( 'wp_root_guard_whitelist' );
delete_option( 'wp_root_guard_logs' );
delete_option( 'wp_root_guard_last_scan' );
delete_option( 'wp_root_guard_unknown_folders' );
delete_option( 'wp_root_guard_quarantined_folders' );
delete_option( 'wp_root_guard_notified_threats' );
delete_transient( 'wp_root_guard_core_checksums' );

// 3. Hapus folder baseline dan isinya.
$wp_uploads  = wp_upload_dir();
$upload_dir  = isset( $wp_uploads['basedir'] ) ? $wp_uploads['basedir'] : '';
$baseline_dir = $upload_dir . '/wp-root-guard';
$json_file    = $baseline_dir . '/baseline.json';

if ( ! empty( $upload_dir ) && file_exists( $json_file ) ) {
	@unlink( $json_file );
}

if ( ! empty( $upload_dir ) && is_dir( $baseline_dir ) ) {
	@rmdir( $baseline_dir );
}
