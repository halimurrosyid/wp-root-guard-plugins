<?php
/**
 * WP Root Guard Uninstall
 *
 * Berkas ini dieksekusi secara otomatis ketika plugin dihapus (uninstall) secara permanen
 * oleh administrator melalui dashboard WordPress. Berkas ini bertanggung jawab untuk
 * membersihkan seluruh data dan jejak plugin dari database dan sistem berkas:
 * 1. Menghapus jadwal cron plugin (wp_root_guard_cron_scan, wp_root_guard_prune_ips).
 * 2. Menghapus semua opsi pengaturan dan transient di tabel options (termasuk user-specific transients).
 * 3. Menghapus aturan blokir IP dari berkas root .htaccess (di antara marker boundary).
 * 4. Menghapus direktori snapshot baseline dan direktori karantina secara rekursif dengan proteksi symlink.
 *
 * Mendukung instalasi Single Site dan WordPress Multisite (Network Uninstall).
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

// 1. Guard: Pastikan proses dipanggil resmi dari WordPress saat uninstall plugin.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

// 2. Guard: Pastikan pengguna memiliki izin administratif untuk menghapus plugin.
if ( ! current_user_can( 'delete_plugins' ) ) {
	exit;
}

if ( ! function_exists( 'wp_root_guard_recursive_delete' ) ) {
	/**
	 * Menghapus berkas atau direktori beserta isinya secara rekursif dengan proteksi symlink.
	 *
	 * OWASP A01:2021 — Broken Access Control (CWE-59 Symlink Traversal).
	 * Mencegah eksploitasi symbolic link: jika direktori/berkas adalah symlink,
	 * hanya pointer link yang dihapus (unlink) tanpa mengikuti target asli.
	 *
	 * @param string $path Path absolut direktori atau berkas yang akan dihapus.
	 * @return bool True jika berhasil atau tidak ada, false jika gagal.
	 */
	function wp_root_guard_recursive_delete( $path ) {
		if ( is_link( $path ) ) {
			return @unlink( $path );
		}

		if ( ! file_exists( $path ) ) {
			return true;
		}

		if ( ! is_dir( $path ) ) {
			return @unlink( $path );
		}

		$items = @scandir( $path );
		if ( false === $items ) {
			return false;
		}

		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) {
				continue;
			}

			$item_path = $path . DIRECTORY_SEPARATOR . $item;

			// Proteksi symlink: hapus link secara langsung tanpa mengikuti targetnya.
			if ( is_link( $item_path ) ) {
				@unlink( $item_path );
			} elseif ( is_dir( $item_path ) ) {
				wp_root_guard_recursive_delete( $item_path );
			} else {
				@unlink( $item_path );
			}
		}

		return @rmdir( $path );
	}
}

if ( ! function_exists( 'wp_root_guard_uninstall_htaccess' ) ) {
	/**
	 * Membersihkan aturan pemblokiran IP milik WP Root Guard dari berkas root .htaccess.
	 *
	 * Mencari dan menghapus seluruh blok aturan di antara boundary marker:
	 * # BEGIN WP Root Guard Blocked IPs ... # END WP Root Guard Blocked IPs
	 */
	function wp_root_guard_uninstall_htaccess() {
		if ( ! defined( 'ABSPATH' ) ) {
			return;
		}

		$htaccess_file = ABSPATH . '.htaccess';
		if ( ! file_exists( $htaccess_file ) || ! is_readable( $htaccess_file ) || ! is_writable( $htaccess_file ) ) {
			return;
		}

		$content = file_get_contents( $htaccess_file );
		if ( false === $content ) {
			return;
		}

		$start_marker = '# BEGIN WP Root Guard Blocked IPs';
		$end_marker   = '# END WP Root Guard Blocked IPs';

		if ( false !== strpos( $content, $start_marker ) && false !== strpos( $content, $end_marker ) ) {
			$pattern     = '/\s*' . preg_quote( $start_marker, '/' ) . '.*?' . preg_quote( $end_marker, '/' ) . '\s*/s';
			$new_content = preg_replace( $pattern, "\n\n", $content );
			if ( null !== $new_content ) {
				$new_content = preg_replace( "/(\r?\n){3,}/", "$1$1", $new_content );
				$new_content = trim( $new_content );
				if ( ! empty( $new_content ) ) {
					$new_content .= "\n";
				}
				file_put_contents( $htaccess_file, $new_content, LOCK_EX );
			}
		}
	}
}

if ( ! function_exists( 'wp_root_guard_uninstall_folders' ) ) {
	/**
	 * Membersihkan folder baseline snapshot dan quarantine vault plugin.
	 *
	 * Dilengkapi validasi realpath dan proteksi path traversal untuk memastikan
	 * hanya folder internal plugin di direktori uploads yang dihapus.
	 */
	function wp_root_guard_uninstall_folders() {
		$base_dirs = array();

		$upload_dir = wp_upload_dir();
		if ( ! empty( $upload_dir['basedir'] ) ) {
			$base_dirs[] = $upload_dir['basedir'];
		}

		if ( defined( 'WP_CONTENT_DIR' ) ) {
			$base_dirs[] = WP_CONTENT_DIR . '/uploads';
		}

		$target_subfolders = array(
			'wp-root-guard',
			'wp-root-guard-quarantine',
		);

		$cleaned_paths = array();

		foreach ( $base_dirs as $base_dir ) {
			$real_base = realpath( $base_dir );
			if ( false === $real_base || ! is_dir( $real_base ) ) {
				continue;
			}

			$real_base_norm = rtrim( str_replace( '\\', '/', $real_base ), '/' );

			foreach ( $target_subfolders as $subfolder ) {
				$target_path = $real_base_norm . '/' . $subfolder;

				// Jika target adalah symlink, jangan ikuti; langsung putus symlink-nya.
				if ( is_link( $target_path ) ) {
					@unlink( $target_path );
					continue;
				}

				if ( ! file_exists( $target_path ) ) {
					continue;
				}

				$real_target = realpath( $target_path );
				if ( false === $real_target ) {
					continue;
				}

				$real_target_norm = rtrim( str_replace( '\\', '/', $real_target ), '/' );

				// Hindari pembersihan ganda untuk target path fisik yang sama.
				if ( isset( $cleaned_paths[ $real_target_norm ] ) ) {
					continue;
				}
				$cleaned_paths[ $real_target_norm ] = true;

				// Validasi realpath: pastikan target berada strictly di dalam $real_base_norm
				// dan bukan $real_base_norm itu sendiri.
				if ( $real_target_norm !== $real_base_norm && 0 === strpos( $real_target_norm, $real_base_norm . '/' ) ) {
					wp_root_guard_recursive_delete( $real_target_norm );
				}
			}
		}
	}
}

if ( ! function_exists( 'wp_root_guard_uninstall_site' ) ) {
	/**
	 * Menjalankan pembersihan menyeluruh untuk satu blog/site.
	 *
	 * Meliputi:
	 * - Pembatalan dan pembersihan hooks WP-Cron
	 * - Penghapusan seluruh opsi dan transients (termasuk user-specific)
	 * - Pembersihan aturan root .htaccess
	 * - Penghapusan berkas baseline snapshot dan quarantine vault
	 */
	function wp_root_guard_uninstall_site() {
		global $wpdb;

		// 1. Hapus jadwal cron hooks plugin.
		$timestamp_scan = wp_next_scheduled( 'wp_root_guard_cron_scan' );
		if ( $timestamp_scan ) {
			wp_unschedule_event( $timestamp_scan, 'wp_root_guard_cron_scan' );
		}
		wp_clear_scheduled_hook( 'wp_root_guard_cron_scan' );

		$timestamp_prune = wp_next_scheduled( 'wp_root_guard_prune_ips' );
		if ( $timestamp_prune ) {
			wp_unschedule_event( $timestamp_prune, 'wp_root_guard_prune_ips' );
		}
		wp_clear_scheduled_hook( 'wp_root_guard_prune_ips' );

		// 2. Hapus seluruh opsi plugin dari tabel options.
		$options = array(
			'wp_root_guard_version',
			'wp_root_guard_settings',
			'wp_root_guard_whitelist',
			'wp_root_guard_logs',
			'wp_root_guard_last_scan',
			'wp_root_guard_unknown_folders',
			'wp_root_guard_quarantined_folders',
			'wp_root_guard_notified_threats',
			'wp_root_guard_blocked_ips',
			'wp_root_guard_active_files',
			'wp_root_guard_active_core_threats',
			'wp_root_guard_baseline_folders',
			'wp_root_guard_baseline_files',
		);

		foreach ( $options as $option_name ) {
			delete_option( $option_name );
		}

		// 3. Hapus transients standar plugin via Transients API.
		delete_transient( 'wp_root_guard_core_checksums' );
		delete_transient( 'wp_root_guard_latest_github_release' );
		delete_transient( 'wp_root_guard_htaccess_lock' );
		delete_site_transient( 'wp_root_guard_core_checksums' );
		delete_site_transient( 'wp_root_guard_latest_github_release' );

		// 4. Hapus seluruh transient dinamis / user-specific via $wpdb->prepare query.
		// Menangani transient dengan prefix wprg_ (seperti wprg_scan_rate_{uid}, wprg_fix_error_{uid}, wprg_bulk_fix_errors_{uid})
		// dan opsi/transient tersisa dengan prefix wp_root_guard_.
		if ( ! empty( $wpdb->options ) ) {
			$transient_patterns = array(
				$wpdb->esc_like( '_transient_wprg_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_wprg_' ) . '%',
				$wpdb->esc_like( '_transient_wp_root_guard_' ) . '%',
				$wpdb->esc_like( '_transient_timeout_wp_root_guard_' ) . '%',
				$wpdb->esc_like( '_site_transient_wp_root_guard_' ) . '%',
				$wpdb->esc_like( '_site_transient_timeout_wp_root_guard_' ) . '%',
				$wpdb->esc_like( 'wp_root_guard_' ) . '%',
			);

			foreach ( $transient_patterns as $pattern ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->query(
					$wpdb->prepare(
						"DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
						$pattern
					)
				);
			}
		}

		// Bersihkan sitemeta jika berada dalam konteks multisite.
		if ( ! empty( $wpdb->sitemeta ) ) {
			$sitemeta_patterns = array(
				$wpdb->esc_like( '_site_transient_wp_root_guard_' ) . '%',
				$wpdb->esc_like( '_site_transient_timeout_wp_root_guard_' ) . '%',
				$wpdb->esc_like( 'wp_root_guard_' ) . '%',
			);

			foreach ( $sitemeta_patterns as $pattern ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery
				$wpdb->query(
					$wpdb->prepare(
						"DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s",
						$pattern
					)
				);
			}
		}

		// 5. Bersihkan aturan blokir IP dari root .htaccess.
		wp_root_guard_uninstall_htaccess();

		// 6. Bersihkan direktori baseline snapshot dan quarantine vault.
		wp_root_guard_uninstall_folders();
	}
}

// Eksekusi uninstall: dukung WordPress Multisite dan Single Site.
if ( is_multisite() ) {
	$wprg_sites = get_sites( array( 'number' => 0 ) );
	if ( ! empty( $wprg_sites ) && is_array( $wprg_sites ) ) {
		foreach ( $wprg_sites as $wprg_site ) {
			$wprg_blog_id = is_object( $wprg_site ) ? (int) $wprg_site->blog_id : (int) $wprg_site;
			switch_to_blog( $wprg_blog_id );
			wp_root_guard_uninstall_site();
			restore_current_blog();
		}
	}
} else {
	wp_root_guard_uninstall_site();
}
