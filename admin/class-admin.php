<?php
/**
 * Mengelola halaman menu admin, penanganan aksi, dan notifikasi.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard\Admin;

use WPRootGuard\Settings;
use WPRootGuard\Baseline;
use WPRootGuard\Scanner;
use WPRootGuard\Logger;
use WPRootGuard\Cron;
use WPRootGuard\Blocker;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Admin
 *
 * Mengelola semua aspek administratif plugin di dasbor WordPress.
 */
class Admin {

	/**
	 * Mendaftarkan hooks administratif.
	 */
	public function init() {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_init', array( $this, 'handle_admin_actions' ) );
		add_action( 'admin_notices', array( $this, 'render_threat_notice' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_styles' ) );

		// Tambahkan link "Settings" pada daftar plugin WordPress.
		add_filter( 'plugin_action_links_' . plugin_basename( WP_ROOT_GUARD_FILE ), array( $this, 'add_action_links' ) );

		// AJAX Actions untuk pemindaian dinamis interaktif dan inspeksi kode
		add_action( 'wp_ajax_wp_root_guard_get_scan_queue', array( $this, 'ajax_get_scan_queue' ) );
		add_action( 'wp_ajax_wp_root_guard_run_scan', array( $this, 'ajax_run_scan' ) );
		add_action( 'wp_ajax_wp_root_guard_inspect_file', array( $this, 'ajax_inspect_file' ) );
	}

	/**
	 * Mendaftarkan submenu di bawah menu Dashboard (index.php).
	 */
	public function register_menu() {
		add_submenu_page(
			'index.php',
			esc_html__( 'WP Root Guard', 'wp-root-guard' ),
			esc_html__( 'Root Guard', 'wp-root-guard' ),
			'manage_options',
			'wp-root-guard',
			array( $this, 'render_admin_page' )
		);
	}

	/**
	 * Memuat berkas CSS khusus admin untuk halaman plugin.
	 *
	 * @param string $hook Halaman admin saat ini.
	 */
	public function enqueue_styles( $hook ) {
		if ( 'dashboard_page_wp-root-guard' !== $hook ) {
			return;
		}

		wp_enqueue_style(
			'wp-root-guard-admin-css',
			WP_ROOT_GUARD_URL . 'admin/css/wp-root-guard-admin.css',
			array(),
			WP_ROOT_GUARD_VERSION
		);
	}

	/**
	 * Menambahkan tautan "Settings" ke baris plugin di halaman Plugins WordPress.
	 *
	 * @param array $links Array tautan aksi plugin bawaan.
	 * @return array Array tautan yang telah ditambahkan.
	 */
	public function add_action_links( $links ) {
		$settings_link = '<a href="' . admin_url( 'index.php?page=wp-root-guard&tab=settings' ) . '">' . esc_html__( 'Settings', 'wp-root-guard' ) . '</a>';
		$check_link    = '<a href="' . wp_nonce_url( admin_url( 'plugins.php?wp_root_guard_check_update=1' ), 'wp_root_guard_check_update' ) . '">' . esc_html__( 'Check Update', 'wp-root-guard' ) . '</a>';
		array_unshift( $links, $settings_link );
		$links[] = $check_link;
		return $links;
	}

	/**
	 * Menampilkan notifikasi admin merah jika ada folder/berkas asing aktif terdeteksi.
	 */
	public function render_threat_notice() {
		$screen = get_current_screen();
		if ( $screen && 'dashboard_page_wp-root-guard' === $screen->id ) {
			return;
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$unknown_folders = Scanner::get_unknown_folders();

		$active_threats = 0;
		foreach ( $unknown_folders as $item ) {
			if ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) !== $item['status'] ) {
				$active_threats++;
			}
		}

		if ( $active_threats > 0 ) {
			$dashboard_url = admin_url( 'index.php?page=wp-root-guard' );
			?>
			<div class="notice notice-error is-dismissible" style="border-left-color: #d63638; padding: 12px 20px;">
				<p style="font-size: 14px; margin: 0 0 6px 0; font-weight: bold; color: #1d2327;">
					⚠️ <?php esc_html_e( 'WP Root Guard: Ancaman Aktif Terdeteksi!', 'wp-root-guard' ); ?>
				</p>
				<p style="margin: 0 0 8px 0; color: #50575e;">
					<?php
					echo esc_html(
						sprintf(
							/* translators: %d: jumlah ancaman */
							_n( 'Ditemukan %d folder atau berkas asing/core yang tidak dikenal atau berubah di WordPress Anda dan belum diamankan. Harap segera amankan!', 'Ditemukan %d folder atau berkas asing/core yang tidak dikenal atau berubah di WordPress Anda dan belum diamankan. Harap segera amankan!', $active_threats, 'wp-root-guard' ),
							$active_threats
						)
					);
					?>
				</p>
				<p style="margin: 0;">
					<a href="<?php echo esc_url( $dashboard_url ); ?>" class="button button-primary" style="background-color: #d63638; border-color: #d63638; box-shadow: none; text-shadow: none;">
						<?php esc_html_e( 'Periksa Sekarang', 'wp-root-guard' ); ?>
					</a>
				</p>
			</div>
			<?php
		}
	}

	/**
	 * Menangani aksi tombol yang ditekan (Scan, Rebuild, Trust, dll).
	 */
	public function handle_admin_actions() {
		// Penanganan untuk aksi GET "Check Update" dari daftar plugin
		if ( isset( $_GET['wp_root_guard_check_update'] ) ) {
			if ( isset( $_GET['_wpnonce'] ) && wp_verify_nonce( $_GET['_wpnonce'], 'wp_root_guard_check_update' ) && current_user_can( 'manage_options' ) ) {
				delete_transient( 'wp_root_guard_latest_github_release' );
				delete_site_transient( 'update_plugins' );
				if ( function_exists( 'wp_update_plugins' ) ) {
					wp_update_plugins();
				}
				wp_safe_redirect( admin_url( 'plugins.php' ) );
				exit;
			}
		}

		if ( ! isset( $_POST['wp_root_guard_action_nonce'] ) ) {
			return;
		}

		if ( ! wp_verify_nonce( $_POST['wp_root_guard_action_nonce'], 'wp_root_guard_admin_action' ) ) {
			wp_die( esc_html__( 'Verifikasi keamanan gagal. Silakan coba lagi.', 'wp-root-guard' ) );
		}

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'Anda tidak memiliki izin untuk melakukan aksi ini.', 'wp-root-guard' ) );
		}

		$action = isset( $_POST['rg_action'] ) ? sanitize_text_field( $_POST['rg_action'] ) : '';

		$current_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'dashboard';
		$redirect_url = admin_url( 'index.php?page=wp-root-guard&tab=' . $current_tab );

		switch ( $action ) {
			case 'scan_now':
				Scanner::perform_scan();
				wp_safe_redirect( add_query_arg( 'message', 'scanned', $redirect_url ) );
				exit;

			case 'rebuild_baseline':
				Baseline::rebuild_baseline();
				Scanner::perform_scan();
				wp_safe_redirect( add_query_arg( 'message', 'rebuilt', $redirect_url ) );
				exit;

			case 'reset_baseline':
				Baseline::reset_baseline();
				delete_option( 'wp_root_guard_last_scan' );
				delete_option( 'wp_root_guard_unknown_folders' );
				Logger::log( esc_html__( 'Baseline direset oleh administrator', 'wp-root-guard' ), '-', esc_html__( 'Reset', 'wp-root-guard' ) );
				wp_safe_redirect( add_query_arg( 'message', 'reset', $redirect_url ) );
				exit;

			case 'trust_folder':
				$folder = isset( $_POST['folder'] ) ? sanitize_text_field( $_POST['folder'] ) : '';
				if ( ! empty( $folder ) ) {
					Settings::add_to_whitelist( $folder );
					Logger::log(
						esc_html__( 'Folder/Berkas dipercayai (Whitelist)', 'wp-root-guard' ),
						$folder,
						esc_html__( 'Trusted', 'wp-root-guard' )
					);
					Scanner::perform_scan();
					wp_safe_redirect( add_query_arg( 'message', 'trusted', $redirect_url ) );
					exit;
				}
				break;

			case 'untrust_folder':
				$folder = isset( $_POST['folder'] ) ? sanitize_text_field( $_POST['folder'] ) : '';
				if ( ! empty( $folder ) ) {
					Settings::remove_from_whitelist( $folder );
					Logger::log(
						esc_html__( 'Folder/Berkas dihapus dari Whitelist', 'wp-root-guard' ),
						$folder,
						esc_html__( 'Untrusted', 'wp-root-guard' )
					);
					Scanner::perform_scan();
					wp_safe_redirect( add_query_arg( 'message', 'untrusted', $redirect_url ) );
					exit;
				}
				break;

			case 'quarantine_file':
				$file = isset( $_POST['folder'] ) ? sanitize_text_field( $_POST['folder'] ) : '';
				if ( ! empty( $file ) ) {
					if ( false !== strpos( $file, '/' ) ) {
						$success = Scanner::quarantine_core_file( $file );
					} else {
						$success = Scanner::quarantine_file( $file );
					}

					if ( $success ) {
						Scanner::perform_scan();
						wp_safe_redirect( add_query_arg( 'message', 'quarantined', $redirect_url ) );
					} else {
						wp_safe_redirect( add_query_arg( 'message', 'quarantine_failed', $redirect_url ) );
					}
					exit;
				}
				break;

			case 'delete_file_directly':
				$file = isset( $_POST['folder'] ) ? sanitize_text_field( $_POST['folder'] ) : '';
				if ( ! empty( $file ) ) {
					$success = Scanner::delete_file_directly( $file );
					if ( $success ) {
						Scanner::perform_scan();
						wp_safe_redirect( add_query_arg( 'message', 'file_deleted', $redirect_url ) );
					} else {
						wp_safe_redirect( add_query_arg( 'message', 'delete_failed', $redirect_url ) );
					}
					exit;
				}
				break;

			case 'fix_core_file':
				$file = isset( $_POST['folder'] ) ? sanitize_text_field( $_POST['folder'] ) : '';
				if ( ! empty( $file ) ) {
					$success = Scanner::restore_core_file( $file );
					if ( $success ) {
						Scanner::perform_scan();
						wp_safe_redirect( add_query_arg( 'message', 'core_fixed', $redirect_url ) );
					} else {
						wp_safe_redirect( add_query_arg( 'message', 'core_fix_failed', $redirect_url ) );
					}
					exit;
				}
				break;

			case 'clear_logs':
				Logger::clear_logs();
				wp_safe_redirect( add_query_arg( 'message', 'logs_cleared', $redirect_url ) );
				exit;

			case 'block_ip':
				$ip     = isset( $_POST['ip_address'] ) ? sanitize_text_field( $_POST['ip_address'] ) : '';
				$reason = isset( $_POST['ip_reason'] ) ? sanitize_text_field( $_POST['ip_reason'] ) : '';
				if ( ! empty( $ip ) ) {
					Blocker::block_ip( $ip, $reason );
					wp_safe_redirect( add_query_arg( 'message', 'ip_blocked', $redirect_url ) );
					exit;
				}
				break;

			case 'unblock_ip':
				$ip = isset( $_POST['target_folder'] ) ? sanitize_text_field( $_POST['target_folder'] ) : '';
				if ( ! empty( $ip ) ) {
					Blocker::unblock_ip( $ip );
					wp_safe_redirect( add_query_arg( 'message', 'ip_unblocked', $redirect_url ) );
					exit;
				}
				break;

			case 'bulk_action':
				$action_type = isset( $_POST['bulk_action_type'] ) ? sanitize_text_field( $_POST['bulk_action_type'] ) : '';
				$items       = isset( $_POST['bulk_items'] ) && is_array( $_POST['bulk_items'] ) ? array_map( 'sanitize_text_field', $_POST['bulk_items'] ) : array();

				if ( ! empty( $action_type ) && ! empty( $items ) ) {
					$success_count = 0;
					foreach ( $items as $item ) {
						if ( 'bulk_trust' === $action_type ) {
							if ( Settings::add_to_whitelist( $item ) ) {
								$success_count++;
							}
						} elseif ( 'bulk_quarantine' === $action_type ) {
							if ( false !== strpos( $item, '/' ) ) {
								$res = Scanner::quarantine_core_file( $item );
							} else {
								$res = Scanner::quarantine_file( $item );
							}
							if ( false !== $res ) {
								$success_count++;
							}
						} elseif ( 'bulk_delete' === $action_type ) {
							if ( Scanner::delete_file_directly( $item ) ) {
								$success_count++;
							}
						}
					}

					Scanner::perform_scan();

					if ( 'bulk_trust' === $action_type ) {
						wp_safe_redirect( add_query_arg( array( 'message' => 'bulk_trusted', 'count' => $success_count ), $redirect_url ) );
					} elseif ( 'bulk_quarantine' === $action_type ) {
						wp_safe_redirect( add_query_arg( array( 'message' => 'bulk_quarantined', 'count' => $success_count ), $redirect_url ) );
					} elseif ( 'bulk_delete' === $action_type ) {
						wp_safe_redirect( add_query_arg( array( 'message' => 'bulk_deleted', 'count' => $success_count ), $redirect_url ) );
					}
					exit;
				}
				break;

			case 'save_settings':
				$settings_data = array(
					'scan_interval'                => isset( $_POST['scan_interval'] ) ? sanitize_text_field( $_POST['scan_interval'] ) : 'every_5_minutes',
					'enable_uploads_php_scan'      => isset( $_POST['enable_uploads_php_scan'] ),
					'enable_auto_quarantine'       => isset( $_POST['enable_auto_quarantine'] ),
					'enable_email_notifications'    => isset( $_POST['enable_email_notifications'] ),
					'admin_email'                  => isset( $_POST['admin_email'] ) ? sanitize_text_field( $_POST['admin_email'] ) : '',
					'enable_telegram_notifications' => isset( $_POST['enable_telegram_notifications'] ),
					'telegram_bot_token'           => isset( $_POST['telegram_bot_token'] ) ? sanitize_text_field( $_POST['telegram_bot_token'] ) : '',
					'telegram_chat_id'             => isset( $_POST['telegram_chat_id'] ) ? sanitize_text_field( $_POST['telegram_chat_id'] ) : '',
				);
				Settings::update_settings( $settings_data );
				Logger::log( esc_html__( 'Pengaturan plugin diperbarui', 'wp-root-guard' ), '-', esc_html__( 'Success', 'wp-root-guard' ) );
				wp_safe_redirect( add_query_arg( 'message', 'settings_saved', $redirect_url ) );
				exit;

			case 'test_telegram':
				$token   = isset( $_POST['telegram_bot_token'] ) ? sanitize_text_field( $_POST['telegram_bot_token'] ) : '';
				$chat_id = isset( $_POST['telegram_chat_id'] ) ? sanitize_text_field( $_POST['telegram_chat_id'] ) : '';
				
				$site_name = get_bloginfo( 'name' );
				$site_url  = home_url();
				$message   = "🔔 *[WP Root Guard] Pesan Uji Coba!*\n\nKoneksi bot Telegram Anda ke situs *{$site_name}* ({$site_url}) berhasil terhubung dengan sukses.";

				$success = Scanner::send_telegram_message( $token, $chat_id, $message );
				
				if ( $success ) {
					wp_safe_redirect( add_query_arg( 'message', 'tg_test_success', $redirect_url ) );
				} else {
					wp_safe_redirect( add_query_arg( 'message', 'tg_test_failed', $redirect_url ) );
				}
				exit;

			case 'test_email':
				$email     = isset( $_POST['admin_email'] ) ? sanitize_email( $_POST['admin_email'] ) : '';
				$site_name = get_bloginfo( 'name' );
				$subject   = esc_html__( '[WP Root Guard] Pesan Uji Coba Notifikasi', 'wp-root-guard' );
				
				$email_body  = esc_html__( 'Halo Administrator,', 'wp-root-guard' ) . "\r\n\r\n";
				$email_body .= sprintf( /* translators: %s: nama situs */ esc_html__( 'Ini adalah email uji coba notifikasi keamanan dari WP Root Guard di situs Anda (%s).', 'wp-root-guard' ), $site_name ) . "\r\n\r\n";
				$email_body .= esc_html__( 'Koneksi pengiriman email berjalan dengan lancar.', 'wp-root-guard' ) . "\r\n";

				$success = wp_mail( $email, $subject, $email_body );
				
				if ( $success ) {
					wp_safe_redirect( add_query_arg( 'message', 'email_test_success', $redirect_url ) );
				} else {
					wp_safe_redirect( add_query_arg( 'message', 'email_test_failed', $redirect_url ) );
				}
				exit;

			case 'restore_folder':
				$folder = isset( $_POST['folder'] ) ? sanitize_text_field( $_POST['folder'] ) : '';
				if ( ! empty( $folder ) ) {
					$success = Scanner::restore_quarantined_folder( $folder );
					if ( $success ) {
						Scanner::perform_scan();
						wp_safe_redirect( add_query_arg( 'message', 'restored', $redirect_url ) );
					} else {
						wp_safe_redirect( add_query_arg( 'message', 'restore_failed', $redirect_url ) );
					}
					exit;
				}
				break;

			case 'delete_permanently':
				$folder = isset( $_POST['folder'] ) ? sanitize_text_field( $_POST['folder'] ) : '';
				if ( ! empty( $folder ) ) {
					$success = Scanner::delete_quarantined_folder_permanently( $folder );
					if ( $success ) {
						Scanner::perform_scan();
						wp_safe_redirect( add_query_arg( 'message', 'deleted_permanently', $redirect_url ) );
					} else {
						wp_safe_redirect( add_query_arg( 'message', 'delete_failed', $redirect_url ) );
					}
					exit;
				}
				break;
		}
	}

	/**
	 * AJAX Handler untuk mengambil antrean (queue) item yang akan dipindai.
	 */
	public function ajax_get_scan_queue() {
		check_ajax_referer( 'wp_root_guard_admin_action', 'security' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Akses ditolak.', 'wp-root-guard' ) ) );
		}

		$queue = array();

		// 1. Ambil folder root
		$folders = Baseline::scan_root_folders();
		foreach ( $folders as $folder ) {
			$queue[] = array(
				'type' => 'folder',
				'name' => $folder,
			);
		}

		// 2. Ambil berkas root
		$files = Baseline::scan_root_files();
		foreach ( array_keys( $files ) as $file ) {
			$queue[] = array(
				'type' => 'file',
				'name' => $file,
			);
		}

		// 3. Tambahkan beberapa file inti penting (wp-admin/wp-includes) untuk simulasi scanner
		$checksums = Scanner::get_core_checksums();
		if ( is_array( $checksums ) ) {
			$core_keys = array_keys( $checksums );
			shuffle( $core_keys );
			$limit = min( count( $core_keys ), 40 );
			for ( $i = 0; $i < $limit; $i++ ) {
				$queue[] = array(
					'type' => 'core',
					'name' => $core_keys[ $i ],
				);
			}
		}

		wp_send_json_success( array( 'queue' => $queue ) );
	}

	/**
	 * AJAX Handler untuk menjalankan pemindaian backend yang sesungguhnya secara instan.
	 */
	public function ajax_run_scan() {
		check_ajax_referer( 'wp_root_guard_admin_action', 'security' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Akses ditolak.', 'wp-root-guard' ) ) );
		}

		Scanner::perform_scan();

		wp_send_json_success( array( 'message' => esc_html__( 'Pemindaian selesai.', 'wp-root-guard' ) ) );
	}

	/**
	 * AJAX Handler untuk menginspeksi isi berkas secara aman.
	 */
	public function ajax_inspect_file() {
		check_ajax_referer( 'wp_root_guard_admin_action', 'security' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error( array( 'message' => esc_html__( 'Akses ditolak.', 'wp-root-guard' ) ) );
		}

		$file = isset( $_POST['file'] ) ? sanitize_text_field( $_POST['file'] ) : '';
		$res  = Scanner::inspect_file_content( $file );

		if ( isset( $res['success'] ) && $res['success'] ) {
			wp_send_json_success( $res );
		} else {
			wp_send_json_error( $res );
		}
	}

	/**
	 * Merender halaman utama dashboard admin Root Guard.
	 */
	public function render_admin_page() {
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'dashboard';

		// Data Konfigurasi & Opsi
		$settings        = Settings::get_settings();
		$results         = Scanner::get_last_scan_results();
		$unknown_folders = Scanner::get_unknown_folders();
		$quarantined     = get_option( 'wp_root_guard_quarantined_folders', array() );
		$user_whitelist  = Settings::get_user_whitelist();
		$baseline_list   = Baseline::get_baseline_folders();
		$baseline_files  = Baseline::get_baseline_files();
		$logs            = Logger::get_logs();

		// Hitung data ringkasan (Summary)
		$protected_count   = count( $baseline_list ) + count( $baseline_files ) + count( $user_whitelist );
		$whitelisted_count = count( Settings::get_default_whitelist() ) + count( Settings::get_default_file_whitelist() ) + count( $user_whitelist );
		$unknown_count     = count( $unknown_folders );
		$quarantine_count  = is_array( $quarantined ) ? count( $quarantined ) : 0;

		$last_scan_time = ! empty( $results['last_scan'] ) ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $results['last_scan'] ) ) : esc_html__( 'Belum pernah dipindai', 'wp-root-guard' );

		$next_cron      = wp_next_scheduled( 'wp_root_guard_cron_scan' );
		$next_scan_time = $next_cron ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_cron ) : esc_html__( 'Tidak dijadwalkan', 'wp-root-guard' );

		$message_code = isset( $_GET['message'] ) ? sanitize_text_field( $_GET['message'] ) : '';
		$notice_text  = '';
		$notice_class = 'notice-success';

		switch ( $message_code ) {
			case 'scanned':
				$notice_text = esc_html__( 'Pemindaian root & berkas core selesai.', 'wp-root-guard' );
				break;
			case 'rebuilt':
				$notice_text = esc_html__( 'Baseline folder & berkas berhasil dibangun ulang.', 'wp-root-guard' );
				break;
			case 'reset':
				$notice_text = esc_html__( 'Baseline berhasil direset. Silakan bangun ulang baseline baru.', 'wp-root-guard' );
				break;
			case 'trusted':
				$notice_text = esc_html__( 'Folder/Berkas berhasil ditambahkan ke whitelist kustom.', 'wp-root-guard' );
				break;
			case 'untrusted':
				$notice_text = esc_html__( 'Folder/Berkas berhasil dihapus dari whitelist kustom.', 'wp-root-guard' );
				break;
			case 'quarantined':
				$notice_text = esc_html__( 'Berkas berhasil dipindahkan ke karantina.', 'wp-root-guard' );
				break;
			case 'quarantine_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal mengkarantina berkas. Pastikan perizinan berkas di server Anda benar.', 'wp-root-guard' );
				break;
			case 'file_deleted':
				$notice_text = esc_html__( 'Berkas asing/penyusup berhasil dihapus secara permanen dari server.', 'wp-root-guard' );
				break;
			case 'ip_blocked':
				$notice_text = esc_html__( 'Alamat IP penyerang berhasil diblokir dan aturan .htaccess diperbarui.', 'wp-root-guard' );
				break;
			case 'ip_unblocked':
				$notice_text = esc_html__( 'Blokir alamat IP berhasil dibuka.', 'wp-root-guard' );
				break;
			case 'bulk_trusted':
				$count = isset( $_GET['count'] ) ? intval( $_GET['count'] ) : 0;
				$notice_text = sprintf( /* translators: %d: jumlah */ esc_html__( '%d item ancaman berhasil ditambahkan ke whitelist kustom.', 'wp-root-guard' ), $count );
				break;
			case 'bulk_quarantined':
				$count = isset( $_GET['count'] ) ? intval( $_GET['count'] ) : 0;
				$notice_text = sprintf( /* translators: %d: jumlah */ esc_html__( '%d item ancaman berhasil dipindahkan ke karantina.', 'wp-root-guard' ), $count );
				break;
			case 'bulk_deleted':
				$count = isset( $_GET['count'] ) ? intval( $_GET['count'] ) : 0;
				$notice_text = sprintf( /* translators: %d: jumlah berkas */ esc_html__( '%d berkas ancaman berhasil dihapus secara permanen dari server.', 'wp-root-guard' ), $count );
				break;
			case 'delete_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal menghapus berkas. Pastikan perizinan berkas (file permissions) di server Anda benar.', 'wp-root-guard' );
				break;
			case 'core_fixed':
				$notice_text = esc_html__( 'Berkas core WordPress berhasil diperbaiki ke keadaan asli.', 'wp-root-guard' );
				break;
			case 'core_fix_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal memulihkan berkas core dari server WordPress.org.', 'wp-root-guard' );
				break;
			case 'logs_cleared':
				$notice_text = esc_html__( 'Riwayat log berhasil dibersihkan.', 'wp-root-guard' );
				break;
			case 'settings_saved':
				$notice_text = esc_html__( 'Pengaturan berhasil disimpan.', 'wp-root-guard' );
				break;
			case 'tg_test_success':
				$notice_text = esc_html__( 'Koneksi bot Telegram berhasil! Pesan uji coba telah dikirim.', 'wp-root-guard' );
				break;
			case 'tg_test_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal mengirim pesan ke Telegram. Mohon periksa Bot Token dan Chat ID Anda.', 'wp-root-guard' );
				break;
			case 'email_test_success':
				$notice_text = esc_html__( 'Email uji coba berhasil dikirim ke alamat email tujuan.', 'wp-root-guard' );
				break;
			case 'email_test_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal mengirim email uji coba. Mohon periksa kembali konfigurasi email server Anda.', 'wp-root-guard' );
				break;
			case 'restored':
				$notice_text = esc_html__( 'Berkas/Folder berhasil dipulihkan dari karantina ke posisi root asal.', 'wp-root-guard' );
				break;
			case 'restore_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal memulihkan. Pastikan tidak ada berkas/folder dengan nama yang sama di root.', 'wp-root-guard' );
				break;
			case 'deleted_permanently':
				$notice_text = esc_html__( 'Item karantina berhasil dihapus secara permanen dari server.', 'wp-root-guard' );
				break;
			case 'delete_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal menghapus item karantina dari server.', 'wp-root-guard' );
				break;
		}

		?>
		<div class="wrap wp-root-guard-wrap">
			<h1 class="wp-heading-inline"><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<hr class="wp-header-end">

			<?php if ( ! empty( $notice_text ) ) : ?>
				<div class="notice <?php echo esc_attr( $notice_class ); ?> is-dismissible">
					<p><?php echo esc_html( $notice_text ); ?></p>
				</div>
			<?php endif; ?>

			<!-- Tab Navigation -->
			<h2 class="nav-tab-wrapper rg-nav-tabs">
				<a href="?page=wp-root-guard&tab=dashboard" class="nav-tab <?php echo 'dashboard' === $active_tab ? 'nav-tab-active' : ''; ?>">
					📊 <?php esc_html_e( 'Dashboard', 'wp-root-guard' ); ?>
				</a>
				<a href="?page=wp-root-guard&tab=settings" class="nav-tab <?php echo 'settings' === $active_tab ? 'nav-tab-active' : ''; ?>">
					⚙️ <?php esc_html_e( 'Pengaturan', 'wp-root-guard' ); ?>
				</a>
			</h2>

			<!-- Form Nonce Bersama -->
			<form id="rg-action-form" method="post" action="">
				<?php wp_nonce_field( 'wp_root_guard_admin_action', 'wp_root_guard_action_nonce' ); ?>
				<input type="hidden" name="rg_action" id="rg-action-field" value="">
				<input type="hidden" name="folder" id="rg-folder-field" value="">
			</form>

			<?php if ( 'dashboard' === $active_tab ) : ?>
				<!-- TAB 1: DASHBOARD CONTENT -->

				<!-- MODAL POP-UP COMPARATIVE DIFF VIEWER -->
				<?php
				$view_diff_file = isset( $_GET['view_diff'] ) ? sanitize_text_field( $_GET['view_diff'] ) : '';
				if ( ! empty( $view_diff_file ) ) :
					$diff = Scanner::get_file_diff( $view_diff_file );
					?>
					<div class="rg-modal-overlay">
						<div class="rg-modal-container">
							<div class="rg-modal-header">
								<h2>🔍 <?php printf( /* translators: %s: nama file */ esc_html__( 'Bandingkan Kode: %s', 'wp-root-guard' ), esc_html( $view_diff_file ) ); ?></h2>
								<a href="?page=wp-root-guard&tab=dashboard" class="rg-modal-close">&times;</a>
							</div>
							<div class="rg-modal-body">
								<p class="rg-field-desc" style="margin-bottom: 15px;">
									<?php esc_html_e( 'Berikut perbedaan kode baris yang terdeteksi antara berkas lokal Anda (merah) dan berkas asli bawaan dari server resmi WordPress.org (hijau).', 'wp-root-guard' ); ?>
								</p>

								<?php if ( isset( $diff['error'] ) ) : ?>
									<div class="notice notice-error inline" style="margin: 0;">
										<p><?php echo esc_html( $diff['error'] ); ?></p>
									</div>
								<?php elseif ( empty( $diff ) ) : ?>
									<div class="notice notice-success inline" style="margin: 0; padding: 15px;">
										<p>✅ <?php esc_html_e( 'Tidak ada perbedaan kode baris yang ditemukan. Berkas lokal sama persis dengan berkas asli resmi.', 'wp-root-guard' ); ?></p>
									</div>
								<?php else : ?>
									<div class="rg-diff-wrapper" style="max-height: 450px; overflow-y: auto; border: 1px solid #cbd5e1; border-radius: 6px;">
										<table class="rg-diff-table" style="width: 100%; border-collapse: collapse; font-family: monospace; font-size: 13px;">
											<thead>
												<tr style="background-color: #f1f5f9; border-bottom: 2px solid #cbd5e1; text-align: left;">
													<th style="padding: 8px 10px; width: 60px; border-right: 1px solid #cbd5e1;"><?php esc_html_e( 'Baris', 'wp-root-guard' ); ?></th>
													<th style="padding: 8px 12px; background-color: #f0fdf4; color: #15803d; border-right: 1px solid #cbd5e1;"><?php esc_html_e( 'Berkas Asli (WordPress.org)', 'wp-root-guard' ); ?></th>
													<th style="padding: 8px 12px; background-color: #fef2f2; color: #b91c1c;"><?php esc_html_e( 'Berkas Lokal Anda', 'wp-root-guard' ); ?></th>
												</tr>
											</thead>
											<tbody>
												<?php foreach ( $diff as $line ) : ?>
													<tr style="border-bottom: 1px solid #e2e8f0;">
														<td style="padding: 6px 10px; text-align: center; font-weight: bold; background-color: #f8fafc; border-right: 1px solid #cbd5e1; color: #64748b;"><?php echo esc_html( $line['line'] ); ?></td>
														<td style="padding: 6px 12px; background-color: #f6fdf9; border-right: 1px solid #cbd5e1; white-space: pre-wrap; word-break: break-all; color: #166534;"><?php echo esc_html( $line['original'] ); ?></td>
														<td style="padding: 6px 12px; background-color: #fff5f5; white-space: pre-wrap; word-break: break-all; color: #991b1b;"><?php echo esc_html( $line['local'] ); ?></td>
													</tr>
												<?php endforeach; ?>
											</tbody>
										</table>
									</div>
								<?php endif; ?>
							</div>
							<div class="rg-modal-footer" style="display: flex; justify-content: flex-end; gap: 10px;">
								<a href="?page=wp-root-guard&tab=dashboard" class="button button-secondary"><?php esc_html_e( 'Tutup', 'wp-root-guard' ); ?></a>
								<form method="post" action="" style="margin: 0;">
									<?php wp_nonce_field( 'wp_root_guard_admin_action', 'wp_root_guard_action_nonce' ); ?>
									<input type="hidden" name="rg_action" value="fix_core_file">
									<input type="hidden" name="folder" value="<?php echo esc_attr( $view_diff_file ); ?>">
									<button type="submit" class="button button-primary" style="background-color: #10b981; border-color: #10b981;">
										🛠️ <?php esc_html_e( 'Perbaiki Berkas Sekarang', 'wp-root-guard' ); ?>
									</button>
								</form>
							</div>
						</div>
					</div>
				<?php endif; ?>

				<!-- Baris Atas: Status Card & Ringkasan -->
				<div class="rg-dashboard-grid">
					
					<!-- STATUS CARD -->
					<div id="rg-status-card" class="rg-card rg-status-card <?php echo 'safe' === $results['status'] ? 'rg-status-safe' : 'rg-status-threat'; ?>">
						<div class="rg-card-header">
							<h2><?php esc_html_e( 'Status Perlindungan', 'wp-root-guard' ); ?></h2>
						</div>
						<div class="rg-card-body text-center">
							<div class="rg-status-badge">
								<?php if ( 'safe' === $results['status'] ) : ?>
									<span class="rg-icon-large">🛡️</span>
									<span class="rg-status-text text-safe"><?php esc_html_e( 'AMAN', 'wp-root-guard' ); ?></span>
									<p class="rg-status-desc"><?php esc_html_e( 'Tidak ada folder, berkas asing, atau berkas core bermasalah yang terdeteksi.', 'wp-root-guard' ); ?></p>
								<?php else : ?>
									<span class="rg-icon-large">⚠️</span>
									<span class="rg-status-text text-danger"><?php esc_html_e( 'BAHAYA', 'wp-root-guard' ); ?></span>
									<p class="rg-status-desc"><?php esc_html_e( 'Terdeteksi ancaman berkas/folder asing atau modifikasi core aktif!', 'wp-root-guard' ); ?></p>
								<?php endif; ?>
							</div>
						</div>
					</div>

					<!-- SUMMARY CARD -->
					<div id="rg-summary-card" class="rg-card rg-summary-card">
						<div class="rg-card-header">
							<h2><?php esc_html_e( 'Ringkasan Sistem', 'wp-root-guard' ); ?></h2>
						</div>
						<div class="rg-card-body">
							<table class="rg-summary-table">
								<tr>
									<th><?php esc_html_e( 'Item Terlindungi (Baseline + User Whitelist):', 'wp-root-guard' ); ?></th>
									<td><strong><?php echo esc_html( $protected_count ); ?></strong></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Item Whitelisted (Default + Kustom):', 'wp-root-guard' ); ?></th>
									<td><strong><?php echo esc_html( $whitelisted_count ); ?></strong></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Folder/Berkas Asing Terdeteksi:', 'wp-root-guard' ); ?></th>
									<td><strong class="<?php echo $unknown_count > 0 ? 'text-danger' : ''; ?>"><?php echo esc_html( $unknown_count ); ?></strong></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Item dalam Karantina:', 'wp-root-guard' ); ?></th>
									<td><strong><?php echo esc_html( $quarantine_count ); ?></strong></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Pemindaian Terakhir:', 'wp-root-guard' ); ?></th>
									<td><?php echo esc_html( $last_scan_time ); ?></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Pemindaian Berikutnya (WP Cron):', 'wp-root-guard' ); ?></th>
									<td><?php echo esc_html( $next_scan_time ); ?></td>
								</tr>
							</table>
						</div>
					</div>

					<!-- INLINE SCANNER PANEL -->
					<div id="rg-scan-inline-card" class="rg-card hidden" style="grid-column: 1 / -1; background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%); color: #ffffff; border: none; border-radius: 12px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); margin-bottom: 0;">
						<div class="rg-card-body" style="padding: 40px 30px; text-align: center;">
							<div class="rg-scanner-shield">
								<span class="rg-shield-icon">🛡️</span>
								<div class="rg-pulse-wave wave1"></div>
								<div class="rg-pulse-wave wave2"></div>
							</div>
							
							<h2 style="font-size: 22px; font-weight: 800; color: #ffffff; margin: 25px 0 10px 0; letter-spacing: 0.5px;">
								<?php esc_html_e( 'Memindai Direktori Root & Berkas Core...', 'wp-root-guard' ); ?>
							</h2>
							
							<div id="rg-scan-percentage" style="font-size: 44px; font-weight: 900; color: #3b82f6; margin-bottom: 20px; text-shadow: 0 0 15px rgba(59, 130, 246, 0.4);">
								0%
							</div>

							<div style="background-color: rgba(255, 255, 255, 0.1); height: 8px; border-radius: 20px; overflow: hidden; margin-bottom: 20px; max-width: 600px; margin-left: auto; margin-right: auto; border: 1px solid rgba(255, 255, 255, 0.05);">
								<div id="rg-scan-bar" style="background: linear-gradient(90deg, #3b82f6 0%, #60a5fa 100%); width: 0%; height: 100%; border-radius: 20px; transition: width 0.1s ease; box-shadow: 0 0 10px rgba(59, 130, 246, 0.5);"></div>
							</div>

							<div style="font-size: 13px; font-weight: 600; color: #94a3b8; min-height: 20px; margin-bottom: 10px;"><?php esc_html_e( 'Sedang memproses:', 'wp-root-guard' ); ?></div>
							<div id="rg-scan-current-item" style="font-family: monospace; font-size: 12px; color: #38bdf8; word-break: break-all; background-color: rgba(15, 23, 42, 0.6); padding: 8px 12px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.05); min-height: 20px; max-width: 600px; margin-left: auto; margin-right: auto;">
								-
							</div>
						</div>
					</div>
				</div>

				<!-- PANEL TOMBOL UTAMA -->
				<div id="rg-actions-bar" class="rg-actions-bar">
					<button type="button" class="button button-primary button-large" onclick="startDynamicScan()">
						<?php esc_html_e( 'Pindai Sekarang (Scan Now)', 'wp-root-guard' ); ?>
					</button>
					<button type="button" class="button button-secondary button-large" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin membangun ulang baseline? Ini akan merekam kondisi folder dan berkas root saat ini sebagai standar aman yang baru.', 'wp-root-guard' ) ); ?>')) { submitRgAction('rebuild_baseline'); }">
						<?php esc_html_e( 'Bangun Ulang Baseline (Rebuild Baseline)', 'wp-root-guard' ); ?>
					</button>
					<button type="button" class="button button-link-delete" onclick="if(confirm('<?php echo esc_js( __( 'Peringatan: Reset Baseline akan menghapus data referensi aman dan hasil scan. Anda harus membangun ulang setelahnya. Lanjutkan?', 'wp-root-guard' ) ); ?>')) { submitRgAction('reset_baseline'); }">
						<?php esc_html_e( 'Reset Baseline', 'wp-root-guard' ); ?>
					</button>
				</div>

				<?php
				// Pisahkan data ancaman berdasarkan tipe: folder, file (root), core_file, dan uploads_php
				$active_folders = array();
				$active_files   = array();
				$active_core    = array();
				$active_uploads = array();
				foreach ( $unknown_folders as $item ) {
					if ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) === $item['status'] ) {
						continue;
					}

					$type = isset( $item['type'] ) ? $item['type'] : 'folder';
					if ( 'uploads_php' === $type ) {
						$active_uploads[] = $item;
					} elseif ( 'core_file' === $type ) {
						$active_core[] = $item;
					} elseif ( 'file' === $type ) {
						$active_files[] = $item;
					} else {
						$active_folders[] = $item;
					}
				}
				?>

				<!-- FORM & BULK ACTION BAR -->
				<?php if ( ! empty( $active_folders ) || ! empty( $active_core ) || ! empty( $active_files ) || ! empty( $active_uploads ) ) : ?>
					<form method="post" id="rg-bulk-form" action="">
						<?php wp_nonce_field( 'wp_root_guard_admin_action', 'wp_root_guard_action_nonce' ); ?>
						<input type="hidden" name="rg_action" value="bulk_action">

						<div class="rg-bulk-bar" style="display: flex; align-items: center; gap: 12px; background: #ffffff; padding: 14px 20px; border-radius: 8px; border: 1px solid #cbd5e1; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
							<strong style="font-size: 14px; color: #1e293b;">⚡ <?php esc_html_e( 'Aksi Massal (Bulk Actions):', 'wp-root-guard' ); ?></strong>
							<select name="bulk_action_type" id="rg_bulk_action_type" style="min-width: 220px; padding: 5px 10px; border-radius: 6px; border: 1px solid #cbd5e1;">
								<option value=""><?php esc_html_e( '— Pilih Tindakan Massal —', 'wp-root-guard' ); ?></option>
								<option value="bulk_trust">👍 <?php esc_html_e( 'Trust Selected (Tambah ke Whitelist)', 'wp-root-guard' ); ?></option>
								<option value="bulk_quarantine">🔒 <?php esc_html_e( 'Karantina Selected', 'wp-root-guard' ); ?></option>
								<option value="bulk_delete">🗑️ <?php esc_html_e( 'Hapus Permanen Selected', 'wp-root-guard' ); ?></option>
							</select>
							<button type="button" class="button button-primary" onclick="executeBulkAction()">
								<?php esc_html_e( 'Terapkan (Apply)', 'wp-root-guard' ); ?>
							</button>
							<span style="font-size: 13px; color: #64748b; margin-left: auto;">
								<span id="rg-selected-count" style="font-weight: bold; color: #2563eb; font-size: 15px;">0</span> <?php esc_html_e( 'item dipilih dari seluruh tabel', 'wp-root-guard' ); ?>
							</span>
						</div>
				<?php endif; ?>

				<!-- TABEL 1: HASIL PEMINDAIAN FOLDER ASING -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>📂 <?php esc_html_e( 'Hasil Scan: Folder Asing Aktif', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $active_folders ) ) : ?>
							<div class="rg-empty-message">
								<p>✅ <?php esc_html_e( 'No suspicious folders found.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th style="width: 38px; text-align: center;"><input type="checkbox" class="rg-select-all" onclick="toggleSelectAllTable(this)"></th>
										<th><?php esc_html_e( 'Nama Folder', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Full Path', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Dibuat', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Terdeteksi', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Status', 'wp-root-guard' ); ?></th>
										<th style="width: 150px;"><?php esc_html_e( 'Aksi', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $active_folders as $folder ) : ?>
										<tr>
											<td style="text-align: center;"><input type="checkbox" name="bulk_items[]" value="<?php echo esc_attr( $folder['name'] ); ?>" class="rg-item-checkbox" onchange="updateSelectedCount()"></td>
											<td><strong class="text-danger"><?php echo esc_html( $folder['name'] ); ?></strong></td>
											<td><code><?php echo esc_html( $folder['path'] ); ?></code></td>
											<td><?php echo esc_html( $folder['created_time'] ); ?></td>
											<td><?php echo esc_html( $folder['detection_time'] ); ?></td>
											<td><span class="rg-badge badge-danger"><?php echo esc_html( $folder['status'] ); ?></span></td>
											<td>
												<button type="button" class="button button-small button-secondary" onclick="trustFolder('<?php echo esc_js( $folder['name'] ); ?>')">
													👍 <?php esc_html_e( 'Trust Folder', 'wp-root-guard' ); ?>
												</button>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<!-- TABEL 2: INTEGRITAS BERKAS CORE WORDPRESS (wp-admin, wp-includes, root core) -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>🛡️ <?php esc_html_e( 'Hasil Scan: Integritas Berkas Core (wp-admin, wp-includes, root)', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $active_core ) ) : ?>
							<div class="rg-empty-message">
								<p>✅ <?php esc_html_e( 'Semua berkas core WordPress sesuai standar resmi dan aman.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th style="width: 38px; text-align: center;"><input type="checkbox" class="rg-select-all" onclick="toggleSelectAllTable(this)"></th>
										<th><?php esc_html_e( 'Nama Berkas', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Full Path', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Keadaan Berkas / Indikasi', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Status', 'wp-root-guard' ); ?></th>
										<th style="width: 250px;"><?php esc_html_e( 'Aksi Pemulihan', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $active_core as $file ) : ?>
										<tr>
											<td style="text-align: center;"><input type="checkbox" name="bulk_items[]" value="<?php echo esc_attr( $file['name'] ); ?>" class="rg-item-checkbox" onchange="updateSelectedCount()"></td>
											<td><strong class="text-danger"><?php echo esc_html( $file['name'] ); ?></strong></td>
											<td><code><?php echo esc_html( $file['path'] ); ?></code></td>
											<td>
												<?php
												$text_color = ( '-' !== $file['malware_indicator'] && ( false !== strpos( $file['malware_indicator'], 'Mencurigakan' ) || false !== strpos( $file['malware_indicator'], 'Penyusupan' ) ) ) ? 'text-danger' : 'color: #475569;';
												?>
												<span style="<?php echo esc_attr( $text_color ); ?> font-size: 13px; font-weight: 500;">
													<?php echo esc_html( $file['malware_indicator'] ); ?>
												</span>
											</td>
											<td>
												<?php
												$status_label = $file['status'];
												$badge_class  = 'badge-danger';
												if ( 'Modified Core File' === $file['status'] ) {
													$status_label = esc_html__( 'Berkas Dimodifikasi', 'wp-root-guard' );
													$badge_class  = 'badge-warning';
												} elseif ( 'Missing Core File' === $file['status'] ) {
													$status_label = esc_html__( 'Berkas Hilang', 'wp-root-guard' );
													$badge_class  = 'badge-danger';
												} elseif ( 'Suspicious Core Injection' === $file['status'] ) {
													$status_label = esc_html__( 'Berkas Penyusup', 'wp-root-guard' );
													$badge_class  = 'badge-danger';
												}
												?>
												<span class="rg-badge <?php echo esc_attr( $badge_class ); ?>"><?php echo esc_html( $status_label ); ?></span>
											</td>
											<td>
												<button type="button" class="button button-small button-secondary" onclick="openCodeInspector('<?php echo esc_js( $file['name'] ); ?>')">
													👁️ <?php esc_html_e( 'Lihat Isi', 'wp-root-guard' ); ?>
												</button>
												<?php if ( 'Suspicious Core Injection' === $file['status'] ) : ?>
													<button type="button" class="button button-small button-secondary" onclick="trustFolder('<?php echo esc_js( $file['name'] ); ?>')">
														👍 <?php esc_html_e( 'Trust File', 'wp-root-guard' ); ?>
													</button>
													<button type="button" class="button button-small button-link-delete" style="text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Karantina berkas penyusup core ini?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('quarantine_file', '<?php echo esc_js( $file['name'] ); ?>'); }">
														🔒 <?php esc_html_e( 'Karantina', 'wp-root-guard' ); ?>
													</button>
													<button type="button" class="button button-small button-link-delete" style="color: #dc2626; border-color: #fca5a5; text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin menghapus berkas penyusup ini secara PERMANEN dari server?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('delete_file_directly', '<?php echo esc_js( $file['name'] ); ?>'); }">
														🗑️ <?php esc_html_e( 'Hapus', 'wp-root-guard' ); ?>
													</button>
												<?php else : ?>
													<a href="?page=wp-root-guard&tab=dashboard&view_diff=<?php echo urlencode( $file['name'] ); ?>" class="button button-small button-secondary">
														🔍 <?php esc_html_e( 'Bandingkan Kode', 'wp-root-guard' ); ?>
													</a>
													<button type="button" class="button button-small button-primary" style="background-color: #10b981; border-color: #10b981;" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin menimpa berkas ini dengan berkas asli bawaan dari server resmi WordPress.org?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('fix_core_file', '<?php echo esc_js( $file['name'] ); ?>'); }">
														🛠️ <?php esc_html_e( 'Perbaiki', 'wp-root-guard' ); ?>
													</button>
												<?php endif; ?>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<!-- TABEL 3: HASIL PEMINDAIAN BERKAS ASING DI ROOT -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>📄 <?php esc_html_e( 'Hasil Scan: Berkas Asing Aktif di Root', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $active_files ) ) : ?>
							<div class="rg-empty-message">
								<p>✅ <?php esc_html_e( 'No suspicious or modified files found in root.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th style="width: 38px; text-align: center;"><input type="checkbox" class="rg-select-all" onclick="toggleSelectAllTable(this)"></th>
										<th><?php esc_html_e( 'Nama Berkas', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Full Path', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Indikasi / Keadaan berkas', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Terdeteksi', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Status', 'wp-root-guard' ); ?></th>
										<th style="width: 250px;"><?php esc_html_e( 'Aksi', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $active_files as $file ) : ?>
										<tr>
											<td style="text-align: center;"><input type="checkbox" name="bulk_items[]" value="<?php echo esc_attr( $file['name'] ); ?>" class="rg-item-checkbox" onchange="updateSelectedCount()"></td>
											<td><strong class="text-danger"><?php echo esc_html( $file['name'] ); ?></strong></td>
											<td><code><?php echo esc_html( $file['path'] ); ?></code></td>
											<td>
												<?php
												$text_color = ( '-' !== $file['malware_indicator'] && false !== strpos( $file['malware_indicator'], 'Mencurigakan' ) ) ? 'text-danger' : 'color: #475569;';
												?>
												<span style="<?php echo esc_attr( $text_color ); ?> font-size: 13px; font-weight: 500;">
													<?php echo esc_html( $file['malware_indicator'] ); ?>
												</span>
											</td>
											<td><?php echo esc_html( $file['detection_time'] ); ?></td>
											<td>
												<?php
												$status_label = $file['status'];
												$badge_class  = 'badge-danger';
												if ( esc_html__( 'Modified File', 'wp-root-guard' ) === $file['status'] ) {
													$status_label = esc_html__( 'Berkas Dimodifikasi', 'wp-root-guard' );
													$badge_class  = 'badge-warning';
												}
												?>
												<span class="rg-badge <?php echo esc_attr( $badge_class ); ?>"><?php echo esc_html( $status_label ); ?></span>
											</td>
											<td>
												<button type="button" class="button button-small button-secondary" onclick="openCodeInspector('<?php echo esc_js( $file['name'] ); ?>')">
													👁️ <?php esc_html_e( 'Lihat Isi', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-secondary" onclick="trustFolder('<?php echo esc_js( $file['name'] ); ?>')">
													👍 <?php esc_html_e( 'Trust File', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-link-delete" style="text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Karantina berkas asing ini?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('quarantine_file', '<?php echo esc_js( $file['name'] ); ?>'); }">
													🔒 <?php esc_html_e( 'Karantina', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-link-delete" style="color: #dc2626; border-color: #fca5a5; text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin menghapus berkas asing ini secara PERMANEN dari server?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('delete_file_directly', '<?php echo esc_js( $file['name'] ); ?>'); }">
													🗑️ <?php esc_html_e( 'Hapus', 'wp-root-guard' ); ?>
												</button>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<!-- TABEL 4: HASIL PEMINDAIAN BERKAS PHP DI FOLDER UPLOADS -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header" style="background-color: #fef2f2; border-bottom: 1px solid #fecaca;">
						<h2 style="color: #991b1b;">🚨 <?php esc_html_e( 'Hasil Scan: Berkas PHP Mencurigakan di Folder Uploads (wp-content/uploads)', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $active_uploads ) ) : ?>
							<div class="rg-empty-message">
								<p>✅ <?php esc_html_e( 'Tidak ada berkas PHP berbahaya yang ditemukan di folder wp-content/uploads.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th style="width: 38px; text-align: center;"><input type="checkbox" class="rg-select-all" onclick="toggleSelectAllTable(this)"></th>
										<th><?php esc_html_e( 'Nama Berkas', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Full Path', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Indikasi Bahaya', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Terdeteksi', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Status', 'wp-root-guard' ); ?></th>
										<th style="width: 250px;"><?php esc_html_e( 'Aksi', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $active_uploads as $file ) : ?>
										<tr>
											<td style="text-align: center;"><input type="checkbox" name="bulk_items[]" value="<?php echo esc_attr( $file['name'] ); ?>" class="rg-item-checkbox" onchange="updateSelectedCount()"></td>
											<td><strong class="text-danger"><?php echo esc_html( $file['name'] ); ?></strong></td>
											<td><code><?php echo esc_html( $file['path'] ); ?></code></td>
											<td>
												<span class="text-danger" style="font-size: 13px; font-weight: 600;">
													⚠️ <?php echo esc_html( $file['malware_indicator'] ); ?>
												</span>
											</td>
											<td><?php echo esc_html( $file['detection_time'] ); ?></td>
											<td>
												<span class="rg-badge badge-danger"><?php echo esc_html( $file['status'] ); ?></span>
											</td>
											<td>
												<button type="button" class="button button-small button-secondary" onclick="openCodeInspector('<?php echo esc_js( $file['name'] ); ?>')">
													👁️ <?php esc_html_e( 'Lihat Isi', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-secondary" onclick="trustFolder('<?php echo esc_js( $file['name'] ); ?>')">
													👍 <?php esc_html_e( 'Trust File', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-link-delete" style="text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Karantina berkas PHP di folder uploads ini?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('quarantine_file', '<?php echo esc_js( $file['name'] ); ?>'); }">
													🔒 <?php esc_html_e( 'Karantina', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-link-delete" style="color: #dc2626; border-color: #fca5a5; text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin menghapus berkas PHP penyusup di folder uploads ini secara PERMANEN?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('delete_file_directly', '<?php echo esc_js( $file['name'] ); ?>'); }">
													🗑️ <?php esc_html_e( 'Hapus', 'wp-root-guard' ); ?>
												</button>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<?php if ( ! empty( $active_folders ) || ! empty( $active_core ) || ! empty( $active_files ) || ! empty( $active_uploads ) ) : ?>
					</form>
				<?php endif; ?>
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>🔒 <?php esc_html_e( 'Daftar Karantina (Quarantined Folders & Files)', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $quarantined ) ) : ?>
							<div class="rg-empty-message">
								<p><?php esc_html_e( 'Tidak ada folder atau berkas dalam karantina saat ini.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Tipe', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Nama Asli', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Nama Folder/File Karantina', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Dikarantina', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Status Keamanan', 'wp-root-guard' ); ?></th>
										<th style="width: 250px;"><?php esc_html_e( 'Aksi Karantina', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $quarantined as $item ) : ?>
										<?php
										$type_label = ( isset( $item['type'] ) && 'file' === $item['type'] ) ? esc_html__( 'Berkas', 'wp-root-guard' ) : esc_html__( 'Folder', 'wp-root-guard' );
										$status_label = ( isset( $item['type'] ) && 'file' === $item['type'] ) ? esc_html__( 'Berkas Diisolasi', 'wp-root-guard' ) : esc_html__( 'Akses Diblokir (.htaccess)', 'wp-root-guard' );
										?>
										<tr>
											<td><code><?php echo esc_html( $type_label ); ?></code></td>
											<td><strong><?php echo esc_html( $item['original_name'] ); ?></strong></td>
											<td><code><?php echo esc_html( $item['quarantine_name'] ); ?></code></td>
											<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $item['quarantine_time'] ) ) ); ?></td>
											<td><span class="rg-badge badge-safe">🔒 <?php echo esc_html( $status_label ); ?></span></td>
											<td>
												<?php if ( isset( $item['type'] ) && 'file' === $item['type'] ) : ?>
													<button type="button" class="button button-small button-secondary" onclick="openCodeInspector('<?php echo esc_js( $item['quarantine_name'] ); ?>')">
														👁️ <?php esc_html_e( 'Lihat Isi', 'wp-root-guard' ); ?>
													</button>
												<?php endif; ?>
												<button type="button" class="button button-small button-primary" style="background-color: #10b981; border-color: #10b981;" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin memulihkan item ini kembali ke root asal? Item ini otomatis akan masuk ke Whitelist agar tidak dikarantina kembali.', 'wp-root-guard' ) ); ?>')) { submitFolderAction('restore_folder', '<?php echo esc_js( $item['quarantine_name'] ); ?>'); }">
													↩️ <?php esc_html_e( 'Restore', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-link-delete" style="text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Peringatan keras: Item ini beserta seluruh file di dalamnya akan dihapus secara PERMANEN dari server. Tindakan ini tidak bisa dibatalkan. Lanjutkan?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('delete_permanently', '<?php echo esc_js( $item['quarantine_name'] ); ?>'); }">
													🗑️ <?php esc_html_e( 'Hapus Permanen', 'wp-root-guard' ); ?>
												</button>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<!-- TABEL 5: DAFTAR IP TERBLOKIR OTOMATIS & HTACCESS BLOCKER -->
				<?php $blocked_ips = Blocker::get_blocked_ips(); ?>
				<div class="rg-card rg-table-card">
					<div class="rg-card-header" style="display: flex; justify-content: space-between; align-items: center;">
						<h2>🚫 <?php esc_html_e( 'Proteksi IP Terblokir & Webshell Access Blocker (.htaccess)', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<!-- FORM TAMBAH MANUAL IP BLOCK -->
						<form method="post" action="" style="margin-bottom: 20px; display: flex; gap: 10px; align-items: center; background: #f8fafc; padding: 12px 16px; border-radius: 8px; border: 1px solid #cbd5e1;">
							<?php wp_nonce_field( 'wp_root_guard_admin_action', 'wp_root_guard_action_nonce' ); ?>
							<input type="hidden" name="rg_action" value="block_ip">
							<strong>➕ <?php esc_html_e( 'Blokir IP Manual:', 'wp-root-guard' ); ?></strong>
							<input type="text" name="ip_address" placeholder="Contoh: 192.168.1.100" class="regular-text" required style="max-width: 200px;">
							<input type="text" name="ip_reason" placeholder="Alasan (Opsional)" class="regular-text" style="max-width: 250px;">
							<button type="submit" class="button button-secondary">
								🚫 <?php esc_html_e( 'Blokir IP Ini', 'wp-root-guard' ); ?>
							</button>
						</form>

						<?php if ( empty( $blocked_ips ) ) : ?>
							<div class="rg-empty-message">
								<p>✅ <?php esc_html_e( 'Tidak ada IP penyerang yang diblokir saat ini.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Alamat IP Penyerang', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Alasan Pemblokiran', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Di-block', 'wp-root-guard' ); ?></th>
										<th style="width: 150px;"><?php esc_html_e( 'Aksi', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $blocked_ips as $item ) : ?>
										<tr>
											<td><strong class="text-danger"><code><?php echo esc_html( $item['ip'] ); ?></code></strong></td>
											<td><?php echo esc_html( $item['reason'] ); ?></td>
											<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $item['time'] ) ) ); ?></td>
											<td>
												<button type="button" class="button button-small button-secondary" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin membuka blokir IP ini?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('unblock_ip', '<?php echo esc_js( $item['ip'] ); ?>'); }">
													🔓 <?php esc_html_e( 'Unblock IP', 'wp-root-guard' ); ?>
												</button>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<!-- WHITELIST USER -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>🛡️ <?php esc_html_e( 'Whitelist Kustom (Folder & Berkas yang Dipercayai)', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $user_whitelist ) ) : ?>
							<div class="rg-empty-message">
								<p><?php esc_html_e( 'Belum ada folder atau berkas yang Anda percayai secara kustom. Anda bisa menekan tombol "Trust" pada ancaman asing di atas.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Nama Folder/Berkas', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Path Asumsi', 'wp-root-guard' ); ?></th>
										<th style="width: 150px;"><?php esc_html_e( 'Aksi', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $user_whitelist as $folder_name ) : ?>
										<tr>
											<td><strong><?php echo esc_html( $folder_name ); ?></strong></td>
											<td><code><?php echo esc_html( ABSPATH . $folder_name ); ?></code></td>
											<td>
												<button type="button" class="button button-small button-secondary" onclick="openCodeInspector('<?php echo esc_js( $folder_name ); ?>')">
													👁️ <?php esc_html_e( 'Lihat Isi', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-link-delete" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin mematikan status percaya untuk item ini?', 'wp-root-guard' ) ); ?>')) { untrustFolder('<?php echo esc_js( $folder_name ); ?>'); }">
													❌ <?php esc_html_e( 'Jangan Percayai', 'wp-root-guard' ); ?>
												</button>
											</td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						<?php endif; ?>
					</div>
				</div>

				<!-- RIWAYAT LOG -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header" style="display: flex; justify-content: space-between; align-items: center;">
						<h2 style="margin: 0;">📜 <?php esc_html_e( 'Log Aktivitas Keamanan', 'wp-root-guard' ); ?></h2>
						<button type="button" class="button button-link-delete" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin menghapus seluruh riwayat log?', 'wp-root-guard' ) ); ?>')) { submitRgAction('clear_logs'); }">
							🧹 <?php esc_html_e( 'Bersihkan Log', 'wp-root-guard' ); ?>
						</button>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $logs ) ) : ?>
							<div class="rg-empty-message">
								<p><?php esc_html_e( 'Belum ada catatan log aktivitas.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<div style="max-height: 250px; overflow-y: auto;">
								<table class="wp-list-table widefat fixed striped posts rg-styled-table">
									<thead>
										<tr>
											<th style="width: 150px;"><?php esc_html_e( 'Waktu', 'wp-root-guard' ); ?></th>
											<th><?php esc_html_e( 'Kejadian', 'wp-root-guard' ); ?></th>
											<th><?php esc_html_e( 'Nama Folder/Berkas', 'wp-root-guard' ); ?></th>
											<th><?php esc_html_e( 'Status', 'wp-root-guard' ); ?></th>
										</tr>
									</thead>
									<tbody>
										<?php foreach ( $logs as $log ) : ?>
											<tr>
												<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $log['time'] ) ) ); ?></td>
												<td><?php echo esc_html( $log['event'] ); ?></td>
												<td><code><?php echo esc_html( $log['folder_name'] ); ?></code></td>
												<td>
													<?php
													$badge_class = 'rg-badge';
													if ( esc_html__( 'Safe', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Success', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Restored', 'wp-root-guard' ) === $log['status'] ) {
														$badge_class .= ' badge-safe';
													} elseif ( esc_html__( 'Threat Detected', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Unknown', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Quarantined', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Deleted', 'wp-root-guard' ) === $log['status'] ) {
														$badge_class .= ' badge-danger';
													} elseif ( esc_html__( 'Modified', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Malware Suspicious', 'wp-root-guard' ) === $log['status'] ) {
														$badge_class .= ' badge-warning';
													}
													?>
													<span class="<?php echo esc_attr( $badge_class ); ?>"><?php echo esc_html( $log['status'] ); ?></span>
												</td>
											</tr>
										<?php endforeach; ?>
									</tbody>
								</table>
							</div>
						<?php endif; ?>
					</div>
				</div>

				<!-- MODAL INSPEKTUR KODE BERKAS -->
				<div id="rg-code-modal" class="rg-modal-overlay" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.75); z-index: 999999; align-items: center; justify-content: center; backdrop-filter: blur(4px);">
					<div class="rg-modal-content" style="background: #ffffff; width: 92%; max-width: 1050px; height: 88vh; border-radius: 12px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); display: flex; flex-direction: column; overflow: hidden;">
						<div class="rg-modal-header" style="background: #0f172a; color: #ffffff; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1e293b;">
							<div>
								<h3 style="margin: 0; font-size: 16px; color: #f8fafc; display: flex; align-items: center; gap: 8px;">
									👁️ <?php esc_html_e( 'Inspektur Kode Berkas:', 'wp-root-guard' ); ?>
									<code id="rg-modal-filename" style="background: #1e293b; color: #38bdf8; padding: 3px 10px; border-radius: 6px; font-size: 14px; border: 1px solid #334155;">...</code>
								</h3>
								<div id="rg-modal-stats" style="font-size: 12px; color: #94a3b8; margin-top: 4px;">...</div>
							</div>
							<button type="button" onclick="closeCodeInspector()" style="background: transparent; border: none; color: #94a3b8; font-size: 28px; cursor: pointer; line-height: 1; padding: 0 8px;">&times;</button>
						</div>
						<div class="rg-modal-body" style="padding: 0; flex: 1; overflow-y: auto; background: #090d16; font-family: Consolas, Monaco, 'Courier New', monospace; font-size: 13px; line-height: 1.6;">
							<div id="rg-modal-loading" style="padding: 60px 20px; text-align: center; color: #94a3b8; font-size: 15px;">
								<div style="margin-bottom: 10px;">⏳ <?php esc_html_e( 'Memuat & menganalisis kode berkas dari server...', 'wp-root-guard' ); ?> <strong id="rg-modal-loading-pct" style="color: #38bdf8;">0%</strong></div>
								<div style="width: 240px; height: 6px; background: #1e293b; border-radius: 3px; margin: 0 auto; overflow: hidden;">
									<div id="rg-modal-loading-bar" style="width: 0%; height: 100%; background: #38bdf8; transition: width 0.2s ease;"></div>
								</div>
							</div>
							<div id="rg-modal-error" style="padding: 40px; text-align: center; color: #f87171; display: none;"></div>
							<table id="rg-modal-codetable" style="width: 100%; border-collapse: collapse; display: none;">
								<tbody id="rg-modal-codebody"></tbody>
							</table>
						</div>
						<div class="rg-modal-footer" style="background: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; display: flex; align-items: center; gap: 10px; justify-content: space-between;">
							<div id="rg-modal-actions" style="display: flex; gap: 10px; align-items: center;"></div>
							<button type="button" class="button button-secondary button-large" onclick="closeCodeInspector()"><?php esc_html_e( 'Tutup Inspektur', 'wp-root-guard' ); ?></button>
						</div>
					</div>
				</div>

				<script type="text/javascript">
					function openCodeInspector(fileName) {
						var modal = document.getElementById('rg-code-modal');
						var filenameEl = document.getElementById('rg-modal-filename');
						var statsEl = document.getElementById('rg-modal-stats');
						var loadingEl = document.getElementById('rg-modal-loading');
						var loadingPct = document.getElementById('rg-modal-loading-pct');
						var loadingBar = document.getElementById('rg-modal-loading-bar');
						var errorEl = document.getElementById('rg-modal-error');
						var codeTable = document.getElementById('rg-modal-codetable');
						var codeBody = document.getElementById('rg-modal-codebody');
						var actionsEl = document.getElementById('rg-modal-actions');

						if (!modal) return;

						filenameEl.innerText = fileName;
						statsEl.innerText = 'Memuat analisis...';
						if (loadingPct) loadingPct.innerText = '15%';
						if (loadingBar) loadingBar.style.width = '15%';
						loadingEl.style.display = 'block';
						errorEl.style.display = 'none';
						codeTable.style.display = 'none';
						codeBody.innerHTML = '';
						actionsEl.innerHTML = '';
						modal.style.display = 'flex';

						var data = {
							action: 'wp_root_guard_inspect_file',
							file: fileName,
							security: '<?php echo esc_js( wp_create_nonce( 'wp_root_guard_admin_action' ) ); ?>'
						};

						if (loadingPct) loadingPct.innerText = '45%';
						if (loadingBar) loadingBar.style.width = '45%';

						jQuery.post(ajaxurl, data, function(response) {
							if (loadingPct) loadingPct.innerText = '90%';
							if (loadingBar) loadingBar.style.width = '90%';

							setTimeout(function() {
								loadingEl.style.display = 'none';

								if (response.success && response.data) {
									var res = response.data;
									var statsText = 'Total Baris: ' + res.total_lines;
									if (res.total_dangers > 0) {
										statsText += ' | ⚠️ TERDETEKSI ' + res.total_dangers + ' INDIKASI BAHAYA MALWARE';
									} else {
										statsText += ' | ✅ Tidak terdeteksi tanda tangan malware berbahaya';
									}
									statsEl.innerText = statsText;

									var rowsHtml = '';
									res.lines.forEach(function(item) {
										var isDanger = item.dangers && item.dangers.length > 0;
										var trStyle = isDanger ? 'background: #450a0a; color: #fecaca; font-weight: 600;' : 'color: #e2e8f0;';
										var lineStyle = isDanger ? 'background: #7f1d1d; color: #fca5a5;' : 'background: #1e293b; color: #64748b;';
										
										rowsHtml += '<tr style="' + trStyle + '">';
										rowsHtml += '<td style="width: 50px; text-align: right; padding: 2px 10px; user-select: none; border-right: 1px solid #334155; ' + lineStyle + '">' + item.line_number + '</td>';
										rowsHtml += '<td style="padding: 2px 12px; white-space: pre-wrap; word-break: break-all;">';
										
										if (isDanger) {
											rowsHtml += '<span style="background: #dc2626; color: #ffffff; padding: 1px 6px; border-radius: 4px; font-size: 11px; margin-right: 8px; font-weight: bold;">⚠️ BAHAYA: ' + item.dangers.join(', ') + '</span>';
										}
										
										var escapedCode = jQuery('<div/>').text(item.code).html();
										rowsHtml += escapedCode;
										rowsHtml += '</td>';
										rowsHtml += '</tr>';
									});

									codeBody.innerHTML = rowsHtml;
									codeTable.style.display = 'table';

									// Tombol aksi di footer modal
									var actionsHtml = '';
									actionsHtml += '<button type="button" class="button button-secondary" onclick="trustFolder(\'' + fileName + '\')">👍 Trust File</button>';
									actionsHtml += '<button type="button" class="button button-secondary" onclick="if(confirm(\'Karantina berkas ini?\')) { submitFolderAction(\'quarantine_file\', \'' + fileName + '\'); }">🔒 Karantina</button>';
									actionsHtml += '<button type="button" class="button button-link-delete" style="color: #dc2626; border-color: #fca5a5;" onclick="if(confirm(\'Apakah Anda yakin ingin menghapus berkas ini secara PERMANEN?\')) { submitFolderAction(\'delete_file_directly\', \'' + fileName + '\'); }">🗑️ Hapus Permanen</button>';
									actionsEl.innerHTML = actionsHtml;

								} else {
									errorEl.innerText = '❌ ' + (response.data ? response.data.message : 'Gagal membaca berkas.');
									errorEl.style.display = 'block';
								}
							}, 150);
						}).fail(function() {
							loadingEl.style.display = 'none';
							errorEl.innerText = '❌ Terjadi kesalahan koneksi server saat membaca berkas.';
							errorEl.style.display = 'block';
						});
					}

					function closeCodeInspector() {
						var modal = document.getElementById('rg-code-modal');
						if (modal) modal.style.display = 'none';
					}

					document.addEventListener('keydown', function(e) {
						if (e.key === 'Escape') {
							closeCodeInspector();
						}
					});

					function toggleSelectAllTable(masterCheckbox) {
						var table = masterCheckbox.closest('table');
						if (table) {
							var checkboxes = table.querySelectorAll('.rg-item-checkbox');
							checkboxes.forEach(function(cb) {
								cb.checked = masterCheckbox.checked;
							});
							updateSelectedCount();
						}
					}

					function updateSelectedCount() {
						var count = document.querySelectorAll('.rg-item-checkbox:checked').length;
						var counterEl = document.getElementById('rg-selected-count');
						if (counterEl) {
							counterEl.innerText = count;
						}
					}

					function executeBulkAction() {
						var actionSelect = document.getElementById('rg_bulk_action_type');
						var action = actionSelect ? actionSelect.value : '';
						var checkedCount = document.querySelectorAll('.rg-item-checkbox:checked').length;

						if (!action) {
							alert('Silakan pilih jenis tindakan massal terlebih dahulu.');
							return;
						}

						if (checkedCount === 0) {
							alert('Silakan centang/pilih minimal 1 item ancaman dari tabel.');
							return;
						}

						var message = '';
						if (action === 'bulk_trust') {
							message = 'Apakah Anda yakin ingin menambahkan ' + checkedCount + ' item ancaman yang dipilih ke Whitelist Kustom?';
						} else if (action === 'bulk_quarantine') {
							message = 'Apakah Anda yakin ingin memindahkan ' + checkedCount + ' item ancaman yang dipilih ke Karantina?';
						} else if (action === 'bulk_delete') {
							message = 'PERINGATAN BAHAYA: Apakah Anda yakin ingin menghapus ' + checkedCount + ' berkas/folder ancaman yang dipilih secara PERMANEN dari server? Aksi ini tidak dapat dibatalkan!';
						}

						if (confirm(message)) {
							document.getElementById('rg-bulk-form').submit();
						}
					}

					function startDynamicScan() {
						var statusCard = document.getElementById('rg-status-card');
						var summaryCard = document.getElementById('rg-summary-card');
						var actionsBar = document.getElementById('rg-actions-bar');
						var inlineCard = document.getElementById('rg-scan-inline-card');

						var percentText = document.getElementById('rg-scan-percentage');
						var progressBar = document.getElementById('rg-scan-bar');
						var currentItemText = document.getElementById('rg-scan-current-item');
						
						// Sembunyikan panel dashboard lama secara halus dan tampilkan scan inline card
						if (statusCard) statusCard.style.display = 'none';
						if (summaryCard) summaryCard.style.display = 'none';
						if (actionsBar) actionsBar.style.display = 'none';
						inlineCard.classList.remove('hidden');

						var data = {
							action: 'wp_root_guard_get_scan_queue',
							security: '<?php echo esc_js( wp_create_nonce( 'wp_root_guard_admin_action' ) ); ?>'
						};

						jQuery.post(ajaxurl, data, function(response) {
							if (response.success && response.data.queue) {
								var queue = response.data.queue;
								var total = queue.length;
								var current = 0;

								var interval = setInterval(function() {
									if (current < total) {
										var item = queue[current];
										var prefix = item.type === 'folder' ? '📂 Folder: ' : (item.type === 'core' ? '🛡️ Core File: ' : '📄 File: ');
										currentItemText.innerText = prefix + item.name;
										
										var percent = Math.floor((current / total) * 90);
										percentText.innerText = percent + '%';
										progressBar.style.width = percent + '%';
										
										current++;
									} else {
										clearInterval(interval);
										currentItemText.innerText = '🛡️ Menganalisis hasil & tanda tangan malware...';
										
										var scanData = {
											action: 'wp_root_guard_run_scan',
											security: '<?php echo esc_js( wp_create_nonce( 'wp_root_guard_admin_action' ) ); ?>'
										};

										jQuery.post(ajaxurl, scanData, function(scanResponse) {
											percentText.innerText = '100%';
											progressBar.style.width = '100%';
											currentItemText.innerText = '✅ Pemindaian Selesai! Memuat ulang halaman...';
											
											setTimeout(function() {
												window.location.href = '?page=wp-root-guard&tab=dashboard&message=scanned';
											}, 800);
										});
									}
								}, 30);
							} else {
								submitRgAction('scan_now');
							}
						}).fail(function() {
							submitRgAction('scan_now');
						});
					}
				</script>

			<?php elseif ( 'settings' === $active_tab ) : ?>
				<!-- TAB 2: SETTINGS CONTENT -->

				<div class="rg-card rg-form-card">
					<div class="rg-card-header">
						<h2>⚙️ <?php esc_html_e( 'Konfigurasi WP Root Guard', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<form method="post" action="">
							<?php wp_nonce_field( 'wp_root_guard_admin_action', 'wp_root_guard_action_nonce' ); ?>
							<input type="hidden" name="rg_action" value="save_settings">

							<!-- SECTION 0: SCAN SCHEDULE & UPLOADS GUARD -->
							<div class="rg-settings-section">
								<h3>⏱️ <?php esc_html_e( 'Jadwal Pemindaian Otomatis (Background Scan)', 'wp-root-guard' ); ?></h3>
								<hr>
								<div class="rg-form-group">
									<label for="scan_interval"><strong><?php esc_html_e( 'Frekuensi Pemindaian Sistem (WP Cron)', 'wp-root-guard' ); ?></strong></label>
									<select name="scan_interval" id="scan_interval" class="regular-text" style="margin-top: 6px; display: block;">
										<option value="every_5_minutes" <?php selected( $settings['scan_interval'], 'every_5_minutes' ); ?>><?php esc_html_e( 'Setiap 5 Menit (Direkomendasikan untuk Proteksi Maksimal)', 'wp-root-guard' ); ?></option>
										<option value="every_15_minutes" <?php selected( $settings['scan_interval'], 'every_15_minutes' ); ?>><?php esc_html_e( 'Setiap 15 Menit', 'wp-root-guard' ); ?></option>
										<option value="every_30_minutes" <?php selected( $settings['scan_interval'], 'every_30_minutes' ); ?>><?php esc_html_e( 'Setiap 30 Menit', 'wp-root-guard' ); ?></option>
										<option value="hourly" <?php selected( $settings['scan_interval'], 'hourly' ); ?>><?php esc_html_e( 'Setiap 1 Jam', 'wp-root-guard' ); ?></option>
										<option value="twicedaily" <?php selected( $settings['scan_interval'], 'twicedaily' ); ?>><?php esc_html_e( 'Setiap 12 Jam (2x Sehari)', 'wp-root-guard' ); ?></option>
										<option value="daily" <?php selected( $settings['scan_interval'], 'daily' ); ?>><?php esc_html_e( 'Setiap 24 Jam (1x Sehari)', 'wp-root-guard' ); ?></option>
									</select>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Tentukan seberapa sering WP Root Guard secara otomatis memindai folder root dan berkas core di latar belakang.', 'wp-root-guard' ); ?>
									</p>
								</div>
								<div class="rg-form-group" style="margin-top: 16px;">
									<label class="rg-switch-label">
										<input type="checkbox" name="enable_uploads_php_scan" value="1" <?php checked( $settings['enable_uploads_php_scan'], true ); ?>>
										<span class="rg-switch-slider"></span>
										<strong><?php esc_html_e( 'Aktifkan Pemindaian Berkas PHP di Folder wp-content/uploads/', 'wp-root-guard' ); ?></strong>
									</label>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Folder uploads seharusnya hanya berisi berkas media (gambar/dokumen). Mengaktifkan opsi ini akan mendeteksi dan mengisolasi setiap berkas eksekusi PHP atau webshell yang disisipkan di dalam direktori wp-content/uploads/.', 'wp-root-guard' ); ?>
									</p>
								</div>
								<div class="rg-form-group" style="margin-top: 16px;">
									<label class="rg-switch-label">
										<input type="checkbox" name="enable_ip_blocker" value="1" <?php checked( $settings['enable_ip_blocker'], true ); ?>>
										<span class="rg-switch-slider"></span>
										<strong><?php esc_html_e( 'Aktifkan Blocker Akses Webshell & IP Penyerang (.htaccess)', 'wp-root-guard' ); ?></strong>
									</label>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Otomatis mencegat percobaan eksekusi PHP di folder uploads dan query string berbahaya, serta memblokir IP penyerang di .htaccess.', 'wp-root-guard' ); ?>
									</p>
								</div>
							</div>

							<!-- SECTION 1: AUTO QUARANTINE -->
							<div class="rg-settings-section">
								<h3>🔒 <?php esc_html_e( 'Auto-Quarantine (Karantina Otomatis)', 'wp-root-guard' ); ?></h3>
								<hr>
								<div class="rg-form-group">
									<label class="rg-switch-label">
										<input type="checkbox" name="enable_auto_quarantine" value="1" <?php checked( $settings['enable_auto_quarantine'], true ); ?>>
										<span class="rg-switch-slider"></span>
										<strong><?php esc_html_e( 'Aktifkan Karantina Otomatis', 'wp-root-guard' ); ?></strong>
									</label>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Saat aktif, folder asing, berkas asing root, dan berkas penyusup asing di folder core (wp-admin & wp-includes) yang baru terdeteksi akan otomatis diganti namanya dan dikarantina. Berkas core terdaftar resmi yang dimodifikasi tidak dikarantina demi stabilitas situs.', 'wp-root-guard' ); ?>
									</p>
								</div>
							</div>

							<!-- SECTION 2: EMAIL NOTIFICATIONS -->
							<div class="rg-settings-section">
								<h3>📧 <?php esc_html_e( 'Notifikasi Email', 'wp-root-guard' ); ?></h3>
								<hr>
								<div class="rg-form-group">
									<label class="rg-switch-label">
										<input type="checkbox" id="rg-toggle-email" name="enable_email_notifications" value="1" <?php checked( $settings['enable_email_notifications'], true ); ?>>
										<span class="rg-switch-slider"></span>
										<strong><?php esc_html_e( 'Aktifkan Notifikasi Email', 'wp-root-guard' ); ?></strong>
									</label>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Kirim email laporan otomatis ketika ditemukan folder atau berkas asing baru serta berkas yang dimodifikasi.', 'wp-root-guard' ); ?>
									</p>
								</div>
								
								<div id="rg-email-fields" class="rg-sub-fields <?php echo $settings['enable_email_notifications'] ? '' : 'hidden'; ?>">
									<div class="rg-form-group">
										<label for="admin_email"><strong><?php esc_html_e( 'Alamat Email Penerima:', 'wp-root-guard' ); ?></strong></label>
										<input type="email" id="admin_email" name="admin_email" class="regular-text" value="<?php echo esc_attr( $settings['admin_email'] ); ?>">
										<button type="button" class="button button-secondary" onclick="triggerTestNotification('test_email')">
											✉️ <?php esc_html_e( 'Kirim Uji Coba', 'wp-root-guard' ); ?>
										</button>
									</div>
								</div>
							</div>

							<!-- SECTION 3: TELEGRAM NOTIFICATIONS -->
							<div class="rg-settings-section">
								<h3>🔔 <?php esc_html_e( 'Notifikasi Telegram', 'wp-root-guard' ); ?></h3>
								<hr>
								<div class="rg-form-group">
									<label class="rg-switch-label">
										<input type="checkbox" id="rg-toggle-telegram" name="enable_telegram_notifications" value="1" <?php checked( $settings['enable_telegram_notifications'], true ); ?>>
										<span class="rg-switch-slider"></span>
										<strong><?php esc_html_e( 'Aktifkan Notifikasi Telegram', 'wp-root-guard' ); ?></strong>
									</label>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Kirim pesan instan otomatis melalui bot Telegram Anda saat ancaman berkas/folder baru terdeteksi.', 'wp-root-guard' ); ?>
									</p>
								</div>

								<div id="rg-telegram-fields" class="rg-sub-fields <?php echo $settings['enable_telegram_notifications'] ? '' : 'hidden'; ?>">
									<div class="rg-form-group">
										<label for="telegram_bot_token"><strong><?php esc_html_e( 'Telegram Bot Token:', 'wp-root-guard' ); ?></strong></label>
										<input type="text" id="telegram_bot_token" name="telegram_bot_token" class="regular-text" value="<?php echo esc_attr( $settings['telegram_bot_token'] ); ?>" placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ">
									</div>
									<div class="rg-form-group">
										<label for="telegram_chat_id"><strong><?php esc_html_e( 'Telegram Chat ID:', 'wp-root-guard' ); ?></strong></label>
										<input type="text" id="telegram_chat_id" name="telegram_chat_id" class="regular-text" value="<?php echo esc_attr( $settings['telegram_chat_id'] ); ?>" placeholder="-100123456789">
										<button type="button" class="button button-secondary" onclick="triggerTestNotification('test_telegram')">
											🚀 <?php esc_html_e( 'Kirim Uji Coba Telegram', 'wp-root-guard' ); ?>
										</button>
										<p class="rg-field-desc" style="margin-top: 5px;">
											<?php
											printf(
												/* translators: %s: link botfather */
												wp_kses_post( __( 'Bot Token dapat diperoleh dengan membuat bot baru di Telegram via %s. Chat ID diperoleh dari ID obrolan grup/pribadi tempat Bot Anda bergabung.', 'wp-root-guard' ) ),
												'<a href="https://t.me/BotFather" target="_blank">@BotFather</a>'
											);
											?>
										</p>
									</div>
								</div>
							</div>

							<div class="rg-form-submit">
								<button type="submit" class="button button-primary button-large">
									💾 <?php esc_html_e( 'Simpan Semua Pengaturan', 'wp-root-guard' ); ?>
								</button>
							</div>
						</form>
					</div>
				</div>

				<script type="text/javascript">
					document.getElementById('rg-toggle-email').addEventListener('change', function() {
						var section = document.getElementById('rg-email-fields');
						if (this.checked) {
							section.classList.remove('hidden');
						} else {
							section.classList.add('hidden');
						}
					});

					document.getElementById('rg-toggle-telegram').addEventListener('change', function() {
						var section = document.getElementById('rg-telegram-fields');
						if (this.checked) {
							section.classList.remove('hidden');
						} else {
							section.classList.add('hidden');
						}
					});

					function triggerTestNotification(action) {
						var mainForm = document.getElementById('rg-action-form');
						var actionField = document.getElementById('rg-action-field');

						var oldToken = document.getElementById('rg-test-token');
						if (oldToken) oldToken.remove();
						var oldChat = document.getElementById('rg-test-chat');
						if (oldChat) oldChat.remove();
						var oldEmail = document.getElementById('rg-test-email');
						if (oldEmail) oldEmail.remove();

						if (action === 'test_telegram') {
							var tokenVal = document.getElementById('telegram_bot_token').value;
							var chatVal = document.getElementById('telegram_chat_id').value;

							if (!tokenVal || !chatVal) {
								alert('<?php echo esc_js( __( 'Mohon isi Bot Token dan Chat ID terlebih dahulu untuk uji coba!', 'wp-root-guard' ) ); ?>');
								return;
							}

							var tokenInput = document.createElement('input');
							tokenInput.type = 'hidden';
							tokenInput.name = 'telegram_bot_token';
							tokenInput.id = 'rg-test-token';
							tokenInput.value = tokenVal;
							mainForm.appendChild(tokenInput);

							var chatInput = document.createElement('input');
							chatInput.type = 'hidden';
							chatInput.name = 'telegram_chat_id';
							chatInput.id = 'rg-test-chat';
							chatInput.value = chatVal;
							mainForm.appendChild(chatInput);

						} else if (action === 'test_email') {
							var emailVal = document.getElementById('admin_email').value;

							if (!emailVal) {
								alert('<?php echo esc_js( __( 'Mohon isi alamat email terlebih dahulu untuk uji coba!', 'wp-root-guard' ) ); ?>');
								return;
							}

							var emailInput = document.createElement('input');
							emailInput.type = 'hidden';
							emailInput.name = 'admin_email';
							emailInput.id = 'rg-test-email';
							emailInput.value = emailVal;
							mainForm.appendChild(emailInput);
						}

						actionField.value = action;
						mainForm.submit();
					}
				</script>

			<?php endif; ?>

		</div>

		<!-- Script Penanganan Aksi Client-side -->
		<script type="text/javascript">
			function submitRgAction(action) {
				document.getElementById('rg-action-field').value = action;
				document.getElementById('rg-action-form').submit();
			}

			function trustFolder(folderName) {
				document.getElementById('rg-action-field').value = 'trust_folder';
				document.getElementById('rg-folder-field').value = folderName;
				document.getElementById('rg-action-form').submit();
			}

			function untrustFolder(folderName) {
				document.getElementById('rg-action-field').value = 'untrust_folder';
				document.getElementById('rg-folder-field').value = folderName;
				document.getElementById('rg-action-form').submit();
			}

			function submitFolderAction(action, folderName) {
				document.getElementById('rg-action-field').value = action;
				document.getElementById('rg-folder-field').value = folderName;
				document.getElementById('rg-action-form').submit();
			}
		</script>
		<?php
	}
}
