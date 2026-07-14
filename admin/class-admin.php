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
		array_unshift( $links, $settings_link );
		return $links;
	}

	/**
	 * Menampilkan notifikasi admin merah jika ada folder asing yang terdeteksi.
	 */
	public function render_threat_notice() {
		// Jangan tampilkan notifikasi jika user sudah berada di halaman Root Guard.
		$screen = get_current_screen();
		if ( $screen && 'dashboard_page_wp-root-guard' === $screen->id ) {
			return;
		}

		// Periksa hak akses.
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$unknown_folders = Scanner::get_unknown_folders();

		// Kita filter: folder yang berstatus dikarantina otomatis tidak perlu memicu spanduk bahaya utama,
		// tapi folder asing aktif (Unknown Folder) yang belum diamankan wajib memicu spanduk bahaya!
		$active_threats = 0;
		foreach ( $unknown_folders as $folder ) {
			if ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) !== $folder['status'] ) {
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
					printf(
						/* translators: %d: jumlah folder asing */
						esc_html( _n( 'Ditemukan %d folder asing aktif yang tidak dikenal di root WordPress Anda dan belum diamankan. Harap segera amankan!', 'Ditemukan %d folder asing aktif yang tidak dikenal di root WordPress Anda dan belum diamankan. Harap segera amankan!', $active_threats, 'wp-root-guard' ) ),
						$active_threats
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

		// Menentukan tab aktif untuk redirect yang presisi
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
						esc_html__( 'Folder dipercayai (Whitelist)', 'wp-root-guard' ),
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
						esc_html__( 'Folder dihapus dari Whitelist', 'wp-root-guard' ),
						$folder,
						esc_html__( 'Untrusted', 'wp-root-guard' )
					);
					Scanner::perform_scan();
					wp_safe_redirect( add_query_arg( 'message', 'untrusted', $redirect_url ) );
					exit;
				}
				break;

			case 'clear_logs':
				Logger::clear_logs();
				wp_safe_redirect( add_query_arg( 'message', 'logs_cleared', $redirect_url ) );
				exit;

			case 'save_settings':
				$settings_data = array(
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
	 * Merender halaman utama dasbor admin Root Guard.
	 */
	public function render_admin_page() {
		// Tentukan tab aktif
		$active_tab = isset( $_GET['tab'] ) ? sanitize_text_field( $_GET['tab'] ) : 'dashboard';

		// Data Konfigurasi & Opsi
		$settings        = Settings::get_settings();
		$results         = Scanner::get_last_scan_results();
		$unknown_folders = Scanner::get_unknown_folders();
		$quarantined     = get_option( 'wp_root_guard_quarantined_folders', array() );
		$user_whitelist  = Settings::get_user_whitelist();
		$baseline_list   = Baseline::get_baseline();
		$logs            = Logger::get_logs();

		// Hitung data ringkasan (Summary)
		$protected_count   = count( $baseline_list ) + count( $user_whitelist );
		$whitelisted_count = count( Settings::get_default_whitelist() ) + count( $user_whitelist );
		$unknown_count     = count( $unknown_folders );
		$quarantine_count  = is_array( $quarantined ) ? count( $quarantined ) : 0;

		$last_scan_time = ! empty( $results['last_scan'] ) ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $results['last_scan'] ) ) : esc_html__( 'Belum pernah dipindai', 'wp-root-guard' );

		// Hitung scan berikutnya
		$next_cron      = wp_next_scheduled( 'wp_root_guard_cron_scan' );
		$next_scan_time = $next_cron ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), $next_cron ) : esc_html__( 'Tidak dijadwalkan', 'wp-root-guard' );

		// Tampilkan pesan konfirmasi aksi jika ada
		$message_code = isset( $_GET['message'] ) ? sanitize_text_field( $_GET['message'] ) : '';
		$notice_text  = '';
		$notice_class = 'notice-success';

		switch ( $message_code ) {
			case 'scanned':
				$notice_text = esc_html__( 'Pemindaian root folder selesai.', 'wp-root-guard' );
				break;
			case 'rebuilt':
				$notice_text = esc_html__( 'Baseline folder berhasil dibangun ulang.', 'wp-root-guard' );
				break;
			case 'reset':
				$notice_text = esc_html__( 'Baseline berhasil direset. Silakan buat baseline baru.', 'wp-root-guard' );
				break;
			case 'trusted':
				$notice_text = esc_html__( 'Folder berhasil ditambahkan ke whitelist kustom.', 'wp-root-guard' );
				break;
			case 'untrusted':
				$notice_text = esc_html__( 'Folder berhasil dihapus dari whitelist kustom.', 'wp-root-guard' );
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
				$notice_text = esc_html__( 'Folder berhasil dikembalikan dari karantina ke posisi root asal.', 'wp-root-guard' );
				break;
			case 'restore_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal mengembalikan folder. Pastikan folder asal tidak terisi folder dengan nama yang sama.', 'wp-root-guard' );
				break;
			case 'deleted_permanently':
				$notice_text = esc_html__( 'Folder karantina berhasil dihapus secara permanen dari server.', 'wp-root-guard' );
				break;
			case 'delete_failed':
				$notice_class = 'notice-error';
				$notice_text  = esc_html__( 'Gagal menghapus folder karantina dari server.', 'wp-root-guard' );
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

				<!-- Baris Atas: Status Card & Ringkasan -->
				<div class="rg-dashboard-grid">
					
					<!-- STATUS CARD -->
					<div class="rg-card rg-status-card <?php echo 'safe' === $results['status'] ? 'rg-status-safe' : 'rg-status-threat'; ?>">
						<div class="rg-card-header">
							<h2><?php esc_html_e( 'Status Perlindungan', 'wp-root-guard' ); ?></h2>
						</div>
						<div class="rg-card-body text-center">
							<div class="rg-status-badge">
								<?php if ( 'safe' === $results['status'] ) : ?>
									<span class="rg-icon-large">🛡️</span>
									<span class="rg-status-text text-safe"><?php esc_html_e( 'AMAN', 'wp-root-guard' ); ?></span>
									<p class="rg-status-desc"><?php esc_html_e( 'Tidak ada folder asing mencurigakan yang terdeteksi di root.', 'wp-root-guard' ); ?></p>
								<?php else : ?>
									<span class="rg-icon-large">⚠️</span>
									<span class="rg-status-text text-danger"><?php esc_html_e( 'BAHAYA', 'wp-root-guard' ); ?></span>
									<p class="rg-status-desc"><?php esc_html_e( 'Terdeteksi folder asing aktif di root WordPress Anda!', 'wp-root-guard' ); ?></p>
								<?php endif; ?>
							</div>
						</div>
					</div>

					<!-- SUMMARY CARD -->
					<div class="rg-card rg-summary-card">
						<div class="rg-card-header">
							<h2><?php esc_html_e( 'Ringkasan Sistem', 'wp-root-guard' ); ?></h2>
						</div>
						<div class="rg-card-body">
							<table class="rg-summary-table">
								<tr>
									<th><?php esc_html_e( 'Folder Terlindungi (Baseline + User Whitelist):', 'wp-root-guard' ); ?></th>
									<td><strong><?php echo esc_html( $protected_count ); ?></strong></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Folder Whitelisted:', 'wp-root-guard' ); ?></th>
									<td><strong><?php echo esc_html( $whitelisted_count ); ?></strong></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Folder Asing Terdeteksi:', 'wp-root-guard' ); ?></th>
									<td><strong class="<?php echo $unknown_count > 0 ? 'text-danger' : ''; ?>"><?php echo esc_html( $unknown_count ); ?></strong></td>
								</tr>
								<tr>
									<th><?php esc_html_e( 'Folder dalam Karantina:', 'wp-root-guard' ); ?></th>
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
				</div>

				<!-- PANEL TOMBOL UTAMA -->
				<div class="rg-actions-bar">
					<button type="button" class="button button-primary button-large" onclick="submitRgAction('scan_now')">
						<?php esc_html_e( 'Pindai Sekarang (Scan Now)', 'wp-root-guard' ); ?>
					</button>
					<button type="button" class="button button-secondary button-large" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin membangun ulang baseline? Ini akan merekam kondisi folder root saat ini sebagai standar aman yang baru.', 'wp-root-guard' ) ); ?>')) { submitRgAction('rebuild_baseline'); }">
						<?php esc_html_e( 'Bangun Ulang Baseline (Rebuild Baseline)', 'wp-root-guard' ); ?>
					</button>
					<button type="button" class="button button-link-delete" onclick="if(confirm('<?php echo esc_js( __( 'Peringatan: Reset Baseline akan menghapus data referensi aman dan hasil scan. Anda harus membangun ulang setelahnya. Lanjutkan?', 'wp-root-guard' ) ); ?>')) { submitRgAction('reset_baseline'); }">
						<?php esc_html_e( 'Reset Baseline', 'wp-root-guard' ); ?>
					</button>
				</div>

				<!-- HASIL PEMINDAIAN FOLDER ASING -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>📂 <?php esc_html_e( 'Hasil Scan: Folder Asing Aktif', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php
						// Kita saring folder asing yang benar-benar belum diamankan (bukan yang statusnya dikarantina otomatis pada scan ini)
						$active_unknown = array();
						foreach ( $unknown_folders as $folder ) {
							if ( esc_html__( 'Quarantined Automatically', 'wp-root-guard' ) !== $folder['status'] ) {
								$active_unknown[] = $folder;
							}
						}
						?>
						
						<?php if ( empty( $active_unknown ) ) : ?>
							<div class="rg-empty-message">
								<p>✅ <?php esc_html_e( 'No suspicious folders found.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Nama Folder', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Full Path', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Dibuat', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Terdeteksi', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Status', 'wp-root-guard' ); ?></th>
										<th style="width: 150px;"><?php esc_html_e( 'Aksi', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $active_unknown as $folder ) : ?>
										<tr>
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

				<!-- DAFTAR FOLDER DIKARANTINA -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>🔒 <?php esc_html_e( 'Folder Terkarantina (Quarantined Folders)', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $quarantined ) ) : ?>
							<div class="rg-empty-message">
								<p><?php esc_html_e( 'Tidak ada folder dalam karantina saat ini.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Nama Asli', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Nama Folder Karantina', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Waktu Dikarantina', 'wp-root-guard' ); ?></th>
										<th><?php esc_html_e( 'Status Keamanan', 'wp-root-guard' ); ?></th>
										<th style="width: 250px;"><?php esc_html_e( 'Aksi Karantina', 'wp-root-guard' ); ?></th>
									</tr>
								</thead>
								<tbody>
									<?php foreach ( $quarantined as $item ) : ?>
										<tr>
											<td><strong><?php echo esc_html( $item['original_name'] ); ?></strong></td>
											<td><code><?php echo esc_html( $item['quarantine_name'] ); ?></code></td>
											<td><?php echo esc_html( date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $item['quarantine_time'] ) ) ); ?></td>
											<td><span class="rg-badge badge-safe">🔒 <?php esc_html_e( 'Akses Diblokir (.htaccess)', 'wp-root-guard' ); ?></span></td>
											<td>
												<button type="button" class="button button-small button-primary" style="background-color: #10b981; border-color: #10b981;" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin memulihkan folder ini kembali ke root asal? Folder ini otomatis akan masuk ke Whitelist agar tidak dikarantina kembali.', 'wp-root-guard' ) ); ?>')) { submitFolderAction('restore_folder', '<?php echo esc_js( $item['quarantine_name'] ); ?>'); }">
													↩️ <?php esc_html_e( 'Restore', 'wp-root-guard' ); ?>
												</button>
												<button type="button" class="button button-small button-link-delete" style="text-decoration: none;" onclick="if(confirm('<?php echo esc_js( __( 'Peringatan keras: Folder ini beserta seluruh file di dalamnya akan dihapus secara PERMANEN dari server. Tindakan ini tidak bisa dibatalkan. Lanjutkan?', 'wp-root-guard' ) ); ?>')) { submitFolderAction('delete_permanently', '<?php echo esc_js( $item['quarantine_name'] ); ?>'); }">
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

				<!-- WHITELIST USER -->
				<div class="rg-card rg-table-card">
					<div class="rg-card-header">
						<h2>🛡️ <?php esc_html_e( 'Whitelist Kustom (Folder yang Dipercayai)', 'wp-root-guard' ); ?></h2>
					</div>
					<div class="rg-card-body">
						<?php if ( empty( $user_whitelist ) ) : ?>
							<div class="rg-empty-message">
								<p><?php esc_html_e( 'Belum ada folder yang Anda percayai secara kustom. Anda bisa menekan tombol "Trust Folder" pada folder asing di atas.', 'wp-root-guard' ); ?></p>
							</div>
						<?php else : ?>
							<table class="wp-list-table widefat fixed striped posts rg-styled-table">
								<thead>
									<tr>
										<th><?php esc_html_e( 'Nama Folder', 'wp-root-guard' ); ?></th>
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
												<button type="button" class="button button-small button-link-delete" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin mematikan status percaya untuk folder ini?', 'wp-root-guard' ) ); ?>')) { untrustFolder('<?php echo esc_js( $folder_name ); ?>'); }">
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
											<th><?php esc_html_e( 'Nama Folder', 'wp-root-guard' ); ?></th>
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
										<?php esc_html_e( 'Saat aktif, folder asing mencurigakan yang baru terdeteksi akan otomatis diganti namanya dan diblokir akses HTTP-nya menggunakan file .htaccess.', 'wp-root-guard' ); ?>
									</p>
								</div>
							</div>

							<!-- SECTION 2: EMAIL NOTIFICATIONS -->
							<div class="rg-settings-section">
								<h3>📧 <?php esc_html_e( 'Notifikasi Email', 'wp-root-guard' ); ?></h3>
								<hr>
								<div class="rg-form-group">
									<label class="rg-switch-label">
										<input type="checkbox" id="rg-toggle-email" name="enable_email_notifications" value="1" <?php checked( $settings['enable_email_notifications'], true ); ?> onchange="toggleEmailSection()">
										<span class="rg-switch-slider"></span>
										<strong><?php esc_html_e( 'Aktifkan Notifikasi Email', 'wp-root-guard' ); ?></strong>
									</label>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Kirim email laporan otomatis ketika ditemukan folder asing baru.', 'wp-root-guard' ); ?>
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
										<input type="checkbox" id="rg-toggle-telegram" name="enable_telegram_notifications" value="1" <?php checked( $settings['enable_telegram_notifications'], true ); ?> onchange="toggleTelegramSection()">
										<span class="rg-switch-slider"></span>
										<strong><?php esc_html_e( 'Aktifkan Notifikasi Telegram', 'wp-root-guard' ); ?></strong>
									</label>
									<p class="rg-field-desc">
										<?php esc_html_e( 'Kirim pesan instan otomatis melalui bot Telegram Anda saat ancaman baru terdeteksi.', 'wp-root-guard' ); ?>
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
					function toggleEmailSection() {
						var toggle = document.getElementById('rg-toggle-email');
						var section = document.getElementById('rg-email-fields');
						if (toggle.checked) {
							section.classList.remove('hidden');
						} else {
							section.classList.add('hidden');
						}
					}

					function toggleTelegramSection() {
						var toggle = document.getElementById('rg-toggle-telegram');
						var section = document.getElementById('rg-telegram-fields');
						if (toggle.checked) {
							section.classList.remove('hidden');
						} else {
							section.classList.add('hidden');
						}
					}

					function triggerTestNotification(action) {
						var mainForm = document.getElementById('rg-action-form');
						var actionField = document.getElementById('rg-action-field');
						var folderField = document.getElementById('rg-folder-field');

						// Hapus input tambahan tes sebelumnya agar bersih
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

							// Sisipkan data input secara dinamis ke form tindakan
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
