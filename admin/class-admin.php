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

		if ( ! empty( $unknown_folders ) ) {
			$count     = count( $unknown_folders );
			$dashboard_url = admin_url( 'index.php?page=wp-root-guard' );
			?>
			<div class="notice notice-error is-dismissible" style="border-left-color: #d63638; padding: 12px 20px;">
				<p style="font-size: 14px; margin: 0 0 6px 0; font-weight: bold; color: #1d2327;">
					⚠️ <?php esc_html_e( 'WP Root Guard: Ancaman Terdeteksi!', 'wp-root-guard' ); ?>
				</p>
				<p style="margin: 0 0 8px 0; color: #50575e;">
					<?php
					printf(
						/* translators: %d: jumlah folder asing */
						esc_html( _n( 'Ditemukan %d folder asing yang tidak dikenal di direktori root WordPress Anda. Hal ini bisa mengindikasikan serangan malware slot judi.', 'Ditemukan %d folder asing yang tidak dikenal di direktori root WordPress Anda. Hal ini bisa mengindikasikan serangan malware slot judi.', $count, 'wp-root-guard' ) ),
						$count
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

		switch ( $action ) {
			case 'scan_now':
				Scanner::perform_scan();
				wp_safe_redirect( add_query_arg( 'message', 'scanned', admin_url( 'index.php?page=wp-root-guard' ) ) );
				exit;

			case 'rebuild_baseline':
				Baseline::rebuild_baseline();
				Scanner::perform_scan();
				wp_safe_redirect( add_query_arg( 'message', 'rebuilt', admin_url( 'index.php?page=wp-root-guard' ) ) );
				exit;

			case 'reset_baseline':
				Baseline::reset_baseline();
				delete_option( 'wp_root_guard_last_scan' );
				delete_option( 'wp_root_guard_unknown_folders' );
				Logger::log( esc_html__( 'Baseline direset oleh administrator', 'wp-root-guard' ), '-', esc_html__( 'Reset', 'wp-root-guard' ) );
				wp_safe_redirect( add_query_arg( 'message', 'reset', admin_url( 'index.php?page=wp-root-guard' ) ) );
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
					// Pindai ulang setelah whitelisting
					Scanner::perform_scan();
					wp_safe_redirect( add_query_arg( 'message', 'trusted', admin_url( 'index.php?page=wp-root-guard' ) ) );
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
					wp_safe_redirect( add_query_arg( 'message', 'untrusted', admin_url( 'index.php?page=wp-root-guard' ) ) );
					exit;
				}
				break;

			case 'clear_logs':
				Logger::clear_logs();
				wp_safe_redirect( add_query_arg( 'message', 'logs_cleared', admin_url( 'index.php?page=wp-root-guard' ) ) );
				exit;
		}
	}

	/**
	 * Merender halaman utama dashboard admin Root Guard.
	 */
	public function render_admin_page() {
		// Dapatkan data-data terbaru
		$results         = Scanner::get_last_scan_results();
		$unknown_folders = Scanner::get_unknown_folders();
		$user_whitelist  = Settings::get_user_whitelist();
		$baseline_list   = Baseline::get_baseline();
		$logs            = Logger::get_logs();

		// Hitung data ringkasan (Summary)
		$protected_count   = count( $baseline_list ) + count( $user_whitelist );
		$whitelisted_count = count( Settings::get_default_whitelist() ) + count( $user_whitelist );
		$unknown_count     = count( $unknown_folders );

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
								<p class="rg-status-desc"><?php esc_html_e( 'Terdeteksi folder asing yang tidak dikenal! Kemungkinan malware.', 'wp-root-guard' ); ?></p>
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

			<!-- Form Nonce Bersama -->
			<form id="rg-action-form" method="post" action="">
				<?php wp_nonce_field( 'wp_root_guard_admin_action', 'wp_root_guard_action_nonce' ); ?>
				<input type="hidden" name="rg_action" id="rg-action-field" value="">
				<input type="hidden" name="folder" id="rg-folder-field" value="">
			</form>

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
					<h2>📂 <?php esc_html_e( 'Hasil Scan: Folder Asing / Belum Dikenal', 'wp-root-guard' ); ?></h2>
				</div>
				<div class="rg-card-body">
					<?php if ( empty( $unknown_folders ) ) : ?>
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
								<?php foreach ( $unknown_folders as $folder ) : ?>
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
											<button type="button" class="button button-small button-link-delete" onclick="if(confirm('<?php echo esc_js( __( 'Apakah Anda yakin ingin membatalkan kepercayaan folder ini?', 'wp-root-guard' ) ); ?>')) { untrustFolder('<?php echo esc_js( $folder_name ); ?>'); }">
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
												if ( esc_html__( 'Safe', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Success', 'wp-root-guard' ) === $log['status'] ) {
													$badge_class .= ' badge-safe';
												} elseif ( esc_html__( 'Threat Detected', 'wp-root-guard' ) === $log['status'] || esc_html__( 'Unknown', 'wp-root-guard' ) === $log['status'] ) {
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
		</script>
		<?php
	}
}
