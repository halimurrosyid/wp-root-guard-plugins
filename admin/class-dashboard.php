<?php
/**
 * Mengelola widget dashboard WordPress.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard\Admin;

use WPRootGuard\Scanner;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Dashboard
 *
 * Membuat dan merender widget status keamanan di dashboard WordPress.
 */
class Dashboard {

	/**
	 * Mendaftarkan hooks untuk Dashboard widget.
	 */
	public function init() {
		add_action( 'wp_dashboard_setup', array( $this, 'add_dashboard_widget' ) );
	}

	/**
	 * Menambahkan widget ke dashboard WordPress.
	 */
	public function add_dashboard_widget() {
		// Hanya user dengan kapabilitas manage_options yang dapat melihat widget ini.
		if ( current_user_can( 'manage_options' ) ) {
			wp_add_dashboard_widget(
				'wp_root_guard_dashboard_widget',
				esc_html__( '🛡️ WP Root Guard Status', 'wp-root-guard' ),
				array( $this, 'render_widget' )
			);
		}
	}

	/**
	 * Merender konten widget dashboard.
	 */
	public function render_widget() {
		$results       = Scanner::get_last_scan_results();
		$unknown_count = $results['unknown_count'];

		$last_scan_time = ! empty( $results['last_scan'] ) ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $results['last_scan'] ) ) : esc_html__( 'Belum pernah dipindai', 'wp-root-guard' );

		// Tambahkan gaya minimal khusus untuk widget dashboard.
		?>
		<div class="rg-widget-content" style="padding: 5px 0;">
			<div class="rg-widget-status" style="margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
				<span style="font-size: 20px;">
					<?php echo 'safe' === $results['status'] ? '🛡️' : '⚠️'; ?>
				</span>
				<div>
					<span style="font-weight: bold; font-size: 14px;">
						<?php esc_html_e( 'Status:', 'wp-root-guard' ); ?>
					</span>
					<?php if ( 'safe' === $results['status'] ) : ?>
						<span style="color: #46b450; font-weight: bold; font-size: 14px;">
							<?php esc_html_e( 'Safe', 'wp-root-guard' ); ?>
						</span>
					<?php else : ?>
						<span style="color: #dc3232; font-weight: bold; font-size: 14px;">
							<?php esc_html_e( 'Threat Detected', 'wp-root-guard' ); ?>
						</span>
					<?php endif; ?>
				</div>
			</div>

			<table class="rg-widget-info-table" style="width: 100%; margin-bottom: 15px; border-collapse: collapse;">
				<tr style="border-bottom: 1px solid #f0f0f1;">
					<th style="text-align: left; padding: 6px 0; font-weight: normal; color: #50575e;">
						<?php esc_html_e( 'Terakhir Dipindai:', 'wp-root-guard' ); ?>
					</th>
					<td style="text-align: right; padding: 6px 0; font-weight: bold; color: #1d2327;">
						<?php echo esc_html( $last_scan_time ); ?>
					</td>
				</tr>
				<tr>
					<th style="text-align: left; padding: 6px 0; font-weight: normal; color: #50575e;">
						<?php esc_html_e( 'Folder Asing Terdeteksi:', 'wp-root-guard' ); ?>
					</th>
					<td style="text-align: right; padding: 6px 0; font-weight: bold; color: <?php echo $unknown_count > 0 ? '#dc3232' : '#1d2327'; ?>;">
						<?php echo esc_html( $unknown_count ); ?>
					</td>
				</tr>
			</table>

			<div class="rg-widget-actions" style="display: flex; gap: 8px; align-items: center; margin-top: 10px;">
				<form method="post" action="<?php echo esc_url( admin_url( 'index.php?page=wp-root-guard' ) ); ?>" style="margin: 0; display: inline-block;">
					<?php wp_nonce_field( 'wp_root_guard_admin_action', 'wp_root_guard_action_nonce' ); ?>
					<input type="hidden" name="rg_action" value="scan_now">
					<button type="submit" class="button button-primary">
						<?php esc_html_e( 'Scan Now', 'wp-root-guard' ); ?>
					</button>
				</form>
				<a href="<?php echo esc_url( admin_url( 'index.php?page=wp-root-guard' ) ); ?>" class="button button-secondary">
					<?php esc_html_e( 'Buka Dashboard', 'wp-root-guard' ); ?>
				</a>
			</div>
		</div>
		<?php
	}
}
