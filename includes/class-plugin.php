<?php
/**
 * Orkestrator utama plugin WP Root Guard.
 *
 * Berkas ini berisi class Plugin yang bertanggung jawab untuk:
 * 1. Menginisialisasi komponen utama (Cron, Blocker, Updater).
 * 2. Mendaftarkan hook lifecycle plugin.
 * 3. Memuat textdomain untuk i18n.
 * 4. Menginisialisasi komponen admin jika berada di area admin.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Plugin
 *
 * Kelas utama yang mendaftarkan semua action, filter, dan memuat
 * class-class pembantu untuk admin, cron, dan widget.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Plugin {

	/** @var Cron|null */
	private $cron;

	/** @var Admin\Admin|null */
	private $admin;

	/** @var Admin\Dashboard|null */
	private $dashboard;

	/** @var Blocker|null */
	private $blocker;

	/** @var Updater|null */
	private $updater;

	/**
	 * Konstruktor. Menginisialisasi komponen utama dengan class_exists guard.
	 */
	public function __construct() {
		if ( class_exists( __NAMESPACE__ . '\\Cron' ) ) {
			$this->cron = new Cron();
		}
		if ( class_exists( __NAMESPACE__ . '\\Blocker' ) ) {
			$this->blocker = new Blocker();
		}
		if ( class_exists( __NAMESPACE__ . '\\Updater' ) ) {
			$this->updater = new Updater( WP_ROOT_GUARD_FILE );
		}

		if ( is_admin() ) {
			if ( class_exists( __NAMESPACE__ . '\\Admin\\Admin' ) ) {
				$this->admin = new Admin\Admin();
			}
			if ( class_exists( __NAMESPACE__ . '\\Admin\\Dashboard' ) ) {
				$this->dashboard = new Admin\Dashboard();
			}
		}
	}

	/**
	 * Menjalankan plugin dengan mendaftarkan semua hooks ke WordPress.
	 */
	public function run() {
		add_action( 'init', array( $this, 'load_textdomain' ) );

		// Blocker dilewati di cron / WP-CLI untuk mencegah self-block.
		if ( $this->blocker instanceof Blocker
			&& ! wp_doing_cron()
			&& ! ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			$this->blocker->init();
		}

		// Updater hanya relevan di admin.
		if ( is_admin() && $this->updater instanceof Updater ) {
			$this->updater->init();
		}

		if ( $this->cron instanceof Cron ) {
			$this->cron->init();
		}

		if ( is_admin() && isset( $this->admin, $this->dashboard ) ) {
			$this->admin->init();
			$this->dashboard->init();
		}
	}

	/**
	 * Memuat berkas terjemahan untuk lokalisasi.
	 *
	 * Path: wp-content/plugins/wp-root-guard/languages/
	 */
	public function load_textdomain() {
		load_plugin_textdomain(
			'wp-root-guard',
			false,
			dirname( plugin_basename( WP_ROOT_GUARD_FILE ) ) . '/languages/'
		);
	}
}
