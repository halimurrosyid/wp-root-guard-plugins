<?php
/**
 * Mengoordinasikan seluruh fungsionalitas dan hook plugin.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Plugin
 *
 * Kelas utama yang mendaftarkan semua action, filter, dan memuat
 * class-class pembantu untuk admin, cron, dan widget.
 */
class Plugin {

	/**
	 * Instansi Cron Manager.
	 *
	 * @var Cron
	 */
	private $cron;

	/**
	 * Instansi Admin Manager.
	 *
	 * @var Admin\Admin
	 */
	private $admin;

	/**
	 * Instansi Dashboard Widget Manager.
	 *
	 * @var Admin\Dashboard
	 */
	private $dashboard;

	/**
	 * Instansi Blocker IP Penyerang.
	 *
	 * @var Blocker
	 */
	private $blocker;

	/**
	 * Instansi GitHub Updater.
	 *
	 * @var Updater
	 */
	private $updater;

	/**
	 * Konstruktor. Menginisialisasi komponen utama.
	 */
	public function __construct() {
		$this->cron    = new Cron();
		$this->blocker = new Blocker();
		$this->updater = new Updater( WP_ROOT_GUARD_FILE );

		if ( is_admin() ) {
			$this->admin     = new Admin\Admin();
			$this->dashboard = new Admin\Dashboard();
		}
	}

	/**
	 * Menjalankan plugin dengan mendaftarkan semua hooks ke WordPress.
	 */
	public function run() {
		// Pemuatan translasi.
		add_action( 'plugins_loaded', array( $this, 'load_textdomain' ) );

		// Inisialisasi IP Blocker.
		$this->blocker->init();

		// Inisialisasi GitHub Updater.
		$this->updater->init();

		// Inisialisasi Cron.
		$this->cron->init();

		// Inisialisasi Admin jika berada di area Dashboard Admin.
		if ( is_admin() ) {
			$this->admin->init();
			$this->dashboard->init();
		}
	}

	/**
	 * Memuat berkas terjemahan untuk lokalisasi (Translation Ready).
	 */
	public function load_textdomain() {
		load_plugin_textdomain(
			'wp-root-guard',
			false,
			dirname( dirname( plugin_basename( WP_ROOT_GUARD_FILE ) ) ) . '/languages/'
		);
	}
}
