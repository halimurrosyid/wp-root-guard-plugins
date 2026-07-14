<?php
/**
 * Mengelola pengecekan dan instalasi pembaruan plugin otomatis dari GitHub.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Updater
 *
 * Menghubungkan sistem pembaruan WordPress dengan GitHub API untuk mengambil
 * rilis terbaru dari repositori secara otomatis.
 */
class Updater {

	/**
	 * Path lengkap file utama plugin.
	 *
	 * @var string
	 */
	private $file;

	/**
	 * Slug plugin (folder-nama/file-utama.php).
	 *
	 * @var string
	 */
	private $plugin_slug;

	/**
	 * Nama pengguna pemilik repositori GitHub.
	 *
	 * @var string
	 */
	private $username;

	/**
	 * Nama repositori di GitHub.
	 *
	 * @var string
	 */
	private $repository;

	/**
	 * URL API GitHub untuk mendapatkan rilis terbaru.
	 *
	 * @var string
	 */
	private $github_api_url;

	/**
	 * Konstruktor Updater.
	 *
	 * @param string $file Path lengkap file utama plugin.
	 */
	public function __construct( $file ) {
		$this->file           = $file;
		$this->plugin_slug    = plugin_basename( $file ); // e.g. 'wp-root-guard/wp-root-guard.php' atau 'WP Root Guard/wp-root-guard.php'
		$this->username       = 'halimurrosyid';
		$this->repository     = 'wp-root-guard-plugins';
		$this->github_api_url = "https://api.github.com/repos/{$this->username}/{$this->repository}/releases/latest";
	}

	/**
	 * Mendaftarkan filter WordPress untuk pembaruan plugin.
	 */
	public function init() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugin_popup' ), 10, 3 );
	}

	/**
	 * Memeriksa apakah ada versi baru di GitHub dan memasukkannya ke sistem pembaruan WordPress.
	 *
	 * @param object $transient Data transient pembaruan plugin saat ini.
	 * @return object Data transient yang telah diperbarui jika ada versi baru.
	 */
	public function check_update( $transient ) {
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$release = $this->get_latest_release();
		if ( ! $release ) {
			return $transient;
		}

		$remote_version = ltrim( $release['tag_name'], 'v' );

		// Bandingkan versi lokal dengan versi rilis di GitHub.
		if ( version_compare( WP_ROOT_GUARD_VERSION, $remote_version, '<' ) ) {
			$obj = new \stdClass();
			// Dapatkan nama direktori plugin.
			$obj->slug        = dirname( $this->plugin_slug );
			$obj->plugin      = $this->plugin_slug;
			$obj->new_version = $remote_version;
			$obj->url         = "https://github.com/{$this->username}/{$this->repository}";
			$obj->package     = $this->get_package_url( $release ); // Link unduh otomatis arsip ZIP dari GitHub.

			$transient->response[ $this->plugin_slug ] = $obj;
		}

		return $transient;
	}

	/**
	 * Menampilkan informasi pop-up detail rilis saat pengguna mengklik "View version details".
	 *
	 * @param object|bool $result Data hasil pencarian API sebelumnya.
	 * @param string      $action Jenis aksi API yang diminta.
	 * @param object      $args Argumen query.
	 * @return object Detail informasi plugin jika cocok.
	 */
	public function plugin_popup( $result, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $result;
		}

		// Periksa apakah slug cocok dengan direktori plugin kita.
		if ( dirname( $this->plugin_slug ) !== $args->slug ) {
			return $result;
		}

		$release = $this->get_latest_release();
		if ( ! $release ) {
			return $result;
		}

		$remote_version = ltrim( $release['tag_name'], 'v' );

		$obj = new \stdClass();
		$obj->name           = 'WP Root Guard';
		$obj->slug           = $args->slug;
		$obj->version        = $remote_version;
		$obj->author         = '<a href="https://indahweb.com" target="_blank">Mujaddid Halimurrosyid</a>';
		$obj->homepage       = "https://github.com/{$this->username}/{$this->repository}";
		$obj->download_link  = $this->get_package_url( $release );
		$obj->sections       = array(
			'description' => esc_html__( 'Mendeteksi folder asing/mencurigakan yang muncul di root directory WordPress Anda untuk mencegah malware judi slot.', 'wp-root-guard' ),
			'changelog'   => isset( $release['body'] ) ? nl2br( esc_html( $release['body'] ) ) : '',
		);

		return $obj;
	}

	/**
	 * Dapatkan URL download paket ZIP (browser_download_url dari asset zip atau zipball_url).
	 *
	 * @param array $release Data rilis dari GitHub API.
	 * @return string URL paket download.
	 */
	private function get_package_url( $release ) {
		$package_url = $release['zipball_url'];
		if ( ! empty( $release['assets'] ) && is_array( $release['assets'] ) ) {
			foreach ( $release['assets'] as $asset ) {
				if ( ! empty( $asset['browser_download_url'] ) && false !== strpos( $asset['browser_download_url'], '.zip' ) ) {
					$package_url = $asset['browser_download_url'];
					break;
				}
			}
		}
		return $package_url;
	}

	/**
	 * Mengambil data rilis terbaru dari GitHub API dengan caching transien 12 jam.
	 *
	 * @return array|bool Data JSON rilis dari GitHub atau false jika gagal.
	 */
	private function get_latest_release() {
		$transient_key = 'wp_root_guard_latest_github_release';
		$cached        = get_transient( $transient_key );

		if ( false !== $cached ) {
			return $cached;
		}

		$args = array(
			'headers' => array(
				'User-Agent' => 'WP-Root-Guard-Updater',
			),
			'timeout' => 10,
		);

		$response = wp_remote_get( $this->github_api_url, $args );

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( 200 !== $code ) {
			return false;
		}

		$body    = wp_remote_retrieve_body( $response );
		$release = json_decode( $body, true );

		if ( ! is_array( $release ) || empty( $release['tag_name'] ) ) {
			return false;
		}

		// Simpan hasil ke cache transien selama 12 jam untuk mencegah rate-limit API GitHub.
		set_transient( $transient_key, $release, 12 * HOUR_IN_SECONDS );

		return $release;
	}
}
