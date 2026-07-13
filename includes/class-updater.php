<?php
/**
 * Update Checker dari repositori GitHub untuk WordPress.
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
 * Mengelola pengecekan rilis versi baru di GitHub dan
 * mengintegrasikannya dengan sistem pembaruan WordPress.
 */
class Updater {

	/**
	 * Versi plugin saat ini.
	 *
	 * @var string
	 */
	private $current_version;

	/**
	 * Nama file utama plugin (wp-root-guard.php).
	 *
	 * @var string
	 */
	private $plugin_file;

	/**
	 * Path relatif plugin (wp-root-guard/wp-root-guard.php).
	 *
	 * @var string
	 */
	private $slug;

	/**
	 * Username pemilik repositori GitHub.
	 *
	 * @var string
	 */
	private $username;

	/**
	 * Nama repositori di GitHub.
	 *
	 * @var string
	 */
	private $repo;

	/**
	 * Cache respons API GitHub untuk efisiensi per request.
	 *
	 * @var object
	 */
	private $github_response;

	/**
	 * Konstruktor.
	 *
	 * @param string $plugin_file Nama file utama plugin.
	 * @param string $username Username GitHub.
	 * @param string $repo Nama repositori GitHub.
	 */
	public function __construct( $plugin_file, $username, $repo ) {
		$this->plugin_file = $plugin_file;
		$this->username    = $username;
		$this->repo        = $repo;
		$this->slug        = plugin_basename( $plugin_file );

		// Mengambil versi dari metadata plugin
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugin_data           = get_plugin_data( $plugin_file );
		$this->current_version = $plugin_data['Version'];
	}

	/**
	 * Mendaftarkan hooks ke WordPress.
	 */
	public function init() {
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_update' ) );
		add_filter( 'plugins_api', array( $this, 'get_plugin_info' ), 20, 3 );
		add_filter( 'upgrader_post_install', array( $this, 'rename_extracted_folder' ), 10, 3 );
	}

	/**
	 * Mendapatkan rilis terbaru dari repositori GitHub.
	 */
	private function get_github_release() {
		if ( ! empty( $this->github_response ) ) {
			return $this->github_response;
		}

		$url = sprintf( 'https://api.github.com/repos/%s/%s/releases/latest', $this->username, $this->repo );

		$args = array(
			'headers' => array(
				'User-Agent' => 'WordPress/' . get_bloginfo( 'version' ) . '; ' . get_bloginfo( 'url' ),
			),
		);

		$response = wp_remote_get( $url, $args );

		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
			return false;
		}

		$body = wp_remote_retrieve_body( $response );
		$data = json_decode( $body );

		if ( empty( $data ) ) {
			return false;
		}

		$this->github_response = $data;
		return $data;
	}

	/**
	 * Membandingkan versi dan menyuntikkan update jika rilis baru tersedia di GitHub.
	 */
	public function check_update( $transient ) {
		if ( empty( $transient->checked ) ) {
			return $transient;
		}

		$release = $this->get_github_release();
		if ( ! $release ) {
			return $transient;
		}

		// Membersihkan karakter 'v' di awal tag rilis (misal: v1.0.2 -> 1.0.2)
		$github_version = ltrim( $release->tag_name, 'v' );

		// Jika versi di GitHub lebih tinggi dari versi terpasang
		if ( version_compare( $github_version, $this->current_version, '>' ) ) {
			$obj              = new \stdClass();
			$obj->slug        = 'wp-root-guard'; // Slug folder plugin
			$obj->plugin      = $this->slug;     // Path relative
			$obj->new_version = $github_version;
			$obj->url         = $release->html_url;
			$obj->package     = $release->zipball_url; // WordPress akan mengunduh source code zip rilis

			$transient->response[ $this->slug ] = $obj;
		}

		return $transient;
	}

	/**
	 * Menyediakan detail plugin saat pengguna mengklik "View Details" di dashboard plugin.
	 */
	public function get_plugin_info( $result, $action, $args ) {
		if ( 'plugin_information' !== $action || empty( $args->slug ) || 'wp-root-guard' !== $args->slug ) {
			return $result;
		}

		$release = $this->get_github_release();
		if ( ! $release ) {
			return $result;
		}

		$github_version = ltrim( $release->tag_name, 'v' );

		$res              = new \stdClass();
		$res->name        = 'WP Root Guard';
		$res->slug        = 'wp-root-guard';
		$res->version     = $github_version;
		$res->author      = 'Mujaddid Halimurrosyid';
		$res->homepage    = 'https://indahweb.com/wp-root-guard';
		$res->download_link = $release->zipball_url;
		$res->sections    = array(
			'description' => 'Mendeteksi folder asing/mencurigakan yang muncul di root directory WordPress Anda untuk mencegah malware judi slot.',
			'changelog'   => nl2br( esc_html( $release->body ) ),
		);

		return $res;
	}

	/**
	 * Merapikan folder ekstraksi GitHub setelah instalasi pembaruan.
	 *
	 * Secara default, GitHub menamai zip release sebagai: `username-repo-hash.zip`.
	 * Saat WordPress mengekstraknya, foldernya akan bernama `username-repo-hash`.
	 * Kita harus me-rename folder tersebut kembali menjadi `wp-root-guard`.
	 */
	public function rename_extracted_folder( $response, $hook_extra, $result ) {
		// Pastikan kita memproses plugin kita sendiri
		if ( empty( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== $this->slug ) {
			return $response;
		}

		global $wp_filesystem;

		$install_directory = plugin_dir_path( $this->plugin_file ); // Path folder yang aktif (wp-content/plugins/wp-root-guard/)
		$destination       = $result['destination'];               // Folder hasil ekstraksi sementara

		// Lakukan rename folder jika tujuannya berbeda dengan folder asli kita
		if ( $destination !== $install_directory ) {
			// Hapus folder asli jika ada (agar tidak bentrok)
			if ( $wp_filesystem->exists( $install_directory ) ) {
				$wp_filesystem->delete( $install_directory, true );
			}
			
			// Ubah nama folder ekstraksi baru menjadi nama folder target asli
			$wp_filesystem->move( $destination, $install_directory );
			$result['destination'] = $install_directory;
		}

		return $response;
	}
}
