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
		add_filter( 'site_transient_update_plugins', array( $this, 'check_update' ) );
		add_filter( 'plugins_api', array( $this, 'plugin_popup' ), 10, 3 );
	}

	/**
	 * Memeriksa apakah ada versi baru di GitHub dan memasukkannya ke sistem pembaruan WordPress.
	 *
	 * @param object $transient Data transient pembaruan plugin saat ini.
	 * @return object Data transient yang telah diperbarui jika ada versi baru.
	 */
	public function check_update( $transient ) {
		if ( ! is_object( $transient ) ) {
			$transient = new \stdClass();
		}

		$release = $this->get_latest_release();
		if ( ! $release ) {
			return $transient;
		}

		$remote_version = ltrim( $release['tag_name'], 'v' );

		// Bandingkan versi lokal dengan versi rilis di GitHub.
		if ( version_compare( WP_ROOT_GUARD_VERSION, $remote_version, '<' ) ) {
			$obj = new \stdClass();
			$obj->slug        = dirname( $this->plugin_slug );
			$obj->plugin      = $this->plugin_slug;
			$obj->new_version = $remote_version;
			$obj->url         = "https://github.com/{$this->username}/{$this->repository}";
			$obj->package     = $this->get_package_url( $release ); // Link unduh otomatis arsip ZIP dari GitHub.

			if ( ! isset( $transient->response ) || ! is_array( $transient->response ) ) {
				$transient->response = array();
			}

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
		$obj->author         = '<a href="https://ajidmujaddid.staff.telkomuniversity.ac.id/" target="_blank">Mujaddid Halimurrosyid</a>';
		$obj->homepage       = "https://github.com/{$this->username}/{$this->repository}";
		$obj->download_link  = $this->get_package_url( $release );
		$description_html  = '<p><strong>WP Root Guard</strong> adalah plugin keamanan WordPress profesional, super ringan, dan efisien yang dirancang khusus untuk melindungi direktori root (<code>public_html</code>), direktori sistem (<code>wp-admin</code> &amp; <code>wp-includes</code>), serta folder media (<code>wp-content/uploads/</code>) dari serangan malware judi slot, backdoor, dan webshell injection.</p>';
		$description_html .= '<h4>🛡️ Fitur Keamanan Unggulan:</h4>';
		$description_html .= '<ul>';
		$description_html .= '<li><strong>Integritas Core Checksums WordPress.org API</strong>: Mendeteksi modifikasi, pemalsuan, atau penghapusan berkas core resmi WordPress secara real-time.</li>';
		$description_html .= '<li><strong>Perbaikan Berkas Core Otomatis</strong>: Memulihkan berkas core yang rusak/terinjeksi secara instan langsung dari SVN resmi WordPress.org.</li>';
		$description_html .= '<li><strong>Uploads PHP Security Guard</strong>: Memindai dan mengisolasi berkas eksekusi PHP ilegal di dalam folder media <code>wp-content/uploads/</code>.</li>';
		$description_html .= '<li><strong>Attacker IP Blocker &amp; .htaccess Access Guard</strong>: Mencegat percobaan eksekusi webshell dan otomatis memblokir IP penyerang di <code>.htaccess</code>.</li>';
		$description_html .= '<li><strong>Inspektur Kode Berkas (Secure Code Inspector)</strong>: Menginspeksi isi berkas read-only yang aman dengan penandaan warna stabilo merah otomatis (Malware Signature Highlighting).</li>';
		$description_html .= '<li><strong>Notifikasi Instan Real-Time</strong>: Pengiriman notifikasi peringatan instan ke Telegram Bot API dan Email Administrator.</li>';
		$description_html .= '<li><strong>Vault Karantina Terisolasi Khusus</strong>: Menyimpan seluruh berkas terisolasi di <code>wp-content/uploads/wp-root-guard-quarantine/</code> yang dikunci ketat dengan <code>.htaccess</code>.</li>';
		$description_html .= '</ul>';

		$installation_html  = '<ol>';
		$installation_html .= '<li>Unggah folder <code>wp-root-guard</code> ke direktori <code>/wp-content/plugins/</code>.</li>';
		$installation_html .= '<li>Aktifkan plugin melalui menu <strong>Plugins</strong> di dasbor WordPress.</li>';
		$installation_html .= '<li>Buka menu <strong>Dashboard -&gt; Root Guard</strong> untuk memantau status keamanan situs Anda.</li>';
		$installation_html .= '</ol>';

		$obj->sections = array(
			'description'  => $description_html,
			'installation' => $installation_html,
			'changelog'    => isset( $release['body'] ) ? nl2br( esc_html( $release['body'] ) ) : '',
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

		// Hapus transient jika ada permintaan force-check dari dasbor pembaruan wordpress.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['force-check'] ) && 1 == $_GET['force-check'] ) {
			delete_transient( $transient_key );
		}

		$cached = get_transient( $transient_key );

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
