<?php
/**
 * Pengelola pembaruan otomatis plugin dari repositori GitHub.
 *
 * Berkas ini berisi class Updater yang bertanggung jawab untuk:
 * 1. Memeriksa ketersediaan rilis versi baru dari GitHub Releases API.
 * 2. Menyuntikkan paket pembaruan ke dalam transient update_plugins WordPress.
 * 3. Menampilkan modal pop-up informasi detail plugin dan catatan perubahan (changelog).
 * 4. Memvalidasi domain dan integritas URL paket unduhan rilis demi keamanan.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

namespace WPRootGuard;

// Mencegah akses langsung ke file.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Updater
 *
 * Menghubungkan sistem pembaruan WordPress dengan GitHub Releases API untuk mengambil
 * dan menginstal rilis terbaru dari repositori secara aman dan otomatis.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Updater {

	/**
	 * Nama repositori GitHub dalam format owner/repo.
	 */
	const GITHUB_REPO = 'halimurrosyid/wp-root-guard-plugins';

	/**
	 * Durasi cache data rilis dalam detik (12 jam).
	 */
	const CACHE_DURATION = 43200;

	/**
	 * Kunci transient untuk menyimpan data rilis terbaru dari GitHub.
	 */
	const TRANSIENT_KEY = 'wp_root_guard_latest_github_release';

	/**
	 * Daftar domain resmi yang diizinkan untuk mengunduh paket rilis.
	 */
	const ALLOWED_DOWNLOAD_DOMAINS = array(
		'github.com',
		'codeload.github.com',
		'objects.githubusercontent.com',
	);

	/**
	 * Path lengkap ke file utama plugin.
	 *
	 * @var string
	 */
	private $file;

	/**
	 * Slug plugin (contoh: wp-root-guard/wp-root-guard.php).
	 *
	 * @var string
	 */
	private $plugin_slug;

	/**
	 * URL API GitHub untuk mengambil rilis terbaru.
	 *
	 * @var string
	 */
	private $github_api_url;

	/**
	 * Konstruktor Updater.
	 *
	 * @param string $file Path lengkap file utama plugin.
	 */
	public function __construct( $file = '' ) {
		$this->file           = ! empty( $file ) ? $file : ( defined( 'WP_ROOT_GUARD_FILE' ) ? WP_ROOT_GUARD_FILE : '' );
		$this->plugin_slug    = ! empty( $this->file ) ? plugin_basename( $this->file ) : 'wp-root-guard/wp-root-guard.php';
		$this->github_api_url = 'https://api.github.com/repos/' . self::GITHUB_REPO . '/releases/latest';
	}

	/**
	 * Mendaftarkan filter WordPress untuk pembaruan plugin.
	 *
	 * Hanya dijalankan pada area administrasi (is_admin).
	 *
	 * @return void
	 */
	public function init() {
		if ( ! is_admin() ) {
			return;
		}

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
		if ( ! is_object( $transient ) ) {
			$transient = new \stdClass();
		}

		$release = $this->get_latest_release();
		if ( ! $release || empty( $release['tag_name'] ) ) {
			return $transient;
		}

		$remote_version  = ltrim( $release['tag_name'], 'v' );
		$current_version = defined( 'WP_ROOT_GUARD_VERSION' ) ? WP_ROOT_GUARD_VERSION : '0.0.0';

		// Bandingkan versi lokal dengan versi rilis di GitHub.
		if ( version_compare( $current_version, $remote_version, '<' ) ) {
			$package_url = $this->get_package_url( $release );

			if ( ! empty( $package_url ) && $this->is_valid_download_url( $package_url ) ) {
				$slug = dirname( $this->plugin_slug );
				if ( empty( $slug ) || '.' === $slug ) {
					$slug = 'wp-root-guard';
				}

				$obj               = new \stdClass();
				$obj->slug         = $slug;
				$obj->plugin       = $this->plugin_slug;
				$obj->new_version  = $remote_version;
				$obj->url          = 'https://github.com/' . self::GITHUB_REPO;
				$obj->package      = $package_url;
				$obj->requires     = '6.0';
				$obj->requires_php = '8.1';

				if ( ! isset( $transient->response ) || ! is_array( $transient->response ) ) {
					$transient->response = array();
				}

				$transient->response[ $this->plugin_slug ] = $obj;
			}
		}

		return $transient;
	}

	/**
	 * Menampilkan informasi pop-up detail rilis saat pengguna mengklik "View version details".
	 *
	 * @param object|bool $result Data hasil pencarian API sebelumnya.
	 * @param string      $action Jenis aksi API yang diminta.
	 * @param object      $args   Argumen query dari WordPress.
	 * @return object|bool Detail informasi plugin jika cocok, atau hasil sebelumnya jika tidak cocok.
	 */
	public function plugin_popup( $result, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $result;
		}

		if ( ! is_object( $args ) || empty( $args->slug ) ) {
			return $result;
		}

		$my_slug = dirname( $this->plugin_slug );
		if ( empty( $my_slug ) || '.' === $my_slug ) {
			$my_slug = 'wp-root-guard';
		}

		// Validasi apakah slug sesuai dengan plugin ini.
		$valid_slugs = array(
			$my_slug,
			'wp-root-guard',
			'wp-root-guard-plugins',
			$this->plugin_slug,
		);

		if ( ! in_array( $args->slug, $valid_slugs, true ) ) {
			return $result;
		}

		$release = $this->get_latest_release();
		if ( ! $release ) {
			return $result;
		}

		$remote_version = ! empty( $release['tag_name'] ) ? ltrim( $release['tag_name'], 'v' ) : ( defined( 'WP_ROOT_GUARD_VERSION' ) ? WP_ROOT_GUARD_VERSION : '1.0.0' );
		$package_url    = $this->get_package_url( $release );

		$obj                 = new \stdClass();
		$obj->name           = esc_html( 'WP Root Guard' );
		$obj->slug           = sanitize_key( $args->slug );
		$obj->version        = esc_html( $remote_version );
		$obj->author         = wp_kses_post( '<a href="https://ajidmujaddid.staff.telkomuniversity.ac.id/" target="_blank">Mujaddid Halimurrosyid</a>' );
		$obj->author_profile = esc_url( 'https://ajidmujaddid.staff.telkomuniversity.ac.id/' );
		$obj->homepage       = esc_url( 'https://github.com/' . self::GITHUB_REPO );
		$obj->download_link  = esc_url( $package_url );
		$obj->trunk          = esc_url( $package_url );
		$obj->requires       = '6.0';
		$obj->tested         = '6.7';
		$obj->requires_php   = '8.1';
		$obj->last_updated   = ! empty( $release['published_at'] ) ? sanitize_text_field( $release['published_at'] ) : '';

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

		$changelog_raw  = ! empty( $release['body'] ) ? (string) $release['body'] : esc_html__( 'Tidak ada catatan perubahan rilis.', 'wp-root-guard' );
		$changelog_html = nl2br( esc_html( $changelog_raw ) );

		$obj->sections = array(
			'description'  => wp_kses_post( $description_html ),
			'installation' => wp_kses_post( $installation_html ),
			'changelog'    => wp_kses_post( $changelog_html ),
		);

		return $obj;
	}

	/**
	 * Mengambil data rilis terbaru dari GitHub API dengan caching transien 12 jam.
	 *
	 * Melakukan outbound request dengan sslverify => true, User-Agent konsisten,
	 * caching transient selama 12 jam, dan validasi domain download URL.
	 *
	 * @return array|bool Data rilis dari GitHub atau false jika gagal atau tidak aman.
	 */
	public function get_latest_release() {
		// Hapus transient jika ada permintaan force-check dari dasbor pembaruan WordPress.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if ( isset( $_GET['force-check'] ) && '1' === (string) $_GET['force-check'] ) {
			delete_transient( self::TRANSIENT_KEY );
		}

		$cached = get_transient( self::TRANSIENT_KEY );
		if ( false !== $cached && is_array( $cached ) ) {
			return $cached;
		}

		$version = defined( 'WP_ROOT_GUARD_VERSION' ) ? WP_ROOT_GUARD_VERSION : '1.0.0';
		$args    = array(
			'timeout'   => 15,
			'sslverify' => true,
			'headers'   => array(
				'Accept'     => 'application/vnd.github.v3+json',
				'User-Agent' => 'WP-Root-Guard-Updater/' . $version,
			),
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

		// Validasi URL paket unduhan rilis (domain yang diizinkan dan berakhiran .zip).
		$package_url = $this->get_package_url( $release );
		if ( empty( $package_url ) || ! $this->is_valid_download_url( $package_url ) ) {
			return false;
		}

		// Simpan hasil ke cache transien selama 12 jam (CACHE_DURATION) untuk mencegah rate-limit API GitHub.
		set_transient( self::TRANSIENT_KEY, $release, self::CACHE_DURATION );

		return $release;
	}

	/**
	 * Mendapatkan URL download paket ZIP yang sah dari data rilis.
	 *
	 * Memeriksa aset rilis (.zip) terlebih dahulu, atau menggunakan
	 * URL archive tag resmi GitHub jika aset tidak tersedia.
	 *
	 * @param array $release Data rilis dari GitHub API.
	 * @return string URL paket rilis yang valid, atau string kosong jika tidak ditemukan.
	 */
	public function get_package_url( $release ) {
		if ( ! is_array( $release ) ) {
			return '';
		}

		// 1. Prioritaskan aset rilis berkas .zip jika diunggah pada rilis GitHub.
		if ( ! empty( $release['assets'] ) && is_array( $release['assets'] ) ) {
			foreach ( $release['assets'] as $asset ) {
				if ( ! empty( $asset['browser_download_url'] ) && $this->is_valid_download_url( $asset['browser_download_url'] ) ) {
					return $asset['browser_download_url'];
				}
			}
		}

		// 2. Cek apakah zipball_url valid dan berakhiran .zip.
		if ( ! empty( $release['zipball_url'] ) && $this->is_valid_download_url( $release['zipball_url'] ) ) {
			return $release['zipball_url'];
		}

		// 3. Fallback ke URL archive ZIP tag rilis resmi GitHub.
		if ( ! empty( $release['tag_name'] ) ) {
			$tag_zip_url = 'https://github.com/' . self::GITHUB_REPO . '/archive/refs/tags/' . rawurlencode( $release['tag_name'] ) . '.zip';
			if ( $this->is_valid_download_url( $tag_zip_url ) ) {
				return $tag_zip_url;
			}
		}

		return '';
	}

	/**
	 * Memvalidasi apakah URL paket download aman dan sah dari GitHub.
	 *
	 * Hanya mengizinkan domain github.com, codeload.github.com, objects.githubusercontent.com
	 * dan berkas berakhiran ekstensi .zip.
	 *
	 * @param string $url URL paket rilis yang akan divalidasi.
	 * @return bool True jika URL sah dan aman, false jika sebaliknya.
	 */
	public function is_valid_download_url( $url ) {
		if ( empty( $url ) || ! is_string( $url ) ) {
			return false;
		}

		$parsed = wp_parse_url( $url );
		if ( ! is_array( $parsed ) || empty( $parsed['host'] ) || empty( $parsed['path'] ) ) {
			return false;
		}

		$host = strtolower( $parsed['host'] );
		if ( ! in_array( $host, self::ALLOWED_DOWNLOAD_DOMAINS, true ) ) {
			return false;
		}

		// Validasi path URL harus berakhiran .zip.
		$path = strtolower( $parsed['path'] );
		if ( substr( $path, -4 ) !== '.zip' && 'zip' !== pathinfo( $path, PATHINFO_EXTENSION ) ) {
			return false;
		}

		return true;
	}
}
