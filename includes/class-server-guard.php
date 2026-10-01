<?php
/**
 * Service untuk menyiapkan dan memvalidasi proteksi eksekusi file di uploads.
 *
 * Service ini tidak menulis konfigurasi server dan tidak membuat fixture HTTP.
 * Apache dapat menerima snippet .htaccess yang idempotent, sedangkan Nginx dan
 * IIS hanya menerima guidance karena perubahan konfigurasi memerlukan akses
 * administrator server.
 *
 * @package WPRootGuard
 * @since   3.3.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Menangani deteksi best-effort dan deskripsi status server guard.
 *
 * @package WPRootGuard
 * @since   3.3.0
 */
class ServerGuard {

	/** Status ketika rule telah dipasang tetapi belum diuji dari HTTP. */
	const STATUS_CONFIGURED = 'configured';

	/** Status ketika rule telah diuji dan menolak eksekusi uploads. */
	const STATUS_VERIFIED = 'verified';

	/** Status ketika konfigurasi belum dapat dibuktikan. */
	const STATUS_UNVERIFIED = 'unverified';

	/** Status ketika server family tidak mendukung metode yang tersedia. */
	const STATUS_UNSUPPORTED = 'unsupported';

	/** Status ketika konfigurasi atau validasi guard gagal. */
	const STATUS_FAILED = 'failed';

	/** Marker awal rule WP Root Guard pada .htaccess. */
	const APACHE_BEGIN_MARKER = '# BEGIN WP ROOT GUARD UPLOADS EXECUTION GUARD';

	/** Marker akhir rule WP Root Guard pada .htaccess. */
	const APACHE_END_MARKER = '# END WP ROOT GUARD UPLOADS EXECUTION GUARD';
	const STATUS_OPTION = 'wp_root_guard_server_guard';

	/**
	 * Mendeteksi keluarga web server berdasarkan informasi runtime yang tersedia.
	 *
	 * Hasil ini bersifat best-effort. Reverse proxy dapat menyembunyikan server
	 * origin, sehingga hasil `unknown` harus diperlakukan sebagai tidak terbukti.
	 *
	 * @return string Salah satu apache, nginx, iis, atau unknown.
	 */
	public static function detect_server_family() {
		$values = array();

		foreach ( array( 'SERVER_SOFTWARE', 'SERVER_SIGNATURE', 'SERVER_API' ) as $key ) {
			if ( isset( $_SERVER[ $key ] ) && is_string( $_SERVER[ $key ] ) ) {
				$values[] = strtolower( wp_unslash( $_SERVER[ $key ] ) );
			}
		}

		$server = implode( ' ', $values );

		if ( false !== strpos( $server, 'microsoft-iis' ) || false !== strpos( $server, 'iis' ) ) {
			return 'iis';
		}

		if ( false !== strpos( $server, 'nginx' ) ) {
			return 'nginx';
		}

		if ( false !== strpos( $server, 'apache' ) || false !== strpos( $server, 'litespeed' ) ) {
			return 'apache';
		}

		return 'unknown';
	}

	/**
	 * Mendapatkan status awal guard tanpa mengklaim proteksi telah aktif.
	 *
	 * @param string|null $server_family Keluarga server override untuk testing.
	 * @return array Status terstruktur untuk dashboard atau penyimpanan option.
	 */
	public static function get_initial_status( $server_family = null ) {
		$family = is_string( $server_family ) && '' !== trim( $server_family )
			? strtolower( trim( $server_family ) )
			: self::detect_server_family();

		$family = self::sanitize_server_family( $family );

		if ( 'apache' === $family ) {
			$status = self::STATUS_UNVERIFIED;
		} elseif ( in_array( $family, array( 'nginx', 'iis' ), true ) ) {
			$status = self::STATUS_UNVERIFIED;
		} else {
			$status = self::STATUS_UNSUPPORTED;
		}

		return self::sanitize_status_data(
			array(
				'status'        => $status,
				'server_family' => $family,
				'checked_at_gmt'=> gmdate( 'Y-m-d H:i:s' ),
				'message'       => self::get_status_message( $status, $family ),
				'source'        => 'runtime-detection',
			)
		);
	}

	/**
	 * Memasang rule Apache pada uploads secara idempoten.
	 *
	 * @return array Status pemasangan.
	 */
	public static function install_apache_uploads_guard() {
		if ( 'apache' !== self::detect_server_family() ) {
			return self::persist_status( array( 'status' => self::STATUS_UNSUPPORTED, 'message' => 'Server bukan Apache.' ) );
		}

		$uploads = wp_upload_dir();
		$directory = isset( $uploads['basedir'] ) ? $uploads['basedir'] : '';
		if ( '' === $directory || ! is_dir( $directory ) ) {
			return self::persist_status( array( 'status' => self::STATUS_FAILED, 'message' => 'Direktori uploads tidak ditemukan.' ) );
		}

		$path = trailingslashit( $directory ) . '.htaccess';
		$existing = file_exists( $path ) ? (string) @file_get_contents( $path ) : '';
		$block = self::get_apache_uploads_rules();
		$pattern = '/' . preg_quote( self::APACHE_BEGIN_MARKER, '/' ) . '.*?' . preg_quote( self::APACHE_END_MARKER, '/' ) . '/s';
		$content = preg_match( $pattern, $existing ) ? preg_replace( $pattern, $block, $existing ) : rtrim( $existing ) . ( '' === trim( $existing ) ? '' : "\n\n" ) . $block . "\n";
		$backup = '';
		if ( '' !== $existing ) {
			$backup = $path . '.wp-root-guard.bak';
			AtomicWriter::write( $backup, $existing, 0600 );
		}

		$result = AtomicWriter::write( $path, $content, 0644 );
		if ( is_wp_error( $result ) ) {
			return self::persist_status( array( 'status' => self::STATUS_FAILED, 'message' => $result->get_error_message() ) );
		}

		return self::persist_status( array( 'status' => self::STATUS_CONFIGURED, 'message' => 'Rule Apache berhasil ditulis; verifikasi HTTP diperlukan.' ) );
	}

	/**
	 * Memverifikasi bahwa PHP pada uploads ditolak oleh HTTP server.
	 *
	 * @return array Status verifikasi.
	 */
	public static function verify_uploads_guard() {
		$uploads = wp_upload_dir();
		$base = isset( $uploads['basedir'] ) ? $uploads['basedir'] : '';
		$url_base = isset( $uploads['baseurl'] ) ? trailingslashit( $uploads['baseurl'] ) : '';
		if ( '' === $base || '' === $url_base || ! is_dir( $base ) ) {
			return self::persist_status( array( 'status' => self::STATUS_FAILED, 'message' => 'Uploads URL/path tidak tersedia.' ) );
		}

		$probe = '.wp-root-guard-probe-' . wp_generate_password( 16, false, false ) . '.php';
		$probe_path = trailingslashit( $base ) . $probe;
		$probe_url = $url_base . rawurlencode( $probe );
		$written = AtomicWriter::write( $probe_path, "<?php echo 'WP_ROOT_GUARD_PROBE';", 0600 );
		if ( is_wp_error( $written ) ) {
			return self::persist_status( array( 'status' => self::STATUS_FAILED, 'message' => 'Probe file tidak dapat dibuat.' ) );
		}

		try {
			$response = wp_remote_get( $probe_url, array( 'timeout' => 10, 'redirection' => 0, 'sslverify' => true ) );
		} catch ( \Throwable $exception ) {
			$response = new \WP_Error( 'uploads_probe_exception', $exception->getMessage() );
		} finally {
			// Do not leave a runnable probe behind, even if the HTTP client fails.
			@unlink( $probe_path );
		}
		if ( is_wp_error( $response ) ) {
			return self::persist_status( array( 'status' => self::STATUS_UNVERIFIED, 'message' => $response->get_error_message() ) );
		}

		$code = (int) wp_remote_retrieve_response_code( $response );
		// 404 can be generated by a rewrite, CDN, or bad uploads URL. Only a
		// direct 403 proves that execution access to the known probe was denied.
		$status = 403 === $code ? self::STATUS_VERIFIED : self::STATUS_UNVERIFIED;
		return self::persist_status( array( 'status' => $status, 'message' => 'HTTP probe uploads mengembalikan status ' . $code . '.' ) );
	}

	/** @return array Status tersimpan. */
	public static function get_status() {
		$saved = get_option( self::STATUS_OPTION, array() );
		return self::sanitize_status_data( is_array( $saved ) ? $saved : self::get_initial_status() );
	}

	/** @param array $data Status parsial. @return array */
	private static function persist_status( $data ) {
		$current = self::get_status();
		$result = self::sanitize_status_data( array_merge( $current, $data, array( 'checked_at_gmt' => gmdate( 'Y-m-d H:i:s' ), 'source' => 'runtime-verification' ) ) );
		update_option( self::STATUS_OPTION, $result, false );
		return $result;
	}

	/**
	 * Membuat blok .htaccess idempotent untuk direktori tempat blok ditempatkan.
	 *
	 * Snippet ini sengaja tidak menerima path arbitrary. Tempatkan hasilnya di
	 * `wp-content/uploads/.htaccess` dan, bila vault masih berada di webroot, di
	 * direktori vault secara terpisah.
	 *
	 * @return string Snippet Apache dengan marker eksplisit.
	 */
	public static function get_apache_deny_rules() {
		$extensions = 'php|phtml|php[0-9]?|phps|phar|inc';

		return self::APACHE_BEGIN_MARKER . "\n"
			. '<IfModule mod_authz_core.c>' . "\n"
			. "\t<FilesMatch \"\\.(" . $extensions . ")$\">\n"
			. "\t\tRequire all denied\n"
			. "\t</FilesMatch>\n"
			. '</IfModule>' . "\n"
			. '<IfModule !mod_authz_core.c>' . "\n"
			. "\t<FilesMatch \"\\.(" . $extensions . ")$\">\n"
			. "\t\tDeny from all\n"
			. "\t</FilesMatch>\n"
			. '</IfModule>' . "\n"
			. self::APACHE_END_MARKER;
	}

	/**
	 * Mendapatkan rule Apache untuk ditempatkan di direktori uploads.
	 *
	 * @return string Snippet .htaccess untuk uploads.
	 */
	public static function get_apache_uploads_rules() {
		return self::get_apache_deny_rules();
	}

	/**
	 * Mendapatkan rule Apache untuk ditempatkan di direktori vault quarantine.
	 *
	 * @return string Snippet .htaccess untuk vault.
	 */
	public static function get_apache_vault_rules() {
		return self::get_apache_deny_rules();
	}

	/**
	 * Memberikan guidance Nginx tanpa mencoba menulis konfigurasi server.
	 *
	 * @param string $uploads_path Path URL relatif, default `/wp-content/uploads/`.
	 * @return array Guidance dan status deployment.
	 */
	public static function get_nginx_guidance( $uploads_path = '/wp-content/uploads/' ) {
		$path = self::sanitize_url_path( $uploads_path, '/wp-content/uploads/' );

		return array(
			'status'  => self::STATUS_UNVERIFIED,
			'snippet' => "location ~* ^" . preg_quote( $path, '#' ) . '.*\\.(php|phtml|php[0-9]?|phps|phar|inc)$ {' . "\n"
				. "\treturn 403;\n"
				. "}",
			'notice'  => 'Tambahkan rule pada konfigurasi server Nginx lalu reload Nginx. Plugin tidak memasang atau memverifikasi rule ini secara otomatis.',
		);
	}

	/**
	 * Memberikan guidance IIS tanpa mencoba menulis web.config.
	 *
	 * @return array Guidance dan snippet XML.
	 */
	public static function get_iis_guidance() {
		return array(
			'status'  => self::STATUS_UNVERIFIED,
			'snippet' => "<configuration>\n"
				. "\t<system.webServer>\n"
				. "\t\t<security>\n"
				. "\t\t\t<requestFiltering>\n"
				. "\t\t\t\t<fileExtensions>\n"
				. "\t\t\t\t\t<add fileExtension=\".php\" allowed=\"false\" />\n"
				. "\t\t\t\t\t<add fileExtension=\".phtml\" allowed=\"false\" />\n"
				. "\t\t\t\t</fileExtensions>\n"
				. "\t\t\t</requestFiltering>\n"
				. "\t\t</security>\n"
				. "\t</system.webServer>\n"
				. '</configuration>',
			'notice'  => 'Tambahkan rule pada web.config atau IIS Manager. Plugin tidak memasang atau memverifikasi rule ini secara otomatis.',
		);
	}

	/**
	 * Memvalidasi dan menormalisasi data status dari option atau dashboard.
	 *
	 * @param mixed $data Data status mentah.
	 * @return array Status aman dan konsisten.
	 */
	public static function sanitize_status_data( $data ) {
		$data = is_array( $data ) ? $data : array();
		$status = isset( $data['status'] ) ? self::sanitize_status( $data['status'] ) : self::STATUS_UNVERIFIED;
		$family = isset( $data['server_family'] ) ? self::sanitize_server_family( $data['server_family'] ) : 'unknown';

		return array(
			'status'         => $status,
			'server_family'  => $family,
			'checked_at_gmt' => self::sanitize_datetime( isset( $data['checked_at_gmt'] ) ? $data['checked_at_gmt'] : '' ),
			'message'        => self::sanitize_text( isset( $data['message'] ) ? $data['message'] : '' ),
			'source'         => self::sanitize_text( isset( $data['source'] ) ? $data['source'] : '' ),
		);
	}

	/**
	 * Memastikan status termasuk daftar status resmi.
	 *
	 * @param mixed $status Status mentah.
	 * @return string Status tervalidasi.
	 */
	public static function sanitize_status( $status ) {
		$status = self::sanitize_text( $status );
		$allowed = array(
			self::STATUS_CONFIGURED,
			self::STATUS_VERIFIED,
			self::STATUS_UNVERIFIED,
			self::STATUS_UNSUPPORTED,
			self::STATUS_FAILED,
		);

		return in_array( $status, $allowed, true ) ? $status : self::STATUS_UNVERIFIED;
	}

	/**
	 * Memeriksa apakah status guard merupakan status yang didukung.
	 *
	 * @param mixed $status Status guard.
	 * @return bool True jika status valid.
	 */
	public static function is_valid_status( $status ) {
		return self::sanitize_status( $status ) === $status;
	}

	/**
	 * @param mixed $family Keluarga server mentah.
	 * @return string Keluarga server tervalidasi.
	 */
	private static function sanitize_server_family( $family ) {
		$family = self::sanitize_text( $family );
		$allowed = array( 'apache', 'nginx', 'iis', 'unknown' );

		return in_array( $family, $allowed, true ) ? $family : 'unknown';
	}

	/**
	 * @param mixed  $value Nilai teks mentah.
	 * @param string $fallback Nilai fallback.
	 * @return string Teks bersih.
	 */
	private static function sanitize_text( $value, $fallback = '' ) {
		if ( ! is_scalar( $value ) ) {
			return $fallback;
		}

		$value = (string) $value;
		return function_exists( 'sanitize_text_field' ) ? sanitize_text_field( $value ) : trim( strip_tags( $value ) );
	}

	/**
	 * @param mixed $value Waktu mentah.
	 * @return string Waktu GMT atau string kosong.
	 */
	private static function sanitize_datetime( $value ) {
		$value = self::sanitize_text( $value );
		if ( '' === $value ) {
			return '';
		}

		$timestamp = strtotime( $value . ' UTC' );
		return false === $timestamp ? '' : gmdate( 'Y-m-d H:i:s', $timestamp );
	}

	/**
	 * @param mixed  $path Path URL mentah.
	 * @param string $fallback Path fallback.
	 * @return string Path URL relatif yang aman.
	 */
	private static function sanitize_url_path( $path, $fallback ) {
		$path = self::sanitize_text( $path );
		$path = '/' . ltrim( $path, '/' );
		$path = preg_replace( '#/+#', '/', $path );

		if ( false === $path || false !== strpos( $path, '..' ) || false !== strpos( $path, "\0" ) ) {
			return $fallback;
		}

		return rtrim( $path, '/' ) . '/';
	}

	/**
	 * @param string $status Status guard.
	 * @param string $family Keluarga server.
	 * @return string Pesan singkat untuk admin.
	 */
	private static function get_status_message( $status, $family ) {
		if ( self::STATUS_UNSUPPORTED === $status ) {
			return 'Keluarga web server tidak dikenali; proteksi server belum dapat diverifikasi.';
		}

		return sprintf( 'Keluarga server terdeteksi sebagai %s; konfigurasi masih perlu divalidasi dari HTTP.', $family );
	}
}
