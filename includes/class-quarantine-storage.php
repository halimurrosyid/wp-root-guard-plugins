<?php
/**
 * Abstraksi penyimpanan quarantine yang aman.
 *
 * Class ini hanya menyediakan resolusi path dan metadata. Migrasi, pemindahan,
 * penghapusan, dan integrasi dengan Scanner dilakukan oleh layer pemanggil.
 *
 * @package WPRootGuard
 * @since   3.3.0
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class QuarantineStorage
 *
 * Menentukan lokasi vault quarantine dengan prioritas:
 * 1. Konstanta WP_ROOT_GUARD_QUARANTINE_DIR jika valid.
 * 2. Direktori best-effort di luar webroot.
 * 3. Fallback yang ditandai di dalam uploads.
 *
 * Tidak ada method di class ini yang memindahkan atau menghapus file.
 */
class QuarantineStorage {

	/** Nama direktori fallback di uploads. */
	const FALLBACK_DIRNAME = 'wp-root-guard-quarantine';

	/** Nama direktori default di luar webroot. */
	const OUTSIDE_DIRNAME = 'wp-root-guard-quarantine';

	/** Mode direktori private. */
	const DIRECTORY_MODE = 0700;

	/** Mode file quarantine. */
	const FILE_MODE = 0600;

	/**
	 * Menentukan dan menyiapkan direktori quarantine.
	 *
	 * @return array{directory:string, source:string, status:string, outside_webroot:string, webroot:string, error:string}
	 */
	public static function resolve_directory() {
		$webroot = self::get_webroot();
		$attempts = array();

		if ( defined( 'WP_ROOT_GUARD_QUARANTINE_DIR' ) && WP_ROOT_GUARD_QUARANTINE_DIR ) {
			$explicit = self::normalize_path( WP_ROOT_GUARD_QUARANTINE_DIR );
			$attempts[] = 'explicit';
			$result = self::prepare_directory( $explicit, $webroot );
			if ( $result['status'] === 'ready' ) {
				$result['source'] = 'explicit';
				return $result;
			}
		}

		$outside = self::get_outside_webroot_candidate( $webroot );
		if ( ! empty( $outside ) ) {
			$attempts[] = 'outside_webroot';
			$result = self::prepare_directory( $outside, $webroot );
			if ( $result['status'] === 'ready' && 'true' === $result['outside_webroot'] ) {
				$result['source'] = 'outside_webroot';
				return $result;
			}
		}

		$fallback = self::get_uploads_fallback();
		if ( ! empty( $fallback ) ) {
			$attempts[] = 'uploads_fallback';
			$result = self::prepare_directory( $fallback, $webroot );
			if ( $result['status'] === 'ready' ) {
				$result['source'] = 'uploads_fallback';
				$result['warning'] = 'Quarantine berada di bawah uploads; perlindungan web-server wajib diverifikasi.';
				return $result;
			}
		}

		return array(
			'directory'       => '',
			'source'          => 'none',
			'status'          => 'unavailable',
			'outside_webroot' => 'unknown',
			'webroot'         => $webroot,
			'attempts'        => $attempts,
			'error'           => 'Tidak ada direktori quarantine yang aman dan writable.',
		);
	}

	/**
	 * Mendapatkan hanya path direktori yang berhasil di-resolve.
	 *
	 * @return string Path absolut, atau string kosong jika tidak tersedia.
	 */
	public static function get_directory() {
		$result = self::resolve_directory();
		return isset( $result['directory'] ) ? $result['directory'] : '';
	}

	/**
	 * Membuat path item acak tanpa membuat atau memindahkan file.
	 *
	 * @param string $extension Ekstensi aman, tanpa titik.
	 * @return array{path:string, directory:string, item_id:string, filename:string, extension:string, outside_webroot:string, status:string}
	 */
	public static function create_item_path( $extension = 'bin' ) {
		$storage = self::resolve_directory();
		$extension = self::sanitize_extension( $extension );
		$item_id = self::random_identifier();
		$filename = $item_id . ( $extension ? '.' . $extension : '' );
		$path = '';

		if ( 'ready' === $storage['status'] ) {
			$path = $storage['directory'] . DIRECTORY_SEPARATOR . $filename;
		}

		return array(
			'path'            => $path,
			'directory'       => $storage['directory'],
			'item_id'         => $item_id,
			'filename'        => $filename,
			'extension'       => $extension,
			'outside_webroot' => $storage['outside_webroot'],
			'status'          => $storage['status'],
		);
	}

	/**
	 * Membuat metadata path terstruktur untuk audit atau persistence.
	 *
	 * @param string $path Path yang akan dianalisis.
	 * @param string $base Base containment opsional.
	 * @return array<string,mixed>
	 */
	public static function path_metadata( $path, $base = '' ) {
		$path = self::normalize_path( $path );
		$base = self::normalize_path( $base );
		$exists = '' !== $path && ( file_exists( $path ) || is_link( $path ) );
		$canonical = $exists ? realpath( $path ) : self::canonicalize_parent( $path );

		return array(
			'path'              => $path,
			'canonical_path'    => is_string( $canonical ) ? $canonical : '',
			'relative_path'     => $base ? self::relative_path( $canonical, $base ) : '',
			'exists'            => $exists,
			'is_symlink'        => $exists && is_link( $path ),
			'is_safe'           => self::is_absolute_path( $path ) && ! self::contains_symlink_component( $path ),
			'within_base'       => $base ? self::is_path_within( $canonical, $base ) : null,
			'outside_webroot'   => self::outside_webroot_state( $canonical ),
		);
	}

	/**
	 * Memeriksa containment canonical path tanpa memperbolehkan prefix palsu.
	 *
	 * @param string $path Path target.
	 * @param string $base Base directory.
	 * @param bool   $allow_base Apakah base sendiri valid sebagai target.
	 * @return bool
	 */
	public static function is_path_within( $path, $base, $allow_base = true ) {
		$path = self::normalize_path( $path );
		$base = self::normalize_path( $base );
		if ( '' === $path || '' === $base ) {
			return false;
		}

		$path = self::canonicalize_parent( $path );
		$base = realpath( $base );
		if ( false === $path || false === $base || is_link( $base ) ) {
			return false;
		}

		$path = rtrim( str_replace( '\\', '/', $path ), '/' );
		$base = rtrim( str_replace( '\\', '/', $base ), '/' );
		if ( ! $allow_base && $path === $base ) {
			return false;
		}

		return 0 === strpos( $path, $base . '/' ) || ( $allow_base && $path === $base );
	}

	/**
	 * Mendapatkan mode file yang seharusnya digunakan saat item dibuat.
	 *
	 * @return int
	 */
	public static function get_file_mode() {
		return self::FILE_MODE;
	}

	/**
	 * Mendapatkan mode direktori yang seharusnya digunakan saat folder dibuat.
	 *
	 * @return int
	 */
	public static function get_directory_mode() {
		return self::DIRECTORY_MODE;
	}

	/** Menyiapkan directory dan mengembalikan metadata resolusi. */
	private static function prepare_directory( $directory, $webroot ) {
		$directory = self::normalize_path( $directory );
		$outside = self::outside_webroot_state( $directory, $webroot );
		$result = array(
			'directory'       => '',
			'source'          => '',
			'status'          => 'unavailable',
			'outside_webroot' => $outside,
			'webroot'         => $webroot,
			'error'           => '',
		);

		if ( '' === $directory || ! self::is_absolute_path( $directory ) || self::contains_symlink_component( $directory ) ) {
			$result['error'] = 'Path quarantine kosong, bukan path absolut, atau memiliki komponen symlink.';
			return $result;
		}

		if ( ! file_exists( $directory ) ) {
			$created = function_exists( 'wp_mkdir_p' ) ? wp_mkdir_p( $directory ) : @mkdir( $directory, self::DIRECTORY_MODE, true );
			if ( ! $created && ! is_dir( $directory ) ) {
				$result['error'] = 'Direktori quarantine tidak dapat dibuat.';
				return $result;
			}
		}

		if ( ! is_dir( $directory ) || is_link( $directory ) || ! is_writable( $directory ) ) {
			$result['error'] = 'Direktori quarantine tidak valid atau tidak writable.';
			return $result;
		}

		@chmod( $directory, self::DIRECTORY_MODE );
		$result['directory'] = rtrim( realpath( $directory ), '/\\' );
		$result['status'] = $result['directory'] ? 'ready' : 'unavailable';
		return $result;
	}

	/** Mendapatkan webroot canonical yang diketahui. */
	private static function get_webroot() {
		$root = defined( 'ABSPATH' ) ? ABSPATH : '';
		$root = $root ? realpath( $root ) : false;
		return false === $root ? '' : rtrim( $root, '/\\' );
	}

	/** Mendapatkan kandidat direktori di luar ABSPATH. */
	private static function get_outside_webroot_candidate( $webroot ) {
		if ( '' === $webroot ) {
			return '';
		}
		$parent = dirname( $webroot );
		$site_id = substr( hash( 'sha256', $webroot . '|' . ( function_exists( 'home_url' ) ? home_url( '/' ) : '' ) ), 0, 16 );
		return $parent . DIRECTORY_SEPARATOR . self::OUTSIDE_DIRNAME . '-' . $site_id;
	}

	/** Mendapatkan kandidat fallback uploads. */
	private static function get_uploads_fallback() {
		$base = '';
		if ( function_exists( 'wp_upload_dir' ) ) {
			$uploads = wp_upload_dir();
			$base = isset( $uploads['basedir'] ) ? $uploads['basedir'] : '';
		} elseif ( defined( 'WP_CONTENT_DIR' ) ) {
			$base = WP_CONTENT_DIR . '/uploads';
		} elseif ( defined( 'ABSPATH' ) ) {
			$base = ABSPATH . 'wp-content/uploads';
		}
		return $base ? rtrim( $base, '/\\' ) . DIRECTORY_SEPARATOR . self::FALLBACK_DIRNAME : '';
	}

	/** Menentukan status outside-webroot. */
	private static function outside_webroot_state( $path, $webroot = null ) {
		$webroot = null === $webroot ? self::get_webroot() : $webroot;
		$path = self::canonicalize_parent( $path );
		if ( '' === $path || '' === $webroot ) {
			return 'unknown';
		}
		if ( self::is_path_within( $path, $webroot ) ) {
			return 'false';
		}
		return 'true';
	}

	/** Menolak symlink pada path dan seluruh parent existing-nya. */
	private static function contains_symlink_component( $path ) {
		$path = self::normalize_path( $path );
		$probe = $path;
		while ( $probe && ! file_exists( $probe ) && ! is_link( $probe ) ) {
			$parent = dirname( $probe );
			if ( $parent === $probe ) {
				break;
			}
			$probe = $parent;
		}

		while ( $probe && $probe !== dirname( $probe ) ) {
			if ( is_link( $probe ) ) {
				return true;
			}
			$probe = dirname( $probe );
		}
		return is_link( $probe );
	}

	/** Menghasilkan canonical path untuk target yang mungkin belum ada. */
	private static function canonicalize_parent( $path ) {
		$path = self::normalize_path( $path );
		if ( '' === $path ) {
			return '';
		}
		$existing = $path;
		$tail = array();
		while ( ! file_exists( $existing ) && ! is_link( $existing ) ) {
			$parent = dirname( $existing );
			if ( $parent === $existing ) {
				return false;
			}
			$tail[] = basename( $existing );
			$existing = $parent;
		}
		if ( is_link( $existing ) || false === realpath( $existing ) ) {
			return false;
		}
		$canonical = rtrim( realpath( $existing ), '/\\' );
		foreach ( array_reverse( $tail ) as $part ) {
			$canonical .= DIRECTORY_SEPARATOR . $part;
		}
		return $canonical;
	}

	/** Menghasilkan relative path dengan validasi containment. */
	private static function relative_path( $path, $base ) {
		if ( ! self::is_path_within( $path, $base ) ) {
			return '';
		}
		$path = str_replace( '\\', '/', self::canonicalize_parent( $path ) );
		$base = rtrim( str_replace( '\\', '/', realpath( $base ) ), '/' );
		return ltrim( substr( $path, strlen( $base ) ), '/' );
	}

	/** Normalisasi slash tanpa menghapus path root. */
	private static function normalize_path( $path ) {
		if ( ! is_string( $path ) || '' === trim( $path ) ) {
			return '';
		}
		$path = str_replace( array( '/', '\\' ), DIRECTORY_SEPARATOR, trim( $path ) );
		return rtrim( $path, DIRECTORY_SEPARATOR );
	}

	/** Membatasi ekstensi item agar tidak dapat memengaruhi path. */
	private static function sanitize_extension( $extension ) {
		$extension = strtolower( ltrim( (string) $extension, '.' ) );
		return preg_match( '/^[a-z0-9]{1,12}$/', $extension ) ? $extension : 'bin';
	}

	/** Menentukan apakah path absolut pada Unix atau Windows. */
	private static function is_absolute_path( $path ) {
		return is_string( $path ) && ( '' !== $path && ( '/' === $path[0] || preg_match( '/^[A-Za-z]:[\\\\\/]/', $path ) ) );
	}

	/** Menghasilkan identifier item yang tidak dapat ditebak secara praktis. */
	private static function random_identifier() {
		if ( function_exists( 'wp_generate_uuid4' ) ) {
			return strtolower( str_replace( '-', '', wp_generate_uuid4() ) );
		}
		try {
			return bin2hex( random_bytes( 16 ) );
		} catch ( \Throwable $exception ) {
			return hash( 'sha256', uniqid( '', true ) . microtime( true ) );
		}
	}
}
