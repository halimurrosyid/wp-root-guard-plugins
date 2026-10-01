<?php
/**
 * Penulisan file yang aman dengan temporary file dan atomic rename.
 *
 * @package WPRootGuard
 * @since 3.3.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class AtomicWriter
 */
final class AtomicWriter {

	/**
	 * Menulis konten ke file pada filesystem yang sama, lalu melakukan rename atomik.
	 *
	 * @param string   $path Target absolut.
	 * @param string   $content Konten.
	 * @param int|null $mode Mode file opsional.
	 * @param string   $expected_hash SHA-256 expected hash, optional.
	 * @return true|\WP_Error
	 */
	public static function write( $path, $content, $mode = null, $expected_hash = '' ) {
		$path = self::normalize_path( $path );
		if ( '' === $path || ! self::is_absolute( $path ) ) {
			return new \WP_Error( 'atomic_invalid_path', __( 'Path atomic writer tidak valid.', 'wp-root-guard' ) );
		}

		$directory = dirname( $path );
		$real_directory = realpath( $directory );
		if ( false === $real_directory || is_link( $directory ) || ! is_dir( $real_directory ) || ! is_writable( $real_directory ) ) {
			return new \WP_Error( 'atomic_directory_unwritable', __( 'Direktori target tidak writable.', 'wp-root-guard' ) );
		}
		if ( file_exists( $path ) && is_link( $path ) ) {
			return new \WP_Error( 'atomic_symlink_target', __( 'Target atomic writer tidak boleh berupa symlink.', 'wp-root-guard' ) );
		}
		$path = $real_directory . DIRECTORY_SEPARATOR . basename( $path );

		$temp = @tempnam( $directory, '.wp-root-guard-' );
		if ( false === $temp ) {
			return new \WP_Error( 'atomic_temp_failed', __( 'Temporary file tidak dapat dibuat.', 'wp-root-guard' ) );
		}

		@chmod( $temp, 0600 );
		$handle = @fopen( $temp, 'wb' );
		if ( false === $handle ) {
			@unlink( $temp );
			return new \WP_Error( 'atomic_open_failed', __( 'Temporary file tidak dapat dibuka.', 'wp-root-guard' ) );
		}
		$content = (string) $content;
		$written = @fwrite( $handle, $content );
		$flushed = false !== $written && (int) $written === strlen( $content ) && @fflush( $handle );
		if ( $flushed && function_exists( 'fsync' ) ) {
			$flushed = @fsync( $handle );
		}
		@fclose( $handle );
		if ( ! $flushed ) {
			@unlink( $temp );
			return new \WP_Error( 'atomic_write_failed', __( 'Konten temporary file tidak lengkap.', 'wp-root-guard' ) );
		}

		if ( null !== $mode ) {
			@chmod( $temp, (int) $mode );
		}

		if ( ! @rename( $temp, $path ) ) {
			@unlink( $temp );
			return new \WP_Error( 'atomic_rename_failed', __( 'Atomic rename gagal.', 'wp-root-guard' ) );
		}

		if ( null !== $mode ) {
			@chmod( $path, (int) $mode );
		}
		if ( '' !== $expected_hash && ! hash_equals( strtolower( $expected_hash ), strtolower( (string) @hash_file( 'sha256', $path ) ) ) ) {
			return new \WP_Error( 'atomic_verification_failed', __( 'Verifikasi hash file setelah atomic rename gagal.', 'wp-root-guard' ) );
		}

		return true;
	}

	/** @param string $path Path. @return string */
	private static function normalize_path( $path ) {
		return rtrim( str_replace( '\\', '/', (string) $path ), '/' );
	}

	/** @param string $path Path. @return bool */
	private static function is_absolute( $path ) {
		return (bool) preg_match( '#^(?:[A-Za-z]:/|/)#', $path );
	}
}
