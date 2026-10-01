<?php
/**
 * Transactional quarantine movement and audit metadata.
 *
 * @package WPRootGuard
 * @since 3.3.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class QuarantineManager {

	/** Whether an automatic containment destination is safe and writable. */
	public static function is_available_for_automatic_containment() {
		$storage = QuarantineStorage::resolve_directory();
		return 'ready' === ( $storage['status'] ?? '' ) && self::is_storage_permitted( $storage );
	}

	/**
	 * Move a validated filesystem item into the selected vault.
	 *
	 * A cross-device move is copied to an unpublished temporary location,
	 * verified for regular files, then atomically renamed into the vault.
	 * Symlinks are rejected and the original is removed only after success.
	 *
	 * @param string $original_path Canonical existing source path.
	 * @param string $original_name Relative display name.
	 * @param string $type file or folder.
	 * @return array|WP_Error
	 */
	public static function quarantine( $original_path, $original_name, $type = 'file' ) {
		$storage = QuarantineStorage::resolve_directory();
		if ( 'ready' !== $storage['status'] || ! self::is_storage_permitted( $storage ) ) {
			return new \WP_Error( 'quarantine_storage_unverified', __( 'Vault karantina tidak aman atau belum diverifikasi.', 'wp-root-guard' ) );
		}

		$original_path = realpath( $original_path );
		if ( false === $original_path || is_link( $original_path ) || ( 'folder' === $type && ! is_dir( $original_path ) ) || ( 'folder' !== $type && ! is_file( $original_path ) ) ) {
			return new \WP_Error( 'quarantine_invalid_source', __( 'Target karantina tidak valid.', 'wp-root-guard' ) );
		}

		$item = QuarantineStorage::create_item_path( 'folder' === $type ? '' : pathinfo( $original_path, PATHINFO_EXTENSION ) );
		if ( empty( $item['path'] ) || ! QuarantineStorage::is_path_within( $item['path'], $storage['directory'], false ) ) {
			return new \WP_Error( 'quarantine_path_invalid', __( 'Path tujuan karantina tidak valid.', 'wp-root-guard' ) );
		}

		$sha256 = 'folder' === $type ? '' : (string) @hash_file( 'sha256', $original_path );
		$size = 'folder' === $type ? 0 : (int) @filesize( $original_path );
		$moved = @rename( $original_path, $item['path'] );
		if ( ! $moved ) {
			$moved = self::copy_then_commit( $original_path, $item['path'], $type, $sha256 );
			if ( $moved ) {
				$moved = self::remove_source( $original_path, $type );
			}
		}
		if ( ! $moved ) {
			return new \WP_Error( 'quarantine_move_failed', __( 'Target tidak dapat dipindahkan secara aman ke vault.', 'wp-root-guard' ) );
		}

		@chmod( $item['path'], 'folder' === $type ? QuarantineStorage::get_directory_mode() : QuarantineStorage::get_file_mode() );
		$record = array(
			'id'                => $item['item_id'],
			'type'              => 'folder' === $type ? 'folder' : 'file',
			'original_name'     => $original_name,
			'original_path'     => $original_path,
			'quarantine_name'   => $item['filename'],
			'quarantine_path'   => $item['path'],
			'storage_directory' => $storage['directory'],
			'sha256'            => $sha256,
			'size'              => max( 0, $size ),
			'mode'              => substr( sprintf( '%o', (int) @fileperms( $item['path'] ) ), -4 ),
			'status'            => 'quarantined',
			'created_at_gmt'    => gmdate( 'Y-m-d H:i:s' ),
		);
		if ( ! ScanStore::save_quarantine_item( $record ) ) {
			// The file remains contained; report degraded audit rather than trying
			// an unsafe rollback into a possibly compromised path.
			$record['audit_error'] = 'metadata_not_persisted';
		}
		return $record;
	}

	/** Uploads fallback is permitted only after an execution-denial proof. */
	private static function is_storage_permitted( $storage ) {
		if ( 'uploads_fallback' !== ( $storage['source'] ?? '' ) ) {
			return true;
		}
		$guard = ServerGuard::get_status();
		return ServerGuard::STATUS_VERIFIED === ( $guard['status'] ?? '' );
	}

	private static function copy_then_commit( $source, $destination, $type, $expected_hash ) {
		$tmp = $destination . '.tmp-' . wp_generate_password( 12, false, false );
		if ( 'folder' === $type ) {
			$ok = self::copy_directory( $source, $tmp );
		} else {
			$ok = self::copy_file( $source, $tmp ) && hash_equals( (string) $expected_hash, (string) @hash_file( 'sha256', $tmp ) );
		}
		if ( ! $ok || ! @rename( $tmp, $destination ) ) {
			self::remove_source( $tmp, $type );
			return false;
		}
		return true;
	}

	private static function copy_file( $source, $destination ) {
		$in = @fopen( $source, 'rb' );
		$out = @fopen( $destination, 'xb' );
		if ( ! $in || ! $out ) {
			if ( is_resource( $in ) ) { fclose( $in ); }
			if ( is_resource( $out ) ) { fclose( $out ); }
			return false;
		}
		$ok = false !== stream_copy_to_stream( $in, $out );
		fclose( $in );
		fclose( $out );
		@chmod( $destination, QuarantineStorage::get_file_mode() );
		return $ok;
	}

	private static function copy_directory( $source, $destination ) {
		if ( ! @mkdir( $destination, QuarantineStorage::get_directory_mode(), true ) ) {
			return false;
		}
		try {
			$iterator = new \RecursiveIteratorIterator( new \RecursiveDirectoryIterator( $source, \FilesystemIterator::SKIP_DOTS ), \RecursiveIteratorIterator::SELF_FIRST );
			foreach ( $iterator as $entry ) {
				if ( $entry->isLink() ) { return false; }
				$relative = substr( $entry->getPathname(), strlen( rtrim( $source, '/\\' ) ) + 1 );
				$target = $destination . DIRECTORY_SEPARATOR . $relative;
				if ( $entry->isDir() ) {
					if ( ! is_dir( $target ) && ! @mkdir( $target, QuarantineStorage::get_directory_mode(), true ) ) { return false; }
				} elseif ( ! self::copy_file( $entry->getPathname(), $target ) ) {
					return false;
				}
			}
			return true;
		} catch ( \Throwable $exception ) {
			return false;
		}
	}

	private static function remove_source( $path, $type ) {
		if ( 'folder' !== $type ) { return @unlink( $path ); }
		if ( is_link( $path ) ) { return false; }
		$items = @scandir( $path );
		if ( false === $items ) { return false; }
		foreach ( $items as $item ) {
			if ( '.' === $item || '..' === $item ) { continue; }
			$child = $path . DIRECTORY_SEPARATOR . $item;
			if ( is_link( $child ) || ( is_dir( $child ) ? ! self::remove_source( $child, 'folder' ) : ! @unlink( $child ) ) ) { return false; }
		}
		return @rmdir( $path );
	}
}
