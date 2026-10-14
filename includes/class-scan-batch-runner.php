<?php
/**
 * Bounded, resumable scanner orchestration.
 *
 * @package WPRootGuard
 * @since 3.3.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) { exit; }

class ScanBatchRunner {
	const MAX_ITEMS = 250;
	const MAX_SECONDS = 5;
	const RUN_OPTION = 'wp_root_guard_batch_run';
	const SCOPES = array( 'root_folders', 'root_files', 'core_checksums', 'core_injected_files', 'uploads_php', 'themes_plugins', 'database_integrity', 'remediate', 'finalize' );
	private static $checksums = null;

	/** Start or continue exactly one bounded batch. */
	public static function run( $context = 'unknown' ) {
		if ( ! ScanStore::ensure_schema() ) { return self::failed( 'storage_unavailable' ); }
		$lock = new ScanLock( 120 );
		$lock_state = $lock->acquire( $context );
		if ( false === $lock_state ) { return self::deferred(); }
		$run = array();
		try {
			$run = self::get_or_create_run( $context );
			if ( ! empty( $run['next_retry_at'] ) && (int) $run['next_retry_at'] > time() ) {
				$result = self::deferred( 'retry_wait', $run );
			} else {
				$result = self::process_batch( $run, $lock, $lock_state );
			}
		} catch ( \Throwable $exception ) {
			$result = empty( $run ) ? self::failed( 'batch_bootstrap_failed' ) : self::handle_failure( $run, sanitize_key( $exception->getMessage() ) ?: 'batch_exception' );
		} finally {
			$lock->release( $lock_state['run_id'], $lock_state['fencing_token'] );
		}
		if ( 'completed' !== $result['execution_state'] && 'failed' !== $result['execution_state'] && class_exists( __NAMESPACE__ . '\\Cron' ) ) { Cron::schedule_scan_continuation( ! empty( $result['retry_at'] ) ? max( 15, (int) $result['retry_at'] - time() ) : 15 ); }
		return $result;
	}

	private static function get_or_create_run( $context ) {
		$state = self::get_active_run();
		if ( ! empty( $state ) ) { return $state; }
		$recovered = ScanStore::load_active_run();
		if ( ! empty( $recovered ) ) {
			update_option( self::RUN_OPTION, $recovered, false );
			return $recovered;
		}
		$run = array( 'run_id' => wp_generate_uuid4(), 'fencing_token' => wp_generate_password( 64, false, false ), 'context' => sanitize_key( $context ), 'status' => 'running', 'scope' => self::SCOPES[0], 'scope_index' => 0, 'cursor' => array( 'seeded' => false, 'offset' => 0 ), 'processed' => 0, 'total' => 0, 'batch_number' => 0, 'created_at' => time(), 'updated_at' => time(), 'errors' => array(), 'findings_summary' => array(), 'retry_count' => 0, 'next_retry_at' => 0, 'error_code' => '', 'error_message' => '' );
		self::require_write( ScanStore::save_run( $run ), 'run_create_failed' );
		update_option( self::RUN_OPTION, $run, false );
		self::mark_dashboard_pending( $run );
		return $run;
	}

	private static function process_batch( $run, $lock, $lock_state ) {
		$started = microtime( true ); $scope = $run['scope'];
		self::require_write( ScanStore::reclaim_stale_claims( $run['run_id'], 120 ), 'claim_recovery_failed' );
		if ( Scanner::is_core_update_in_progress() ) { return self::checkpoint( $run, 'maintenance_mode' ); }
		if ( 'finalize' === $scope ) { return self::finalize( $run ); }
		if ( ! self::seed_scope( $run, $started ) ) { return self::persist_running( $run ); }
		$token = wp_generate_password( 32, false, false );
		$items = ScanStore::claim_items( $run['run_id'], $scope, $token, self::MAX_ITEMS );
		self::require_write( false !== $items, 'claim_items_failed' );
		$recent_items = array();
		foreach ( $items as $item ) {
			if ( microtime( true ) - $started >= self::MAX_SECONDS ) { self::require_write( ScanStore::release_claims( $run['run_id'], $scope, $token ), 'claim_release_failed' ); break; }
			self::process_item( $run, $scope, $item, $token, $started );
			$run['processed']++;

			$item_path = (string) $item['path'];
			if ( 'database_integrity' === $scope || in_array( $item['item_type'], array( 'db_table', 'db_post', 'db_option', 'db_check' ), true ) ) {
				$folder = 'Database WordPress';
				$file   = str_replace( array( 'db_table:', 'table:', 'db_check:', 'post:', 'option:' ), '', $item_path );
				if ( 0 === strpos( $item_path, 'db_check:' ) ) {
					$file = 'Pemeriksaan Integritas (' . $file . ')';
				}
			} elseif ( 'folder' === $item['item_type'] || 'directory' === $item['item_type'] ) {
				$folder = 'Root';
				$file   = $item_path . '/';
			} else {
				$folder = dirname( $item_path );
				$folder = ( '.' === $folder || empty( $folder ) ) ? 'Root' : $folder . '/';
				$file   = basename( $item_path );
			}
			$run['current_folder'] = $folder;
			$run['current_file']   = $file;
			if ( count( $recent_items ) < 8 ) {
				$recent_items[] = array(
					'scope'  => $scope,
					'folder' => $folder,
					'file'   => $file,
					'type'   => $item['item_type'],
				);
			}
		}
		$run['recent_items'] = $recent_items;
		// The batch lease is refreshed with the token acquired by this request;
		// never read a potentially replaced lock record back from the database.
		self::require_write( false !== $lock->refresh( $lock_state['run_id'], $lock_state['fencing_token'] ), 'scan_lock_lost' );
		$pending = ScanStore::count_items( $run['run_id'], $scope, array( 'queued', 'claimed' ) );
		self::require_write( false !== $pending, 'item_count_failed' );
		if ( 0 === $pending && ! empty( $run['cursor']['seeded'] ) ) { self::advance_scope( $run ); }
		return self::persist_running( $run );
	}

	private static function seed_scope( &$run, $started ) {
		$scope = $run['scope']; $cursor = is_array( $run['cursor'] ) ? $run['cursor'] : array();
		if ( ! empty( $cursor['seeded'] ) ) { return true; }
		if ( 'root_folders' === $scope ) {
			foreach ( Baseline::scan_root_folders() as $name ) { self::enqueue_item( $run, $scope, $name, 'folder' ); }
			$cursor['seeded'] = true;
		} elseif ( 'root_files' === $scope ) {
			foreach ( Baseline::scan_root_files() as $name => $hash ) { self::enqueue_item( $run, $scope, $name, 'file', $hash, self::stat_meta( ABSPATH . $name ) ); }
			$cursor['seeded'] = true;
		} elseif ( 'core_checksums' === $scope ) {
			$checksums = Scanner::get_core_checksums();
			if ( ! is_array( $checksums ) || empty( $checksums ) ) { $run['errors'][] = 'core_checksums_unavailable'; $cursor['seeded'] = true; }
			else {
				ksort( $checksums ); $offset = absint( $cursor['offset'] ?? 0 ); $chunk = array_slice( $checksums, $offset, self::MAX_ITEMS, true );
				foreach ( $chunk as $path => $hash ) { if ( 0 !== strpos( $path, 'wp-content/' ) ) { self::enqueue_item( $run, $scope, $path, 'core', $hash, self::stat_meta( ABSPATH . $path ) ); } }
				$cursor['offset'] = $offset + count( $chunk ); $cursor['seeded'] = $cursor['offset'] >= count( $checksums );
			}
		} elseif ( 'core_injected_files' === $scope ) {
			$checksums = self::checksums();
			if ( empty( $checksums ) ) {
				// FAIL-SAFE: Jangan menyemai intruder scan jika daftar checksum core tidak tersedia
				$run['errors'][] = 'core_checksums_unavailable';
				$cursor['seeded'] = true;
			} else {
				self::enqueue_item( $run, $scope, 'wp-includes', 'directory', '', array( 'offset' => 0 ) );
				self::enqueue_item( $run, $scope, 'wp-admin', 'directory', '', array( 'offset' => 0 ) );
				$cursor['seeded'] = true;
			}
		} elseif ( 'uploads_php' === $scope ) {
			self::enqueue_item( $run, $scope, 'wp-content/uploads', 'directory', '', array( 'offset' => 0 ) );
			$cursor['seeded'] = true;
		} elseif ( 'themes_plugins' === $scope ) {
			self::enqueue_item( $run, $scope, 'wp-content/themes', 'directory', '', array( 'offset' => 0 ) );
			self::enqueue_item( $run, $scope, 'wp-content/plugins', 'directory', '', array( 'offset' => 0 ) );
			$cursor['seeded'] = true;
		} elseif ( 'database_integrity' === $scope ) {
			self::seed_database_scope( $run );
			$cursor['seeded'] = true;
		} elseif ( 'remediate' === $scope ) {
			self::seed_remediation( $run ); $cursor['seeded'] = true;
		}
		$run['cursor'] = $cursor; return ! empty( $cursor['seeded'] );
	}

	private static function process_item( &$run, $scope, $item, $token, $started ) {
		$path = (string) $item['path']; $absolute = ABSPATH . ltrim( $path, '/\\'); $metadata = json_decode( $item['metadata'], true ); $metadata = is_array( $metadata ) ? $metadata : array();
		if ( 'database_integrity' === $scope || in_array( $item['item_type'], array( 'db_table', 'db_post', 'db_option', 'db_check' ), true ) ) {
			$finding = self::analyze_database_item( $item );
			self::finish_item( $item, $token, $finding ? 'finding' : 'done', $finding ? $finding : array() );
			return;
		}
		if ( 'directory' === $item['item_type'] ) { return self::discover_directory( $run, $scope, $item, $token, $absolute, $metadata, $started ); }
		if ( 'remediate' === $scope ) { return self::remediate_item( $item, $token, $metadata ); }
		if ( 'folder' === $item['item_type'] ) { $finding = self::analyze( $scope, $path, $absolute, $item ); self::finish_item( $item, $token, $finding ? 'finding' : 'done', $finding ? $finding : array() ); return; }
		if ( 'core_checksums' !== $scope && ! self::unchanged( $absolute, $item ) ) { $run['errors'][] = $scope . '_changed_after_discovery'; self::finish_item( $item, $token, 'skipped', array( 'reason' => 'changed_after_discovery' ) ); return; }
		if ( ! self::hashable( $absolute ) ) { $run['errors'][] = $scope . '_file_unverifiable'; self::finish_item( $item, $token, 'skipped', array( 'reason' => 'file_unverifiable_or_too_large' ) ); return; }
		$finding = self::analyze( $scope, $path, $absolute, $item );
		self::finish_item( $item, $token, $finding ? 'finding' : 'done', $finding ? $finding : array() );
	}

	private static function discover_directory( &$run, $scope, $item, $token, $absolute, $metadata = array(), $started = 0 ) {
		if ( ! is_dir( $absolute ) || is_link( $absolute ) || ! is_readable( $absolute ) ) { self::finish_item( $item, $token, 'failed', array( 'reason' => 'directory_unreadable' ) ); $run['errors'][] = $scope . '_directory_unreadable'; return; }
		$mtime = (int) @filemtime( $absolute );
		if ( isset( $metadata['dir_mtime'] ) && (int) $metadata['dir_mtime'] !== $mtime ) {
			$metadata['rescan_attempts'] = absint( $metadata['rescan_attempts'] ?? 0 ) + 1;
			if ( $metadata['rescan_attempts'] > 3 ) { self::finish_item( $item, $token, 'failed', array( 'reason' => 'directory_changed_repeatedly' ) ); $run['errors'][] = $scope . '_directory_changed_repeatedly'; return; }
			$metadata['offset'] = 0;
		}
		$metadata['dir_mtime'] = $mtime;
		try { $entries = new \DirectoryIterator( $absolute ); } catch ( \UnexpectedValueException $exception ) { self::finish_item( $item, $token, 'failed', array( 'reason' => 'directory_iterator_failed' ) ); $run['errors'][] = $scope . '_iterator_failed'; return; }
		$offset = absint( $metadata['offset'] ?? 0 ); $index = 0; $added = 0; $started = $started ?: microtime( true );
		foreach ( $entries as $entry ) {
			if ( $entry->isDot() ) { continue; }
			if ( $index++ < $offset ) { if ( microtime( true ) - $started >= self::MAX_SECONDS ) { self::requeue_item( $item, $token, $metadata ); return; } continue; }
			if ( microtime( true ) - $started >= self::MAX_SECONDS || $added >= self::MAX_ITEMS ) { $metadata['offset'] = $index - 1; self::requeue_item( $item, $token, $metadata ); return; }
			$child = rtrim( $item['path'], '/\\') . '/' . $entry->getFilename();
			if ( $entry->isLink() || self::skip_internal_path( $scope, $child ) ) { if ( $entry->isLink() ) { $run['errors'][] = $scope . '_symlink_skipped'; } continue; }
			self::enqueue_item( $run, $scope, $child, $entry->isDir() ? 'directory' : 'file', '', self::stat_meta( $entry->getPathname() ) ); $added++;
		}
		self::finish_item( $item, $token, 'done' );
	}

	private static function analyze( $scope, $path, $absolute, $item ) {
		$settings  = Settings::get_settings();
		$whitelist = Settings::get_user_whitelist();
		$path_norm = str_replace( '\\', '/', ltrim( (string) $path, '/\\' ) );
		$basename  = basename( $path_norm );

		// 1. Whitelist & Critical File Protection (Req 2 & 3: Never alert or quarantine exempt/whitelisted files)
		$is_whitelisted = in_array( $path_norm, $whitelist, true ) || in_array( $basename, $whitelist, true ) || ( class_exists( __NAMESPACE__ . '\\Settings' ) && Settings::is_path_whitelisted( $path_norm ) );
		$is_exempt      = Settings::is_critical_exempt( $path_norm ) || Settings::is_critical_exempt( $basename );
		if ( $is_whitelisted || $is_exempt ) {
			return false;
		}

		// 2. ROOT FOLDERS
		if ( 'root_folders' === $scope ) {
			$known = array_merge( Settings::get_default_whitelist(), Baseline::get_baseline_folders(), $whitelist );
			return in_array( $path_norm, $known, true ) ? false : self::finding( 'folder', $path_norm, $absolute, 'Unknown Folder', '-' );
		}

		// 3. ROOT FILES (Req 1: Accommodate latest WP versions & official core files)
		if ( 'root_files' === $scope ) {
			$checksums = self::checksums();

			// If file exists in official WP checksums (current version), verify against official hash
			if ( isset( $checksums[ $path_norm ] ) ) {
				if ( self::verify_file_hash( $absolute, $checksums[ $path_norm ] ) ) {
					return false; // Valid official WordPress core file from current version!
				}
				return self::finding( 'core_file', $path_norm, $absolute, 'Modified Core File', Scanner::scan_file_for_webshell( $absolute ) );
			}

			// If not in core checksums, check default file whitelist
			if ( in_array( $path_norm, Settings::get_default_file_whitelist(), true ) || in_array( $basename, Settings::get_default_file_whitelist(), true ) ) {
				return false;
			}

			// Check against Baseline
			$baseline = Baseline::get_baseline_files();
			if ( isset( $baseline[ $path_norm ] ) ) {
				if ( self::verify_file_hash( $absolute, $baseline[ $path_norm ] ) ) {
					return false;
				}
				return self::finding( 'file', $path_norm, $absolute, 'Modified File', Scanner::scan_file_for_webshell( $absolute ) );
			}

			return self::finding( 'file', $path_norm, $absolute, 'Unknown File', Scanner::scan_file_for_webshell( $absolute ) );
		}

		// 4. CORE CHECKSUMS (wp-admin, wp-includes, and root core files)
		if ( 'core_checksums' === $scope ) {
			if ( ! file_exists( $absolute ) ) {
				return self::finding( 'core_file', $path_norm, $absolute, 'Missing Core File', '-' );
			}
			return ! self::verify_file_hash( $absolute, $item['expected_hash'] ) ? self::finding( 'core_file', $path_norm, $absolute, 'Modified Core File', Scanner::scan_file_for_webshell( $absolute ) ) : false;
		}

		// 5. CORE INJECTED FILES (Intruder files in wp-admin / wp-includes)
		if ( 'core_injected_files' === $scope ) {
			$checksums = self::checksums();
			if ( empty( $checksums ) ) {
				return false; // FAIL-SAFE MUTLAK: Jangan pernah menuduh file core sebagai penyusup jika daftar resmi tidak tersedia!
			}
			return ! isset( $checksums[ $path_norm ] ) ? self::finding( 'core_file', $path_norm, $absolute, 'Suspicious Core Injection', Scanner::scan_file_for_webshell( $absolute ) ) : false;
		}

		// 6. UPLOADS PHP (PHP files in wp-content/uploads)
		if ( 'uploads_php' === $scope ) {
			$ext = strtolower( pathinfo( $path_norm, PATHINFO_EXTENSION ) );
			if ( ! in_array( $ext, array( 'php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'phar', 'inc' ), true ) ) {
				return false;
			}
			// Lewati jika berkas atau foldernya masuk whitelist
			if ( class_exists( __NAMESPACE__ . '\\Settings' ) && Settings::is_path_whitelisted( $path_norm ) ) {
				return false;
			}
			// Lewati jika berkas adalah berkas proteksi legal (index.php kosong / "Silence is golden")
			if ( class_exists( __NAMESPACE__ . '\\Scanner' ) && Scanner::is_innocent_uploads_file( $absolute ) ) {
				return false;
			}
			return self::finding( 'uploads_php', $path_norm, $absolute, 'PHP File in Uploads', Scanner::scan_file_for_webshell( $absolute ) );
		}

		// 7. THEMES & PLUGINS DEEP SCAN (Stealth files, disguised images, webshells, and slot injections)
		if ( 'themes_plugins' === $scope ) {
			// Lewati jika berkas atau foldernya masuk whitelist
			if ( class_exists( __NAMESPACE__ . '\\Settings' ) && Settings::is_path_whitelisted( $path_norm ) ) {
				return false;
			}

			$indicator = Scanner::scan_theme_plugin_file( $absolute );
			if ( false !== $indicator ) {
				return self::finding( 'themes_plugins', $path_norm, $absolute, 'Ancaman Tema / Plugin', $indicator );
			}
			return false;
		}

		return false;
	}

	/**
	 * Verify file MD5 hash with CRLF normalization fallback to prevent Windows/OS line-ending false positives.
	 *
	 * @param string $absolute Absolute path to file.
	 * @param string $expected_hash Expected MD5 hash.
	 * @return bool True if hash matches.
	 */
	public static function verify_file_hash( $absolute, $expected_hash ) {
		if ( ! file_exists( $absolute ) || is_dir( $absolute ) ) {
			return false;
		}
		$actual = @md5_file( $absolute );
		if ( false !== $actual && hash_equals( strtolower( (string) $expected_hash ), strtolower( (string) $actual ) ) ) {
			return true;
		}
		// CRLF normalization fallback for files up to 5 MB
		$size = (int) @filesize( $absolute );
		if ( $size > 0 && $size <= 5242880 ) {
			$content = @file_get_contents( $absolute );
			if ( false !== $content && false !== strpos( $content, "\r" ) ) {
				$normalized = md5( str_replace( "\r\n", "\n", $content ) );
				if ( hash_equals( strtolower( (string) $expected_hash ), strtolower( (string) $normalized ) ) ) {
					return true;
				}
			}
		}
		return false;
	}

	private static function finding( $type, $path, $absolute, $status, $indicator ) { return array( 'type' => $type, 'name' => $path, 'path' => $absolute, 'status' => $status, 'malware_indicator' => $indicator ?: '-', 'created_time' => Scanner::get_wib_time( @filectime( $absolute ) ?: time() ), 'detection_time' => Scanner::get_wib_time() ); }
	private static function unchanged( $path, $item ) { return file_exists( $path ) && ! is_link( $path ) && ( ! empty( $item['mtime'] ) ? (int) @filemtime( $path ) === (int) $item['mtime'] : true ) && ( ! empty( $item['size'] ) ? (int) @filesize( $path ) === (int) $item['size'] : true ); }
	private static function stat_meta( $path ) { return array( 'size' => max( 0, (int) @filesize( $path ) ), 'mtime' => max( 0, (int) @filemtime( $path ) ) ); }
	private static function checksums() { if ( null === self::$checksums ) { self::$checksums = Scanner::get_core_checksums(); } return is_array( self::$checksums ) ? self::$checksums : array(); }
	private static function skip_internal_path( $scope, $path ) {
		$path = str_replace( '\\', '/', $path );
		if ( 'uploads_php' === $scope ) {
			return 0 === strpos( $path, 'wp-content/uploads/wp-root-guard/' ) || 0 === strpos( $path, 'wp-content/uploads/wp-root-guard-quarantine/' );
		}
		if ( 'themes_plugins' === $scope ) {
			if ( 0 === strpos( $path, 'wp-content/plugins/wp-root-guard/' ) || 'wp-content/plugins/wp-root-guard' === $path ) {
				return true;
			}
			$basename = basename( $path );
			if ( in_array( $basename, array( '.git', '.svn', '.hg', 'node_modules', '.idea', '.vscode' ), true ) ) {
				return true;
			}
		}
		return false;
	}

	private static function seed_remediation( $run ) { foreach ( self::findings( $run['run_id'] ) as $finding ) { self::enqueue_item( $run, 'remediate', $finding['name'], 'remediate', '', array( 'finding' => $finding ) ); } }
	private static function remediate_item( $item, $token, $metadata ) {
		$finding = $metadata['finding'] ?? array();
		$result = false;
		$settings = Settings::get_settings();

		// Lindungi database dan tema/plugin dari auto-quarantine/auto-delete yang merusak situs
		if ( in_array( $finding['type'] ?? '', array( 'database_threat', 'db_table', 'db_post', 'db_option', 'themes_plugins' ), true ) ) {
			self::finish_item( $item, $token, 'skipped', array( 'remediated' => false, 'reason' => 'manual_review_required' ) );
			return;
		}

		if ( ! empty( $settings['enable_auto_quarantine'] ) || ( 'uploads_php' === ( $finding['type'] ?? '' ) && ! empty( $settings['enable_uploads_auto_quarantine'] ) ) ) {
			// Cegah false positive: Jangan pernah mengarantina otomatis berkas di uploads kecuali jika terbukti memiliki indikator malware/webshell
			if ( 'uploads_php' === ( $finding['type'] ?? '' ) && ( empty( $finding['malware_indicator'] ) || '-' === $finding['malware_indicator'] ) ) {
				self::finish_item( $item, $token, 'skipped', array( 'remediated' => false, 'reason' => 'manual_review_required' ) );
				return;
			}
			$name = $finding['name'] ?? '';
			$result = 'folder' === ( $finding['type'] ?? '' ) ? Scanner::quarantine_folder( $name ) : ( false !== strpos( $name, '/' ) ? Scanner::quarantine_core_file( $name ) : Scanner::quarantine_file( $name ) );
		}
		self::finish_item( $item, $token, false !== $result ? 'done' : 'skipped', array( 'remediated' => false !== $result ) );
	}

	private static function advance_scope( &$run ) { $index = array_search( $run['scope'], self::SCOPES, true ); $run['scope_index'] = false === $index ? count( self::SCOPES ) - 1 : $index + 1; $run['scope'] = self::SCOPES[ $run['scope_index'] ] ?? 'finalize'; $run['cursor'] = array( 'seeded' => false, 'offset' => 0 ); }
	private static function persist_running( $run ) { $run['status'] = 'running'; $run['next_retry_at'] = 0; $run['batch_number']++; $run['updated_at'] = time(); $run['total'] = self::total_items( $run['run_id'] ); $run['findings_summary'] = array( 'threat_count' => count( self::findings( $run['run_id'] ) ) ); self::require_write( ScanStore::save_run( $run ), 'checkpoint_write_failed' ); update_option( self::RUN_OPTION, $run, false ); self::mark_dashboard_pending( $run ); return self::result( $run, ScanResult::EXECUTION_RUNNING ); }
	private static function finalize( $run ) {
		$incomplete = ScanStore::count_run_items( $run['run_id'], array( 'failed', 'skipped', 'queued', 'claimed' ) );
		self::require_write( false !== $incomplete, 'final_coverage_query_failed' );
		if ( $incomplete > 0 ) { $run['errors'][] = 'incomplete_or_unverifiable_items'; }
		$findings = self::findings( $run['run_id'] );
		$errors = array_values( array_unique( $run['errors'] ?? array() ) );
		$coverage = empty( $errors ) ? ScanResult::COVERAGE_COMPLETE : ScanResult::COVERAGE_DEGRADED;
		$result = array(
			'run_id'          => $run['run_id'],
			'last_scan'       => current_time( 'mysql' ),
			'status'          => empty( $findings ) && empty( $errors ) ? 'safe' : ( empty( $findings ) ? 'degraded' : 'threat' ),
			'security_status' => empty( $findings ) ? ( empty( $errors ) ? ScanResult::SECURITY_SAFE : ScanResult::SECURITY_PENDING ) : ScanResult::SECURITY_THREAT,
			'coverage_status' => $coverage,
			'execution_state' => ScanResult::EXECUTION_COMPLETED,
			'scope_errors'    => $errors,
			'unknown_count'   => count( $findings ),
			'unknown_folders' => $findings,
			'progress'        => array(
				'scope'          => 'finalize',
				'scope_index'    => count( self::SCOPES ) - 1,
				'processed'      => (int) $run['processed'],
				'total'          => (int) $run['processed'],
				'current_folder' => 'Selesai',
				'current_file'   => 'Verifikasi Lengkap',
				'recent_items'   => array(),
			),
		);
		self::require_write( self::write_option( 'wp_root_guard_last_scan', $result ), 'last_scan_write_failed' );
		self::require_write( self::write_option( 'wp_root_guard_unknown_folders', $findings ), 'finding_option_write_failed' );
		if ( 'baseline_candidate' === ( $run['context'] ?? '' ) && 'safe' === $result['security_status'] && 'complete' === $result['coverage_status'] && class_exists( __NAMESPACE__ . '\\Baseline' ) ) {
			Baseline::generate_pending_baseline( $run['run_id'] );
		}
		$run['status'] = 'completed';
		$run['updated_at'] = time();
		self::require_write( ScanStore::save_run( $run ), 'run_finalize_failed' );
		delete_option( self::RUN_OPTION );
		self::update_dashboard_state( $run, 'completed' );
		Scanner::notify_scan_findings( $findings );
		return $result;
	}
	private static function findings( $run_id ) { global $wpdb; $table = ScanStore::items_table(); $rows = $wpdb->get_col( $wpdb->prepare( "SELECT metadata FROM {$table} WHERE run_id = %s AND state = 'finding'", $run_id ) ); $out = array(); foreach ( $rows as $row ) { $data = json_decode( $row, true ); if ( is_array( $data ) ) { $out[] = $data; } } return $out; }
	private static function total_items( $run_id ) { $count = ScanStore::count_run_items( $run_id ); self::require_write( false !== $count, 'total_item_count_failed' ); return $count; }
	private static function result( $run, $execution ) {
		return array(
			'last_scan'       => '',
			'status'          => 'running',
			'security_status' => ScanResult::SECURITY_PENDING,
			'coverage_status' => empty( $run['errors'] ) ? ScanResult::COVERAGE_COMPLETE : ScanResult::COVERAGE_DEGRADED,
			'execution_state' => $execution,
			'unknown_count'   => count( self::findings( $run['run_id'] ) ),
			'progress'        => array(
				'scope'          => $run['scope'],
				'scope_index'    => (int) ( $run['scope_index'] ?? 0 ),
				'processed'      => (int) $run['processed'],
				'total'          => max( (int) $run['total'], (int) $run['processed'] ),
				'current_folder' => $run['current_folder'] ?? '',
				'current_file'   => $run['current_file'] ?? '',
				'recent_items'   => $run['recent_items'] ?? array(),
			),
		);
	}

	/**
	 * Seed database scope: enqueues tables and integrity checks for slot/judol/malware.
	 */
	private static function seed_database_scope( &$run ) {
		global $wpdb;

		// 1. Enqueue all database tables
		$tables = $wpdb->get_col( 'SHOW TABLES' ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		if ( is_array( $tables ) ) {
			foreach ( $tables as $table_name ) {
				self::enqueue_item( $run, 'database_integrity', 'db_table:' . $table_name, 'db_table', '', array( 'table' => $table_name ) );
			}
		}

		// 2. Enqueue deep content inspections
		self::enqueue_item( $run, 'database_integrity', 'db_check:posts_slot', 'db_check', '', array( 'check' => 'posts_slot' ) );
		self::enqueue_item( $run, 'database_integrity', 'db_check:posts_hidden', 'db_check', '', array( 'check' => 'posts_hidden' ) );
		self::enqueue_item( $run, 'database_integrity', 'db_check:options_integrity', 'db_check', '', array( 'check' => 'options_integrity' ) );
		self::enqueue_item( $run, 'database_integrity', 'db_check:users_integrity', 'db_check', '', array( 'check' => 'users_integrity' ) );
	}

	/**
	 * Analyze a claimed database item (table, post spam, option backdoor, or admin check).
	 */
	private static function analyze_database_item( $item ) {
		global $wpdb;
		$item_type = $item['item_type'] ?? '';
		$path      = (string) $item['path'];
		$metadata  = json_decode( $item['metadata'] ?? '{}', true );
		$metadata  = is_array( $metadata ) ? $metadata : array();

		// A. Database Table Check
		if ( 'db_table' === $item_type ) {
			$table_name = $metadata['table'] ?? str_replace( 'db_table:', '', $path );
			$matched_kw = self::is_rogue_table( $table_name );
			if ( $matched_kw ) {
				return self::finding(
					'database_threat',
					'Tabel: ' . $table_name,
					'Database: ' . $table_name,
					'Tabel Liar / Berbahaya',
					'Tabel asing tidak terdaftar berindikasi konten judi/backdoor liar (Kata Kunci: "' . $matched_kw . '")'
				);
			}
			return false;
		}

		// B. Check: Posts Slot Gacor & Judi Online
		if ( 'db_check:posts_slot' === $path || ( 'db_check' === $item_type && 'posts_slot' === ( $metadata['check'] ?? '' ) ) ) {
			if ( ! isset( $wpdb->posts ) ) {
				return false;
			}
			$slot_keywords = array(
				'slot gacor', 'judi online', 'rtp slot', 'sbobet',
				'pragmatic play', 'maxwin', 'situs slot', 'bandar togel',
				'poker online', 'agen slot', 'slot88', 'slot deposit',
				'link gacor', 'judi bola', 'bocoran slot', 'togel online',
				'slot online', 'zeus olympus'
			);
			$likes = array();
			$params = array();
			foreach ( $slot_keywords as $kw ) {
				$likes[] = '(post_title LIKE %s OR post_content LIKE %s)';
				$params[] = '%' . $wpdb->esc_like( $kw ) . '%';
				$params[] = '%' . $wpdb->esc_like( $kw ) . '%';
			}
			$where = implode( ' OR ', $likes );
			$count_sql = "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status != 'trash' AND ({$where})";
			$total_found = (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery

			if ( $total_found > 0 ) {
				$sql = "SELECT ID, post_title, post_status FROM {$wpdb->posts} WHERE post_status != 'trash' AND ({$where}) ORDER BY ID DESC LIMIT 15";
				$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$first = ! empty( $rows ) ? $rows[0] : (object) array( 'ID' => 0, 'post_title' => '' );
				$post_id = (int) $first->ID;
				$post_url = function_exists( 'get_permalink' ) ? get_permalink( $post_id ) : home_url( '/?p=' . $post_id );
				if ( empty( $post_url ) ) {
					$post_url = home_url( '/?p=' . $post_id );
				}
				$edit_url = function_exists( 'get_edit_post_link' ) ? get_edit_post_link( $post_id, 'raw' ) : admin_url( 'post.php?post=' . $post_id . '&action=edit' );
				if ( empty( $edit_url ) ) {
					$edit_url = admin_url( 'post.php?post=' . $post_id . '&action=edit' );
				}

				$posts_list = array();
				$titles     = array();
				foreach ( $rows as $r ) {
					$pid   = (int) $r->ID;
					$p_url = function_exists( 'get_permalink' ) ? get_permalink( $pid ) : home_url( '/?p=' . $pid );
					$e_url = function_exists( 'get_edit_post_link' ) ? get_edit_post_link( $pid, 'raw' ) : admin_url( 'post.php?post=' . $pid . '&action=edit' );
					$posts_list[] = array(
						'id'       => $pid,
						'title'    => ! empty( $r->post_title ) ? $r->post_title : '(Tanpa Judul)',
						'post_url' => $p_url ?: home_url( '/?p=' . $pid ),
						'edit_url' => $e_url ?: admin_url( 'post.php?post=' . $pid . '&action=edit' ),
					);
					if ( count( $titles ) < 5 ) {
						$titles[] = '#' . $pid . ' "' . wp_trim_words( $r->post_title, 4, '...' ) . '"';
					}
				}

				$finding = self::finding(
					'database_threat',
					'wp_posts [ID: ' . $first->ID . ' - ' . wp_trim_words( $first->post_title, 5, '...' ) . ']',
					'Database: ' . $wpdb->prefix . 'posts (Ditemukan ' . $total_found . ' post slot)',
					'Injeksi Konten Slot Gacor',
					'Ditemukan ' . $total_found . ' post mengandung kata kunci judi/slot gacor: ' . implode( ', ', $titles )
				);
				$finding['post_id']           = $post_id;
				$finding['post_url']          = $post_url;
				$finding['edit_url']          = $edit_url;
				$finding['total_posts_count'] = $total_found;
				$finding['posts_list']        = $posts_list;
				return $finding;
			}
			return false;
		}

		// C. Check: Posts Hidden Malicious Injections (iframe display:none, stealth redirect divs)
		if ( 'db_check:posts_hidden' === $path || ( 'db_check' === $item_type && 'posts_hidden' === ( $metadata['check'] ?? '' ) ) ) {
			if ( ! isset( $wpdb->posts ) ) {
				return false;
			}
			$params = array(
				'%<iframe%display:none%',
				'%<iframe%visibility:hidden%',
				'%display:none%http%',
				'%position:absolute;left:-999%http%'
			);
			$count_sql = "SELECT COUNT(*) FROM {$wpdb->posts} WHERE post_status != 'trash' AND (
				post_content LIKE %s OR 
				post_content LIKE %s OR 
				post_content LIKE %s OR 
				post_content LIKE %s
			)";
			$total_found = (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $params ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery

			if ( $total_found > 0 ) {
				$sql = "SELECT ID, post_title FROM {$wpdb->posts} WHERE post_status != 'trash' AND (
					post_content LIKE %s OR 
					post_content LIKE %s OR 
					post_content LIKE %s OR 
					post_content LIKE %s
				) ORDER BY ID DESC LIMIT 15";
				$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
				$first = ! empty( $rows ) ? $rows[0] : (object) array( 'ID' => 0, 'post_title' => '' );
				$post_id = (int) $first->ID;
				$post_url = function_exists( 'get_permalink' ) ? get_permalink( $post_id ) : home_url( '/?p=' . $post_id );
				if ( empty( $post_url ) ) {
					$post_url = home_url( '/?p=' . $post_id );
				}
				$edit_url = function_exists( 'get_edit_post_link' ) ? get_edit_post_link( $post_id, 'raw' ) : admin_url( 'post.php?post=' . $post_id . '&action=edit' );
				if ( empty( $edit_url ) ) {
					$edit_url = admin_url( 'post.php?post=' . $post_id . '&action=edit' );
				}

				$posts_list = array();
				$titles     = array();
				foreach ( $rows as $r ) {
					$pid   = (int) $r->ID;
					$p_url = function_exists( 'get_permalink' ) ? get_permalink( $pid ) : home_url( '/?p=' . $pid );
					$e_url = function_exists( 'get_edit_post_link' ) ? get_edit_post_link( $pid, 'raw' ) : admin_url( 'post.php?post=' . $pid . '&action=edit' );
					$posts_list[] = array(
						'id'       => $pid,
						'title'    => ! empty( $r->post_title ) ? $r->post_title : '(Tanpa Judul)',
						'post_url' => $p_url ?: home_url( '/?p=' . $pid ),
						'edit_url' => $e_url ?: admin_url( 'post.php?post=' . $pid . '&action=edit' ),
					);
					if ( count( $titles ) < 5 ) {
						$titles[] = '#' . $pid . ' "' . wp_trim_words( $r->post_title, 4, '...' ) . '"';
					}
				}

				$finding = self::finding(
					'database_threat',
					'wp_posts [ID: ' . $first->ID . ' - ' . wp_trim_words( $first->post_title, 5, '...' ) . ']',
					'Database: ' . $wpdb->prefix . 'posts (Ditemukan ' . $total_found . ' post stealth)',
					'Injeksi Stealth Iframe / Redirect',
					'Ditemukan ' . $total_found . ' post dengan elemen tersembunyi (hidden iframe / invisible spam div): ' . implode( ', ', $titles )
				);
				$finding['post_id']           = $post_id;
				$finding['post_url']          = $post_url;
				$finding['edit_url']          = $edit_url;
				$finding['total_posts_count'] = $total_found;
				$finding['posts_list']        = $posts_list;
				return $finding;
			}
			return false;
		}

		// D. Check: wp_options Integrity (eval, base64_decode, unauthorized redirects)
		if ( 'db_check:options_integrity' === $path || ( 'db_check' === $item_type && 'options_integrity' === ( $metadata['check'] ?? '' ) ) ) {
			if ( ! isset( $wpdb->options ) ) {
				return false;
			}
			$sql = "SELECT option_name FROM {$wpdb->options} WHERE (
				option_name LIKE %s OR 
				option_name LIKE %s OR 
				option_value LIKE %s OR 
				option_value LIKE %s OR 
				option_value LIKE %s
			) LIMIT 5";
			$params = array(
				'%_eval_%',
				'%temp_backdoor%',
				'%eval(base64_decode%',
				'%eval(gzinflate%',
				'%str_rot13(base64_decode%'
			);
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			if ( ! empty( $rows ) ) {
				$first = $rows[0];
				return self::finding(
					'database_threat',
					'wp_options [' . $first->option_name . ']',
					'Database: ' . $wpdb->prefix . 'options -> ' . $first->option_name,
					'Opsi Berbahaya (Backdoor)',
					'Opsi database terdeteksi mengandung kode obfuscated eksekusi dinamis (eval/base64)'
				);
			}
			return false;
		}

		// E. Check: Rogue Administrators in wp_users
		if ( 'db_check:users_integrity' === $path || ( 'db_check' === $item_type && 'users_integrity' === ( $metadata['check'] ?? '' ) ) ) {
			if ( ! isset( $wpdb->users ) ) {
				return false;
			}
			$suspicious_names = array( 'admin1', 'admin2', 'system_admin', 'temp_admin', 'backup_admin', 'support_wp', 'root_admin' );
			$likes = array();
			$params = array();
			foreach ( $suspicious_names as $name ) {
				$likes[] = 'user_login LIKE %s';
				$params[] = '%' . $wpdb->esc_like( $name ) . '%';
			}
			$sql = "SELECT ID, user_login, user_email FROM {$wpdb->users} WHERE (" . implode( ' OR ', $likes ) . ") LIMIT 5";
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, $params ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			if ( ! empty( $rows ) ) {
				$first = $rows[0];
				return self::finding(
					'database_threat',
					'wp_users [ID: ' . $first->ID . ' - ' . $first->user_login . ']',
					'Database: ' . $wpdb->prefix . 'users -> ID ' . $first->ID,
					'Akun Pengguna Mencurigakan',
					'Terdeteksi akun pengguna dengan pola penamaan administrator liar: ' . $first->user_login . ' (' . $first->user_email . ')'
				);
			}
			return false;
		}

		return false;
	}

	/**
	 * Check if a table name is rogue or malicious.
	 *
	 * @param string $table_name Table name to test.
	 * @return string|false Matched keyword or false if safe.
	 */
	public static function is_rogue_table( $table_name ) {
		global $wpdb;
		$prefix = isset( $wpdb->prefix ) ? $wpdb->prefix : 'wp_';
		$core_tables = array(
			$prefix . 'commentmeta',
			$prefix . 'comments',
			$prefix . 'links',
			$prefix . 'options',
			$prefix . 'postmeta',
			$prefix . 'posts',
			$prefix . 'termmeta',
			$prefix . 'terms',
			$prefix . 'term_relationships',
			$prefix . 'term_taxonomy',
			$prefix . 'usermeta',
			$prefix . 'users',
			$prefix . 'wprg_scan_runs',
			$prefix . 'wprg_scan_items',
			$prefix . 'wprg_scan_findings',
			$prefix . 'wprg_quarantine_items',
		);
		$lower = strtolower( (string) $table_name );
		if ( in_array( $lower, $core_tables, true ) ) {
			return false;
		}

		$suspicious_keywords = array(
			'slot', 'gacor', 'judol', 'poker', 'casino', 'sbobet',
			'pragmatic', 'maxwin', 'zeus', 'togel', 'hack', 'backdoor',
			'temp_admin', 'wp_eval', 'shell', 'wso'
		);
		foreach ( $suspicious_keywords as $kw ) {
			if ( false !== strpos( $lower, $kw ) ) {
				return $kw;
			}
		}
		return false;
	}
	private static function checkpoint( $run, $error ) { $run['errors'][] = $error; $run['status'] = 'retry_wait'; $run['next_retry_at'] = time() + 60; $run['updated_at'] = time(); self::require_write( ScanStore::save_run( $run ), 'deferred_checkpoint_write_failed' ); update_option( self::RUN_OPTION, $run, false ); self::mark_dashboard_pending( $run ); return self::deferred( $error, $run ); }
	private static function deferred( $error = 'deferred', $run = array() ) { return array( 'run_id' => $run['run_id'] ?? '', 'status' => 'deferred', 'security_status' => ScanResult::SECURITY_PENDING, 'coverage_status' => ScanResult::COVERAGE_DEGRADED, 'execution_state' => ScanResult::EXECUTION_DEFERRED, 'unknown_count' => 0, 'error' => sanitize_key( $error ), 'retry_at' => $run['next_retry_at'] ?? 0 ); }
	private static function failed( $error ) { return array( 'status' => 'failed', 'security_status' => ScanResult::SECURITY_PENDING, 'coverage_status' => ScanResult::COVERAGE_FAILED, 'execution_state' => ScanResult::EXECUTION_FAILED, 'unknown_count' => 0, 'error' => $error ); }
	/** Return the current run only when it has not reached a terminal state. */
	public static function get_active_run() { $run = get_option( self::RUN_OPTION, array() ); return is_array( $run ) && ! empty( $run['run_id'] ) && in_array( $run['status'] ?? '', array( 'running', 'retry_wait' ), true ) ? $run : array(); }
	private static function update_dashboard_state( $run, $status = 'running' ) { update_option( Scanner::SCAN_STATE_OPTION, array( 'status' => $status, 'run_id' => $run['run_id'], 'started_at_gmt' => gmdate( 'Y-m-d H:i:s', $run['created_at'] ), 'completed_at_gmt' => in_array( $status, array( 'completed', 'failed' ), true ) ? gmdate( 'Y-m-d H:i:s' ) : '', 'last_heartbeat' => gmdate( 'Y-m-d H:i:s' ), 'duration_ms' => 0, 'found_count' => count( self::findings( $run['run_id'] ) ), 'error' => implode( ',', (array) ( $run['errors'] ?? array() ) ) ), false ); }
	private static function mark_dashboard_pending( $run ) { $last = get_option( 'wp_root_guard_last_scan', array() ); $last = is_array( $last ) ? $last : array(); $last['run_id'] = $run['run_id']; $last['status'] = 'pending'; $last['security_status'] = ScanResult::SECURITY_PENDING; $last['coverage_status'] = ScanResult::COVERAGE_DEGRADED; $last['execution_state'] = ScanResult::EXECUTION_RUNNING; self::write_option( 'wp_root_guard_last_scan', $last ); self::update_dashboard_state( $run, 'running' ); }
	private static function handle_failure( $run, $error ) { $run['retry_count'] = absint( $run['retry_count'] ?? 0 ) + 1; $run['error_code'] = sanitize_key( $error ); $run['error_message'] = sanitize_text_field( $error ); $run['errors'][] = $run['error_code']; if ( $run['retry_count'] <= 3 ) { $delays = array( 60, 300, 900 ); $run['status'] = 'retry_wait'; $run['next_retry_at'] = time() + $delays[ $run['retry_count'] - 1 ]; if ( ScanStore::save_run( $run ) ) { update_option( self::RUN_OPTION, $run, false ); self::mark_dashboard_pending( $run ); return self::deferred( $run['error_code'], $run ); } } $run['status'] = 'failed'; $run['next_retry_at'] = 0; ScanStore::save_run( $run ); delete_option( self::RUN_OPTION ); self::update_dashboard_state( $run, 'failed' ); $result = self::failed( $run['error_code'] ); $result['run_id'] = $run['run_id']; update_option( 'wp_root_guard_last_scan', $result, false ); return $result; }
	private static function require_write( $success, $error ) { if ( ! $success ) { throw new \RuntimeException( sanitize_key( $error ) ); } }
	private static function enqueue_item( $run, $scope, $path, $type, $hash = '', $metadata = array() ) { self::require_write( ScanStore::enqueue_item( $run['run_id'], $scope, $path, $type, $hash, $metadata ), 'item_enqueue_failed' ); }
	private static function finish_item( $item, $token, $state, $metadata = array() ) { self::require_write( ScanStore::finish_item( $item['id'], $token, $state, $metadata ), 'item_finish_failed' ); }
	private static function requeue_item( $item, $token, $metadata = array() ) { self::require_write( ScanStore::requeue_item( $item['id'], $token, $metadata ), 'item_requeue_failed' ); }
	private static function hashable( $path ) { return ! file_exists( $path ) || ( is_file( $path ) && ! is_link( $path ) && is_readable( $path ) && (int) @filesize( $path ) <= 5242880 ); }
	private static function write_option( $key, $value ) { return update_option( $key, $value, false ) || get_option( $key, null ) === $value; }
}
