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
	const MAX_ITEMS = 100;
	const MAX_SECONDS = 5;
	const RUN_OPTION = 'wp_root_guard_batch_run';
	const SCOPES = array( 'root_folders', 'root_files', 'core_checksums', 'core_injected_files', 'uploads_php', 'remediate', 'finalize' );
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
		foreach ( $items as $item ) {
			if ( microtime( true ) - $started >= self::MAX_SECONDS ) { self::require_write( ScanStore::release_claims( $run['run_id'], $scope, $token ), 'claim_release_failed' ); break; }
			self::process_item( $run, $scope, $item, $token, $started );
			$run['processed']++;
		}
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
		} elseif ( in_array( $scope, array( 'core_injected_files', 'uploads_php' ), true ) ) {
			$root = 'core_injected_files' === $scope ? 'wp-admin' : 'wp-content/uploads';
			if ( 'core_injected_files' === $scope ) { self::enqueue_item( $run, $scope, 'wp-includes', 'directory', '', array( 'offset' => 0 ) ); }
			self::enqueue_item( $run, $scope, $root, 'directory', '', array( 'offset' => 0 ) ); $cursor['seeded'] = true;
		} elseif ( 'remediate' === $scope ) {
			self::seed_remediation( $run ); $cursor['seeded'] = true;
		}
		$run['cursor'] = $cursor; return ! empty( $cursor['seeded'] );
	}

	private static function process_item( &$run, $scope, $item, $token, $started ) {
		$path = (string) $item['path']; $absolute = ABSPATH . ltrim( $path, '/\\'); $metadata = json_decode( $item['metadata'], true ); $metadata = is_array( $metadata ) ? $metadata : array();
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
		$settings = Settings::get_settings(); $whitelist = Settings::get_user_whitelist();
		if ( 'root_folders' === $scope ) { $known = array_merge( Settings::get_default_whitelist(), Baseline::get_baseline_folders(), $whitelist ); return in_array( $path, $known, true ) ? false : self::finding( 'folder', $path, $absolute, 'Unknown Folder', '-' ); }
		if ( 'root_files' === $scope ) { $baseline = Baseline::get_baseline_files(); $known = array_merge( Settings::get_default_file_whitelist(), array_keys( $baseline ), $whitelist ); if ( ! in_array( $path, $known, true ) ) return self::finding( 'file', $path, $absolute, 'Unknown File', Scanner::scan_file_for_webshell( $absolute ) ); if ( isset( $baseline[$path] ) && ! hash_equals( $baseline[$path], (string) @md5_file( $absolute ) ) ) return self::finding( 'file', $path, $absolute, 'Modified File', Scanner::scan_file_for_webshell( $absolute ) ); return false; }
		if ( 'core_checksums' === $scope ) { $actual = file_exists( $absolute ) ? @md5_file( $absolute ) : false; return false === $actual || ! hash_equals( strtolower( $item['expected_hash'] ), strtolower( (string) $actual ) ) ? self::finding( 'core_file', $path, $absolute, false === $actual ? 'Missing Core File' : 'Modified Core File', Scanner::scan_file_for_webshell( $absolute ) ) : false; }
		if ( 'core_injected_files' === $scope ) { $checksums = self::checksums(); return ! isset( $checksums[$path] ) && ! in_array( $path, $whitelist, true ) ? self::finding( 'core_file', $path, $absolute, 'Suspicious Core Injection', Scanner::scan_file_for_webshell( $absolute ) ) : false; }
		if ( 'uploads_php' === $scope ) { $ext = strtolower( pathinfo( $path, PATHINFO_EXTENSION ) ); return in_array( $ext, array( 'php','phtml','php3','php4','php5','php7','phps','phar','inc' ), true ) && ! in_array( $path, $whitelist, true ) ? self::finding( 'uploads_php', $path, $absolute, 'PHP File in Uploads', Scanner::scan_file_for_webshell( $absolute ) ) : false; }
		return false;
	}

	private static function finding( $type, $path, $absolute, $status, $indicator ) { return array( 'type' => $type, 'name' => $path, 'path' => $absolute, 'status' => $status, 'malware_indicator' => $indicator ?: '-', 'created_time' => Scanner::get_wib_time( @filectime( $absolute ) ?: time() ), 'detection_time' => Scanner::get_wib_time() ); }
	private static function unchanged( $path, $item ) { return file_exists( $path ) && ! is_link( $path ) && ( ! empty( $item['mtime'] ) ? (int) @filemtime( $path ) === (int) $item['mtime'] : true ) && ( ! empty( $item['size'] ) ? (int) @filesize( $path ) === (int) $item['size'] : true ); }
	private static function stat_meta( $path ) { return array( 'size' => max( 0, (int) @filesize( $path ) ), 'mtime' => max( 0, (int) @filemtime( $path ) ) ); }
	private static function checksums() { if ( null === self::$checksums ) { self::$checksums = Scanner::get_core_checksums(); } return is_array( self::$checksums ) ? self::$checksums : array(); }
	private static function skip_internal_path( $scope, $path ) { if ( 'uploads_php' !== $scope ) { return false; } $path = str_replace( '\\', '/', $path ); return 0 === strpos( $path, 'wp-content/uploads/wp-root-guard/' ) || 0 === strpos( $path, 'wp-content/uploads/wp-root-guard-quarantine/' ); }

	private static function seed_remediation( $run ) { foreach ( self::findings( $run['run_id'] ) as $finding ) { self::enqueue_item( $run, 'remediate', $finding['name'], 'remediate', '', array( 'finding' => $finding ) ); } }
	private static function remediate_item( $item, $token, $metadata ) { $finding = $metadata['finding'] ?? array(); $result = false; $settings = Settings::get_settings(); if ( ! empty( $settings['enable_auto_quarantine'] ) || ( 'uploads_php' === ( $finding['type'] ?? '' ) && ! empty( $settings['enable_uploads_auto_quarantine'] ) ) ) { $name = $finding['name'] ?? ''; $result = 'folder' === ( $finding['type'] ?? '' ) ? Scanner::quarantine_folder( $name ) : ( false !== strpos( $name, '/' ) ? Scanner::quarantine_core_file( $name ) : Scanner::quarantine_file( $name ) ); } self::finish_item( $item, $token, false !== $result ? 'done' : 'skipped', array( 'remediated' => false !== $result ) ); }

	private static function advance_scope( &$run ) { $index = array_search( $run['scope'], self::SCOPES, true ); $run['scope_index'] = false === $index ? count( self::SCOPES ) - 1 : $index + 1; $run['scope'] = self::SCOPES[ $run['scope_index'] ] ?? 'finalize'; $run['cursor'] = array( 'seeded' => false, 'offset' => 0 ); }
	private static function persist_running( $run ) { $run['status'] = 'running'; $run['next_retry_at'] = 0; $run['batch_number']++; $run['updated_at'] = time(); $run['total'] = self::total_items( $run['run_id'] ); $run['findings_summary'] = array( 'threat_count' => count( self::findings( $run['run_id'] ) ) ); self::require_write( ScanStore::save_run( $run ), 'checkpoint_write_failed' ); update_option( self::RUN_OPTION, $run, false ); self::mark_dashboard_pending( $run ); return self::result( $run, ScanResult::EXECUTION_RUNNING ); }
	private static function finalize( $run ) { $incomplete = ScanStore::count_run_items( $run['run_id'], array( 'failed', 'skipped', 'queued', 'claimed' ) ); self::require_write( false !== $incomplete, 'final_coverage_query_failed' ); if ( $incomplete > 0 ) { $run['errors'][] = 'incomplete_or_unverifiable_items'; } $findings = self::findings( $run['run_id'] ); $errors = array_values( array_unique( $run['errors'] ?? array() ) ); $coverage = empty( $errors ) ? ScanResult::COVERAGE_COMPLETE : ScanResult::COVERAGE_DEGRADED; $result = array( 'run_id' => $run['run_id'], 'last_scan' => current_time( 'mysql' ), 'status' => empty( $findings ) && empty( $errors ) ? 'safe' : ( empty( $findings ) ? 'degraded' : 'threat' ), 'security_status' => empty( $findings ) ? ( empty( $errors ) ? ScanResult::SECURITY_SAFE : ScanResult::SECURITY_PENDING ) : ScanResult::SECURITY_THREAT, 'coverage_status' => $coverage, 'execution_state' => ScanResult::EXECUTION_COMPLETED, 'scope_errors' => $errors, 'unknown_count' => count( $findings ), 'unknown_folders' => $findings ); self::require_write( self::write_option( 'wp_root_guard_last_scan', $result ), 'last_scan_write_failed' ); self::require_write( self::write_option( 'wp_root_guard_unknown_folders', $findings ), 'finding_option_write_failed' ); if ( 'baseline_candidate' === ( $run['context'] ?? '' ) && 'safe' === $result['security_status'] && 'complete' === $result['coverage_status'] && class_exists( __NAMESPACE__ . '\\Baseline' ) ) { Baseline::generate_pending_baseline( $run['run_id'] ); } $run['status'] = 'completed'; $run['updated_at'] = time(); self::require_write( ScanStore::save_run( $run ), 'run_finalize_failed' ); delete_option( self::RUN_OPTION ); self::update_dashboard_state( $run, 'completed' ); Scanner::notify_scan_findings( $findings ); return $result; }
	private static function findings( $run_id ) { global $wpdb; $table = ScanStore::items_table(); $rows = $wpdb->get_col( $wpdb->prepare( "SELECT metadata FROM {$table} WHERE run_id = %s AND state = 'finding'", $run_id ) ); $out = array(); foreach ( $rows as $row ) { $data = json_decode( $row, true ); if ( is_array( $data ) ) { $out[] = $data; } } return $out; }
	private static function total_items( $run_id ) { $count = ScanStore::count_run_items( $run_id ); self::require_write( false !== $count, 'total_item_count_failed' ); return $count; }
	private static function result( $run, $execution ) { return array( 'last_scan' => '', 'status' => 'running', 'security_status' => ScanResult::SECURITY_PENDING, 'coverage_status' => empty( $run['errors'] ) ? ScanResult::COVERAGE_COMPLETE : ScanResult::COVERAGE_DEGRADED, 'execution_state' => $execution, 'unknown_count' => count( self::findings( $run['run_id'] ) ), 'progress' => array( 'scope' => $run['scope'], 'processed' => (int) $run['processed'], 'total' => self::total_items( $run['run_id'] ) ) ); }
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
