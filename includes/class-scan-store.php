<?php
/**
 * Database persistence for resumable scan runs and quarantine audit records.
 *
 * @package WPRootGuard
 * @since 3.3.0
 */

namespace WPRootGuard;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Keeps operational scan state out of wp_options.  The tables are deliberately
 * small: file contents never enter the database.
 */
class ScanStore {

	const SCHEMA_OPTION = 'wp_root_guard_storage_schema';
	const SCHEMA_VERSION = 3;

	/** Create or upgrade the plugin-owned tables. */
	public static function ensure_schema( $force = false ) {
		global $wpdb;

		if ( ! isset( $wpdb->prefix ) ) {
			return false;
		}
		$runs  = $wpdb->prefix . 'wprg_scan_runs';
		$items = $wpdb->prefix . 'wprg_scan_items';
		if ( ! $force && (int) get_option( self::SCHEMA_OPTION, 0 ) >= self::SCHEMA_VERSION ) {
			$has_runs  = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $runs ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			$has_items = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $items ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
			if ( $runs === $has_runs && $items === $has_items ) {
				return true;
			}
		}

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		$findings = $wpdb->prefix . 'wprg_scan_findings';
		$quarantine = $wpdb->prefix . 'wprg_quarantine_items';

		dbDelta( "CREATE TABLE {$runs} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			run_id char(36) NOT NULL,
			fencing_hash char(64) NOT NULL,
			context varchar(32) NOT NULL,
			status varchar(20) NOT NULL,
			scope varchar(32) NOT NULL,
			checkpoint_json longtext NOT NULL,
			processed bigint(20) unsigned NOT NULL DEFAULT 0,
			batch_number bigint(20) unsigned NOT NULL DEFAULT 0,
			retry_count tinyint(3) unsigned NOT NULL DEFAULT 0,
			next_retry_at_gmt datetime NULL,
			started_at_gmt datetime NOT NULL,
			heartbeat_at_gmt datetime NOT NULL,
			completed_at_gmt datetime NULL,
			error_code varchar(100) NOT NULL DEFAULT '',
			error_message text NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY run_id (run_id),
			KEY status_heartbeat (status,heartbeat_at_gmt),
			KEY retry_due (status,next_retry_at_gmt)
		) {$charset};" );

		dbDelta( "CREATE TABLE {$findings} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			run_id char(36) NOT NULL,
			scope varchar(32) NOT NULL,
			finding_key char(64) NOT NULL,
			severity varchar(20) NOT NULL,
			path_hash char(64) NOT NULL,
			details longtext NOT NULL,
			created_at_gmt datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY run_finding (run_id,finding_key),
			KEY run_scope (run_id,scope)
		) {$charset};" );

		dbDelta( "CREATE TABLE {$quarantine} (
			id char(36) NOT NULL,
			storage_id char(64) NOT NULL,
			type varchar(16) NOT NULL,
			original_path longtext NOT NULL,
			quarantine_path longtext NOT NULL,
			sha256 char(64) NOT NULL DEFAULT '',
			size bigint(20) unsigned NOT NULL DEFAULT 0,
			item_mode varchar(12) NOT NULL DEFAULT '',
			status varchar(20) NOT NULL,
			created_at_gmt datetime NOT NULL,
			updated_at_gmt datetime NOT NULL,
			PRIMARY KEY  (id),
			KEY status_updated (status,updated_at_gmt)
		) {$charset};" );

		dbDelta( "CREATE TABLE {$items} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			run_id char(36) NOT NULL,
			scope varchar(32) NOT NULL,
			path longtext NOT NULL,
			path_hash char(64) NOT NULL,
			item_type varchar(16) NOT NULL,
			expected_hash char(64) NOT NULL DEFAULT '',
			size bigint(20) unsigned NOT NULL DEFAULT 0,
			mtime bigint(20) unsigned NOT NULL DEFAULT 0,
			state varchar(16) NOT NULL DEFAULT 'queued',
			claim_token char(64) NOT NULL DEFAULT '',
			metadata longtext NOT NULL,
			created_at_gmt datetime NOT NULL,
			updated_at_gmt datetime NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY run_scope_path (run_id,scope,path_hash),
			KEY runnable (run_id,scope,state,id),
			KEY claims (run_id,state,updated_at_gmt)
		) {$charset};" );

		update_option( self::SCHEMA_OPTION, self::SCHEMA_VERSION, false );
		return true;
	}

	/** @return string */
	public static function items_table() {
		global $wpdb;
		return $wpdb->prefix . 'wprg_scan_items';
	}

	/** @return string */
	public static function runs_table() {
		global $wpdb;
		return $wpdb->prefix . 'wprg_scan_runs';
	}

	/** Recover the newest durable non-terminal checkpoint when the option cache is lost. */
	public static function load_active_run() {
		global $wpdb;
		if ( ! self::ensure_schema() ) {
			return array();
		}
		$row = $wpdb->get_row( "SELECT * FROM " . self::runs_table() . " WHERE status IN ('running','retry_wait') ORDER BY heartbeat_at_gmt DESC LIMIT 1", ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( ! is_array( $row ) || empty( $row['run_id'] ) ) {
			return array();
		}
		$checkpoint = json_decode( $row['checkpoint_json'], true );
		$checkpoint = is_array( $checkpoint ) ? $checkpoint : array();
		return array(
			'run_id'          => (string) $row['run_id'],
			'fencing_token'   => wp_generate_password( 64, false, false ),
			'context'         => (string) $row['context'],
			'status'          => (string) $row['status'],
			'scope'           => (string) $row['scope'],
			'scope_index'     => absint( $checkpoint['scope_index'] ?? 0 ),
			'cursor'          => is_array( $checkpoint['cursor'] ?? null ) ? $checkpoint['cursor'] : array(),
			'processed'       => absint( $row['processed'] ),
			'total'           => absint( $checkpoint['total'] ?? 0 ),
			'batch_number'    => absint( $row['batch_number'] ),
			'created_at'      => strtotime( $row['started_at_gmt'] . ' UTC' ) ?: time(),
			'updated_at'      => strtotime( $row['heartbeat_at_gmt'] . ' UTC' ) ?: time(),
			'errors'          => is_array( $checkpoint['errors'] ?? null ) ? $checkpoint['errors'] : array(),
			'findings_summary'=> is_array( $checkpoint['findings_summary'] ?? null ) ? $checkpoint['findings_summary'] : array(),
			'retry_count'     => absint( $row['retry_count'] ?? 0 ),
			'next_retry_at'   => ! empty( $row['next_retry_at_gmt'] ) ? ( strtotime( $row['next_retry_at_gmt'] . ' UTC' ) ?: 0 ) : 0,
			'error_code'      => (string) ( $row['error_code'] ?? '' ),
			'error_message'   => (string) ( $row['error_message'] ?? '' ),
		);
	}

	/** Backward-compatible alias. */
	public static function load_running_run() {
		return self::load_active_run();
	}

	/** Store an item without exposing content in options. */
	public static function enqueue_item( $run_id, $scope, $path, $type, $expected_hash = '', $metadata = array() ) {
		global $wpdb;
		if ( ! self::ensure_schema() ) {
			return false;
		}
		$path = (string) $path;
		$now = gmdate( 'Y-m-d H:i:s' );
		$data = array(
			'run_id' => sanitize_text_field( $run_id ), 'scope' => sanitize_key( $scope ), 'path' => $path,
			'path_hash' => hash( 'sha256', $path ), 'item_type' => sanitize_key( $type ),
			'expected_hash' => sanitize_text_field( $expected_hash ), 'size' => absint( $metadata['size'] ?? 0 ),
			'mtime' => absint( $metadata['mtime'] ?? 0 ), 'state' => 'queued', 'claim_token' => '',
			'metadata' => wp_json_encode( $metadata ), 'created_at_gmt' => $now, 'updated_at_gmt' => $now,
		);
		$sql = $wpdb->prepare( "INSERT IGNORE INTO " . self::items_table() . " (run_id,scope,path,path_hash,item_type,expected_hash,size,mtime,state,claim_token,metadata,created_at_gmt,updated_at_gmt) VALUES (%s,%s,%s,%s,%s,%s,%d,%d,%s,%s,%s,%s,%s)", array_values( $data ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$result = $wpdb->query( $sql ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
		return false !== $result;
	}

	/** Claim a bounded set of queued items for a worker. */
	public static function claim_items( $run_id, $scope, $token, $limit ) {
		global $wpdb;
		$limit = max( 1, min( 100, absint( $limit ) ) );
		$table = self::items_table();
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$table} WHERE run_id = %s AND scope = %s AND state = 'queued' ORDER BY id ASC LIMIT {$limit}", $run_id, $scope ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( empty( $ids ) ) { return array(); }
		$placeholders = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		$args = array_merge( array( sanitize_text_field( $token ), gmdate( 'Y-m-d H:i:s' ) ), array_map( 'absint', $ids ) );
		$updated = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET state = 'claimed', claim_token = %s, updated_at_gmt = %s WHERE id IN ({$placeholders}) AND state = 'queued'", $args ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( false === $updated ) {
			return false;
		}
		$claimed = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE run_id = %s AND scope = %s AND state = 'claimed' AND claim_token = %s ORDER BY id ASC", $run_id, $scope, $token ), ARRAY_A ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return null === $claimed ? false : $claimed;
	}

	/** Finish one claimed item with an optional finding payload. */
	public static function finish_item( $id, $token, $state, $metadata = array() ) {
		global $wpdb;
		$state = in_array( $state, array( 'done', 'finding', 'skipped', 'failed' ), true ) ? $state : 'failed';
		return false !== $wpdb->update( self::items_table(), array( 'state' => $state, 'metadata' => wp_json_encode( $metadata ), 'updated_at_gmt' => gmdate( 'Y-m-d H:i:s' ) ), array( 'id' => absint( $id ), 'claim_token' => sanitize_text_field( $token ), 'state' => 'claimed' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
	}

	/** Return a claimed item to the queue with a durable continuation cursor. */
	public static function requeue_item( $id, $token, $metadata = array() ) {
		global $wpdb;
		return false !== $wpdb->update( self::items_table(), array( 'state' => 'queued', 'claim_token' => '', 'metadata' => wp_json_encode( $metadata ), 'updated_at_gmt' => gmdate( 'Y-m-d H:i:s' ) ), array( 'id' => absint( $id ), 'claim_token' => sanitize_text_field( $token ), 'state' => 'claimed' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
	}

	/** Release unprocessed claims when a batch reaches its time limit. */
	public static function release_claims( $run_id, $scope, $token ) {
		global $wpdb;
		return false !== $wpdb->query( $wpdb->prepare( "UPDATE " . self::items_table() . " SET state = 'queued', claim_token = '', updated_at_gmt = %s WHERE run_id = %s AND scope = %s AND state = 'claimed' AND claim_token = %s", gmdate( 'Y-m-d H:i:s' ), $run_id, $scope, $token ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/** Recover items claimed by a PHP request that never completed. */
	public static function reclaim_stale_claims( $run_id, $seconds = 900 ) {
		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - max( 60, absint( $seconds ) ) );
		return false !== $wpdb->query( $wpdb->prepare( "UPDATE " . self::items_table() . " SET state = 'queued', claim_token = '' WHERE run_id = %s AND state = 'claimed' AND updated_at_gmt < %s", $run_id, $cutoff ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/** @return int */
	public static function count_items( $run_id, $scope, $states = array() ) {
		global $wpdb;
		$table = self::items_table();
		if ( empty( $states ) ) {
			$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE run_id = %s AND scope = %s", $run_id, $scope ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return null === $count ? false : (int) $count;
		}
		$states = array_map( 'sanitize_key', $states );
		$placeholders = implode( ',', array_fill( 0, count( $states ), '%s' ) );
		$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE run_id = %s AND scope = %s AND state IN ({$placeholders})", array_merge( array( $run_id, $scope ), $states ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return null === $count ? false : (int) $count;
	}

	/** Count terminal item states across the whole run. Returns false on DB failure. */
	public static function count_run_items( $run_id, $states = array() ) {
		global $wpdb;
		$table = self::items_table();
		if ( empty( $states ) ) {
			$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE run_id = %s", $run_id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			return null === $count ? false : (int) $count;
		}
		$placeholders = implode( ',', array_fill( 0, count( $states ), '%s' ) );
		$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE run_id = %s AND state IN ({$placeholders})", array_merge( array( $run_id ), array_map( 'sanitize_key', $states ) ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return null === $count ? false : (int) $count;
	}

	/** Remove completed operational scan records after the dashboard retention window. */
	public static function cleanup_completed_runs( $days = 7 ) {
		global $wpdb;
		if ( ! self::ensure_schema() ) {
			return false;
		}
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS * max( 1, absint( $days ) ) );
		$runs   = self::runs_table();
		$items  = self::items_table();
		$run_ids = $wpdb->get_col( $wpdb->prepare( "SELECT run_id FROM {$runs} WHERE status IN ('completed','failed','cancelled') AND completed_at_gmt IS NOT NULL AND completed_at_gmt < %s", $cutoff ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		if ( empty( $run_ids ) ) {
			return true;
		}
		$placeholders = implode( ',', array_fill( 0, count( $run_ids ), '%s' ) );
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$items} WHERE run_id IN ({$placeholders})", $run_ids ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}wprg_scan_findings WHERE run_id IN ({$placeholders})", $run_ids ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return false !== $wpdb->query( $wpdb->prepare( "DELETE FROM {$runs} WHERE run_id IN ({$placeholders})", $run_ids ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared
	}

	/** Persist a bounded run checkpoint. */
	public static function save_run( $state ) {
		global $wpdb;
		if ( empty( $state['run_id'] ) || ! self::ensure_schema() ) {
			return false;
		}
		$table = $wpdb->prefix . 'wprg_scan_runs';
		$now = gmdate( 'Y-m-d H:i:s' );
		$data = array(
			'run_id'           => sanitize_text_field( $state['run_id'] ),
			'fencing_hash'     => hash( 'sha256', (string) ( $state['fencing_token'] ?? '' ) ),
			'context'          => sanitize_key( $state['context'] ?? 'unknown' ),
			'status'           => sanitize_key( $state['status'] ?? 'running' ),
			'scope'            => sanitize_key( $state['scope'] ?? 'root_folders' ),
			'checkpoint_json'  => wp_json_encode( array(
				'cursor'           => $state['cursor'] ?? array(),
				'scope_index'      => absint( $state['scope_index'] ?? 0 ),
				'total'            => absint( $state['total'] ?? 0 ),
				'errors'           => array_values( (array) ( $state['errors'] ?? array() ) ),
				'findings_summary' => (array) ( $state['findings_summary'] ?? array() ),
			) ),
			'processed'        => absint( $state['processed'] ?? 0 ),
			'batch_number'     => absint( $state['batch_number'] ?? 0 ),
			'retry_count'      => min( 255, absint( $state['retry_count'] ?? 0 ) ),
			'next_retry_at_gmt' => ! empty( $state['next_retry_at'] ) ? gmdate( 'Y-m-d H:i:s', (int) $state['next_retry_at'] ) : null,
			'started_at_gmt'   => ! empty( $state['created_at'] ) ? gmdate( 'Y-m-d H:i:s', (int) $state['created_at'] ) : $now,
			'heartbeat_at_gmt' => $now,
			'completed_at_gmt' => in_array( $state['status'] ?? '', array( 'completed', 'failed', 'cancelled' ), true ) ? $now : null,
			'error_code'       => sanitize_key( $state['error_code'] ?? '' ),
			'error_message'    => sanitize_text_field( $state['error_message'] ?? '' ),
		);
		$existing = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE run_id = %s", $data['run_id'] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $existing ? false !== $wpdb->update( $table, $data, array( 'run_id' => $data['run_id'] ) ) : false !== $wpdb->insert( $table, $data ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
	}

	/** Store a deduplicated finding summary for a run. */
	public static function save_finding( $run_id, $scope, $path, $severity, $details = array() ) {
		global $wpdb;
		if ( ! self::ensure_schema() ) {
			return false;
		}
		$path = (string) $path;
		$table = $wpdb->prefix . 'wprg_scan_findings';
		$data = array(
			'run_id'         => sanitize_text_field( $run_id ),
			'scope'          => sanitize_key( $scope ),
			'finding_key'    => hash( 'sha256', $scope . '|' . $path . '|' . $severity ),
			'severity'       => sanitize_key( $severity ),
			'path_hash'      => hash( 'sha256', $path ),
			'details'        => wp_json_encode( is_array( $details ) ? $details : array() ),
			'created_at_gmt' => gmdate( 'Y-m-d H:i:s' ),
		);
		return false !== $wpdb->query( $wpdb->prepare( "INSERT INTO {$table} (run_id,scope,finding_key,severity,path_hash,details,created_at_gmt) VALUES (%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE details = VALUES(details)", array_values( $data ) ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery
	}

	/** Persist immutable quarantine metadata. */
	public static function save_quarantine_item( $item ) {
		global $wpdb;
		if ( empty( $item['id'] ) || ! self::ensure_schema() ) {
			return false;
		}
		$table = $wpdb->prefix . 'wprg_quarantine_items';
		$now = gmdate( 'Y-m-d H:i:s' );
		$data = array(
			'id'                  => sanitize_text_field( $item['id'] ),
			'storage_id'          => hash( 'sha256', (string) ( $item['storage_directory'] ?? '' ) ),
			'type'                => sanitize_key( $item['type'] ?? 'file' ),
			'original_path'       => (string) ( $item['original_path'] ?? '' ),
			'quarantine_path'     => (string) ( $item['quarantine_path'] ?? '' ),
			'sha256'              => sanitize_text_field( $item['sha256'] ?? '' ),
			'size'                => absint( $item['size'] ?? 0 ),
			'item_mode'           => sanitize_text_field( $item['mode'] ?? '' ),
			'status'              => sanitize_key( $item['status'] ?? 'quarantined' ),
			'created_at_gmt'      => $item['created_at_gmt'] ?? $now,
			'updated_at_gmt'      => $now,
		);
		$existing = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE id = %s", $data['id'] ) ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		return $existing ? false !== $wpdb->update( $table, $data, array( 'id' => $data['id'] ) ) : false !== $wpdb->insert( $table, $data ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery
	}
}
