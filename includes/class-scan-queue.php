<?php
/**
 * Persistent state service for resumable scanner runs.
 *
 * This service deliberately stores run metadata only. Finding details and file
 * contents must remain in the scanner's existing stores or a future custom
 * table. A custom table is recommended for very large installations.
 *
 * @package WPRootGuard
 * @since   3.3.0
 */

namespace WPRootGuard;

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Stores one bounded, non-autoloaded state record for a resumable scan run.
 *
 * @package WPRootGuard
 */
class ScanQueue {

	/**
	 * Option containing the active or most recent run state.
	 */
	const OPTION_NAME = 'wp_root_guard_scan_queue';

	/**
	 * State schema version.
	 */
	const SCHEMA_VERSION = 1;

	/**
	 * Default lease duration in seconds.
	 */
	const DEFAULT_LEASE_SECONDS = 900;

	/**
	 * Maximum number of recorded errors.
	 */
	const MAX_ERRORS = 20;

	/**
	 * Maximum number of finding categories in the summary.
	 */
	const MAX_FINDING_TYPES = 20;

	/**
	 * Maximum length for a persisted path/cursor.
	 */
	const MAX_CURSOR_LENGTH = 1024;

	/**
	 * Allowed lifecycle states.
	 */
	const STATES = array( 'running', 'paused', 'completed', 'failed', 'cancelled' );

	/**
	 * Create and persist a new scan run.
	 *
	 * Existing running state is not overwritten. Callers should acquire a
	 * separate global lock before creating a run.
	 *
	 * @param string $scope Initial scan scope.
	 * @param int    $scope_index Scope position in the scanner plan.
	 * @param int    $total Estimated item count.
	 * @param array  $args Optional context, cursor, and lease settings.
	 * @return array|WP_Error Normalized state or error.
	 */
	public static function create_run( $scope = 'root', $scope_index = 0, $total = 0, $args = array() ) {
		$current = self::get_state();
		if ( $current && 'running' === $current['status'] && ! self::is_stale( $current ) ) {
			return new \WP_Error( 'scan_queue_busy', __( 'Pemindaian lain sedang berjalan.', 'wp-root-guard' ) );
		}

		$now = time();
		$lease_seconds = isset( $args['lease_seconds'] ) ? self::normalize_int( $args['lease_seconds'], self::DEFAULT_LEASE_SECONDS, 60, 3600 ) : self::DEFAULT_LEASE_SECONDS;
		$state = self::normalize_state(
			array(
				'run_id'          => self::new_id(),
				'fencing_token'   => self::new_token(),
				'scope'           => $scope,
				'scope_index'     => $scope_index,
				'cursor'          => isset( $args['cursor'] ) ? $args['cursor'] : '',
				'batch_number'    => 0,
				'processed'       => 0,
				'total'           => $total,
				'snapshot_time'   => isset( $args['snapshot_time'] ) ? $args['snapshot_time'] : gmdate( 'c', $now ),
				'status'          => 'running',
				'heartbeat'       => $now,
				'lease_expires'   => $now + $lease_seconds,
				'errors'          => array(),
				'findings_summary'=> array(),
				'context'         => isset( $args['context'] ) ? $args['context'] : 'unknown',
				'created_at'      => $now,
				'updated_at'      => $now,
			),
			$lease_seconds
		);

		// A stale or terminal record may remain after a request timeout. Reuse
		// the existing option in that case; an active lease was rejected above.
		$must_exist = (bool) $current;
		if ( ! self::persist( $state, $must_exist ) ) {
			return new \WP_Error( 'scan_queue_create_failed', __( 'State pemindaian tidak dapat disimpan.', 'wp-root-guard' ) );
		}

		return $state;
	}

	/**
	 * Return the normalized current state, or null when no run exists.
	 *
	 * @return array|null
	 */
	public static function get_state() {
		$state = get_option( self::OPTION_NAME, null );
		return is_array( $state ) ? self::normalize_state( $state ) : null;
	}

	/**
	 * Determine whether a state lease has expired.
	 *
	 * @param array|null $state Optional state; current state when omitted.
	 * @param int        $now Optional Unix timestamp.
	 * @return bool
	 */
	public static function is_stale( $state = null, $now = null ) {
		$state = is_array( $state ) ? self::normalize_state( $state ) : self::get_state();
		if ( ! $state || 'running' !== $state['status'] ) {
			return false;
		}

		$now = null === $now ? time() : (int) $now;
		return $state['lease_expires'] > 0 && $state['lease_expires'] <= $now;
	}

	/**
	 * Validate that a caller owns the current run and fencing token.
	 *
	 * The filter is an extension point for a future lock/table implementation;
	 * returning false from it rejects the ownership check.
	 *
	 * @param string     $fencing_token Token held by the caller.
	 * @param array|null $state Optional state.
	 * @return bool
	 */
	public static function validate_ownership( $fencing_token, $state = null ) {
		$state = is_array( $state ) ? self::normalize_state( $state ) : self::get_state();
		$valid = is_array( $state )
			&& 'running' === $state['status']
			&& ! self::is_stale( $state )
			&& hash_equals( (string) $state['fencing_token'], (string) $fencing_token );

		return (bool) apply_filters( 'wp_root_guard_scan_queue_validate_ownership', $valid, $state, (string) $fencing_token );
	}

	/**
	 * Refresh the lease without advancing the cursor.
	 *
	 * @param string $fencing_token Caller token.
	 * @param int    $lease_seconds Lease duration.
	 * @return array|WP_Error Updated state or error.
	 */
	public static function heartbeat( $fencing_token, $lease_seconds = self::DEFAULT_LEASE_SECONDS ) {
		$state = self::get_state();
		if ( ! self::validate_ownership( $fencing_token, $state ) ) {
			return new \WP_Error( 'scan_queue_not_owner', __( 'Lease pemindaian tidak valid atau sudah kedaluwarsa.', 'wp-root-guard' ) );
		}

		$now = time();
		$state['heartbeat']     = $now;
		$state['lease_expires'] = $now + self::normalize_int( $lease_seconds, self::DEFAULT_LEASE_SECONDS, 60, 3600 );
		$state['updated_at']    = $now;

		return self::save_owned_state( $state, $fencing_token );
	}

	/**
	 * Persist the next batch checkpoint after ownership validation.
	 *
	 * @param string $fencing_token Caller token.
	 * @param array  $batch Batch fields to merge into state.
	 * @return array|WP_Error Updated state or error.
	 */
	public static function update_next_batch( $fencing_token, $batch = array() ) {
		$state = self::get_state();
		if ( ! self::validate_ownership( $fencing_token, $state ) ) {
			return new \WP_Error( 'scan_queue_not_owner', __( 'Lease pemindaian tidak valid atau sudah kedaluwarsa.', 'wp-root-guard' ) );
		}

		$allowed = array( 'scope', 'scope_index', 'cursor', 'batch_number', 'processed', 'total', 'status', 'errors', 'findings_summary' );
		foreach ( $allowed as $key ) {
			if ( array_key_exists( $key, $batch ) ) {
				$state[ $key ] = $batch[ $key ];
			}
		}

		$state['batch_number'] = max( $state['batch_number'], self::normalize_int( $state['batch_number'], 0, 0, PHP_INT_MAX ) );
		$state['processed']    = self::normalize_int( $state['processed'], 0, 0, PHP_INT_MAX );
		$state['total']        = self::normalize_int( $state['total'], 0, 0, PHP_INT_MAX );
		$state['heartbeat']    = time();
		$state['lease_expires'] = $state['heartbeat'] + self::DEFAULT_LEASE_SECONDS;
		$state['updated_at']    = $state['heartbeat'];

		return self::save_owned_state( self::normalize_state( $state ), $fencing_token );
	}

	/**
	 * Mark a run as terminal after validating ownership.
	 *
	 * @param string $fencing_token Caller token.
	 * @param string $status Terminal status.
	 * @param array  $args Optional errors and summary.
	 * @return array|WP_Error Updated state or error.
	 */
	public static function finish( $fencing_token, $status = 'completed', $args = array() ) {
		if ( ! in_array( $status, array( 'completed', 'failed', 'cancelled' ), true ) ) {
			return new \WP_Error( 'scan_queue_invalid_status', __( 'Status akhir pemindaian tidak valid.', 'wp-root-guard' ) );
		}

		$batch             = array( 'status' => $status );
		$batch['errors']   = isset( $args['errors'] ) ? $args['errors'] : array();
		$batch['findings_summary'] = isset( $args['findings_summary'] ) ? $args['findings_summary'] : array();
		$result = self::update_next_batch( $fencing_token, $batch );
		if ( is_wp_error( $result ) ) {
			return $result;
		}

		$result['lease_expires'] = 0;
		$result['updated_at']    = time();
		return self::save_owned_state( self::normalize_state( $result ), $fencing_token, true );
	}

	/**
	 * Remove terminal or stale state after the retention period.
	 *
	 * @param int  $max_age Minimum age in seconds.
	 * @param bool $force Remove any non-running state regardless of age.
	 * @return bool True when removed or no state exists.
	 */
	public static function cleanup( $max_age = 604800, $force = false ) {
		$state = self::get_state();
		if ( ! $state ) {
			return true;
		}

		$age = time() - max( $state['updated_at'], $state['created_at'] );
		$removable = $force || ( 'running' !== $state['status'] && $age >= max( 3600, (int) $max_age ) );
		if ( ! $removable && self::is_stale( $state ) && $age >= max( 3600, (int) $max_age ) ) {
			$removable = true;
		}

		return $removable ? (bool) delete_option( self::OPTION_NAME ) : true;
	}

	/**
	 * Save state only when the current fencing token still matches.
	 *
	 * @param array  $state Normalized state.
	 * @param string $fencing_token Caller token.
	 * @param bool   $terminal Whether a terminal state is being saved.
	 * @return array|WP_Error
	 */
	private static function save_owned_state( $state, $fencing_token, $terminal = false ) {
		$current = self::get_state();
		if ( ! $current || ! hash_equals( (string) $current['fencing_token'], (string) $fencing_token ) || ( ! $terminal && self::is_stale( $current ) ) ) {
			return new \WP_Error( 'scan_queue_fenced', __( 'State pemindaian ditolak karena fencing token berubah.', 'wp-root-guard' ) );
		}

		return self::persist( self::normalize_state( $state ), true ) ? self::normalize_state( $state ) : new \WP_Error( 'scan_queue_save_failed', __( 'Checkpoint pemindaian tidak dapat disimpan.', 'wp-root-guard' ) );
	}

	/**
	 * Persist using a non-autoloaded option.
	 *
	 * @param array $state State to persist.
	 * @param bool  $must_exist Require an existing option.
	 * @return bool
	 */
	private static function persist( $state, $must_exist ) {
		$state = self::normalize_state( $state );
		$state = apply_filters( 'wp_root_guard_scan_queue_before_save', $state, $must_exist );
		if ( ! is_array( $state ) ) {
			return false;
		}

		if ( $must_exist && false === get_option( self::OPTION_NAME, false ) ) {
			return false;
		}

		$option_saved = $must_exist
			? (bool) update_option( self::OPTION_NAME, $state, false )
			: (bool) add_option( self::OPTION_NAME, $state, '', 'no' );

		// Keep the option only as a small backwards-compatible dashboard cache.
		// The authoritative operational checkpoint is the custom table.
		$table_saved = class_exists( __NAMESPACE__ . '\\ScanStore' ) && ScanStore::save_run( $state );
		return $option_saved || ( $must_exist && is_array( get_option( self::OPTION_NAME, null ) ) ) || $table_saved;
	}

	/**
	 * Normalize untrusted persisted or caller-provided state.
	 *
	 * @param array $state Raw state.
	 * @param int   $lease_seconds Lease fallback.
	 * @return array
	 */
	private static function normalize_state( $state, $lease_seconds = self::DEFAULT_LEASE_SECONDS ) {
		$state = is_array( $state ) ? $state : array();
		$now   = time();
		$state = array(
			'schema_version'   => self::SCHEMA_VERSION,
			'run_id'           => self::bounded_token( isset( $state['run_id'] ) ? $state['run_id'] : self::new_id(), self::new_id() ),
			'fencing_token'    => self::bounded_token( isset( $state['fencing_token'] ) ? $state['fencing_token'] : self::new_token(), self::new_token() ),
			'scope'            => sanitize_key( isset( $state['scope'] ) ? $state['scope'] : 'root' ),
			'scope_index'      => self::normalize_int( isset( $state['scope_index'] ) ? $state['scope_index'] : 0, 0, 0, PHP_INT_MAX ),
			'cursor'           => self::bounded_string( isset( $state['cursor'] ) ? $state['cursor'] : '', self::MAX_CURSOR_LENGTH ),
			'batch_number'     => self::normalize_int( isset( $state['batch_number'] ) ? $state['batch_number'] : 0, 0, 0, PHP_INT_MAX ),
			'processed'        => self::normalize_int( isset( $state['processed'] ) ? $state['processed'] : 0, 0, 0, PHP_INT_MAX ),
			'total'            => self::normalize_int( isset( $state['total'] ) ? $state['total'] : 0, 0, 0, PHP_INT_MAX ),
			'snapshot_time'    => self::bounded_string( isset( $state['snapshot_time'] ) ? $state['snapshot_time'] : gmdate( 'c', $now ), 40 ),
			'status'           => self::normalize_status( isset( $state['status'] ) ? $state['status'] : 'running' ),
			'heartbeat'        => self::normalize_int( isset( $state['heartbeat'] ) ? $state['heartbeat'] : $now, $now, 0, PHP_INT_MAX ),
			'lease_expires'    => self::normalize_int( isset( $state['lease_expires'] ) ? $state['lease_expires'] : ( $now + $lease_seconds ), $now + $lease_seconds, 0, PHP_INT_MAX ),
			'errors'           => self::normalize_errors( isset( $state['errors'] ) ? $state['errors'] : array() ),
			'findings_summary' => self::normalize_findings_summary( isset( $state['findings_summary'] ) ? $state['findings_summary'] : array() ),
			'context'          => self::bounded_string( isset( $state['context'] ) ? $state['context'] : 'unknown', 40 ),
			'created_at'       => self::normalize_int( isset( $state['created_at'] ) ? $state['created_at'] : $now, $now, 0, PHP_INT_MAX ),
			'updated_at'       => self::normalize_int( isset( $state['updated_at'] ) ? $state['updated_at'] : $now, $now, 0, PHP_INT_MAX ),
		);

		return $state;
	}

	/**
	 * Normalize a bounded finding summary without retaining file content.
	 *
	 * @param mixed $summary Raw summary.
	 * @return array
	 */
	private static function normalize_findings_summary( $summary ) {
		if ( ! is_array( $summary ) ) {
			return array();
		}

		$normalized = array();
		foreach ( $summary as $key => $value ) {
			if ( count( $normalized ) >= self::MAX_FINDING_TYPES ) {
				break;
			}
			$key = sanitize_key( $key );
			if ( '' !== $key ) {
				$normalized[ $key ] = self::normalize_int( $value, 0, 0, PHP_INT_MAX );
			}
		}

		return $normalized;
	}

	/**
	 * Normalize bounded error messages.

	 * @param mixed $errors Raw errors.
	 * @return array
	 */
	private static function normalize_errors( $errors ) {
		if ( ! is_array( $errors ) ) {
			$errors = array( $errors );
		}

		$normalized = array();
		foreach ( $errors as $error ) {
			if ( count( $normalized ) >= self::MAX_ERRORS ) {
				break;
			}
			$error = self::bounded_string( is_scalar( $error ) ? $error : wp_json_encode( $error ), 500 );
			if ( '' !== $error ) {
				$normalized[] = $error;
			}
		}

		return $normalized;
	}

	/**
	 * @param mixed $value Value.
	 * @param int   $fallback Fallback.
	 * @param int   $minimum Minimum.
	 * @param int   $maximum Maximum.
	 * @return int
	 */
	private static function normalize_int( $value, $fallback, $minimum, $maximum ) {
		$value = filter_var( $value, FILTER_VALIDATE_INT );
		return false === $value ? (int) $fallback : max( $minimum, min( $maximum, (int) $value ) );
	}

	/**
	 * @param mixed $value Value.
	 * @param int   $length Maximum length.
	 * @return string
	 */
	private static function bounded_string( $value, $length ) {
		$value = is_scalar( $value ) ? (string) $value : '';
		return substr( sanitize_text_field( $value ), 0, $length );
	}

	/**
	 * @param mixed  $value Candidate token.
	 * @param string $fallback Fallback token.
	 * @return string
	 */
	private static function bounded_token( $value, $fallback ) {
		$value = self::bounded_string( $value, 128 );
		return '' === $value ? $fallback : $value;
	}

	/**
	 * @param mixed $status Candidate status.
	 * @return string
	 */
	private static function normalize_status( $status ) {
		$status = sanitize_key( $status );
		return in_array( $status, self::STATES, true ) ? $status : 'running';
	}

	/**
	 * @return string
	 */
	private static function new_id() {
		return function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : uniqid( 'scan-', true );
	}

	/**
	 * @return string
	 */
	private static function new_token() {
		return function_exists( 'wp_generate_password' ) ? wp_generate_password( 64, false, false ) : bin2hex( random_bytes( 32 ) );
	}
}
