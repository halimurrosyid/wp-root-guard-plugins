<?php
/**
 * Kontrak hasil pemindaian WP Root Guard.
 *
 * Class ini menjaga agar status keamanan, coverage, dan eksekusi scan tidak
 * tercampur. Hasil dengan ancaman tetap berstatus threat walaupun sebagian
 * scope gagal dipindai (coverage degraded/failed).
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
 * Value/helper class untuk hasil scan yang konsisten.
 *
 * Class ini sengaja tidak menyimpan state internal. Array hasil dapat dipakai
 * oleh scanner, cron, AJAX, dan dashboard tanpa memerlukan instance object.
 *
 * @package WPRootGuard
 * @since   3.3.0
 */
final class ScanResult {

	/** Status keamanan: tidak ada ancaman dan seluruh scope tervalidasi. */
	const SECURITY_SAFE = 'safe';

	/** Status keamanan: satu atau lebih ancaman ditemukan. */
	const SECURITY_THREAT = 'threat';

	/** Status keamanan: verifikasi awal atau hasil scan belum selesai. */
	const SECURITY_PENDING = 'pending';

	/** Coverage lengkap tanpa error atau scope yang dilewati. */
	const COVERAGE_COMPLETE = 'complete';

	/** Coverage selesai sebagian atau terdapat scope/file yang tidak tervalidasi. */
	const COVERAGE_DEGRADED = 'degraded';

	/** Coverage gagal sehingga hasil tidak dapat dianggap lengkap. */
	const COVERAGE_FAILED = 'failed';

	/** Scan sedang berjalan. */
	const EXECUTION_RUNNING = 'running';

	/** Scan selesai. */
	const EXECUTION_COMPLETED = 'completed';

	/** Scan gagal menghasilkan hasil yang valid. */
	const EXECUTION_FAILED = 'failed';

	/** Scan ditunda dan harus dilanjutkan oleh pemicu berikutnya. */
	const EXECUTION_DEFERRED = 'deferred';

	/**
	 * Menghasilkan struktur hasil scan default.
	 *
	 * @return array Struktur hasil scan yang belum menemukan threat.
	 */
	public static function defaults() {
		return array(
			'run_id'          => '',
			'security_status' => self::SECURITY_PENDING,
			'coverage_status' => self::COVERAGE_DEGRADED,
			'execution_state' => self::EXECUTION_RUNNING,
			'coverage'        => array(),
			'errors'          => array(),
			'skipped'         => array(),
			'threats'         => array(),
			'threat_count'    => 0,
			'processed'       => 0,
			'started_at'      => '',
			'completed_at'    => '',
			'last_heartbeat'  => '',
		);
	}

	/**
	 * Menormalisasi hasil lama/parsial ke kontrak hasil scan baru.
	 *
	 * Kompatibilitas dengan format lama dipertahankan untuk key `status` dan
	 * `state`; keduanya dipetakan ke key P0.1 tanpa menganggap hasil parsial aman.
	 *
	 * @param mixed $result Hasil scan parsial atau hasil tersimpan sebelumnya.
	 * @return array Hasil scan yang sudah dinormalisasi.
	 */
	public static function normalize( $result = array() ) {
		if ( ! is_array( $result ) ) {
			$result = array();
		}

		$normalized = self::defaults();
		$normalized = array_merge( $normalized, $result );

		if ( empty( $result['security_status'] ) && isset( $result['status'] ) ) {
			$normalized['security_status'] = self::normalize_security_status( $result['status'] );
		}

		if ( empty( $result['execution_state'] ) && isset( $result['state'] ) ) {
			$normalized['execution_state'] = self::normalize_execution_state( $result['state'] );
		}

		$normalized['security_status'] = self::normalize_security_status( $normalized['security_status'] );
		$normalized['coverage_status'] = self::normalize_coverage_status( $normalized['coverage_status'] );
		$normalized['execution_state'] = self::normalize_execution_state( $normalized['execution_state'] );

		foreach ( array( 'coverage', 'errors', 'skipped', 'threats' ) as $key ) {
			if ( ! is_array( $normalized[ $key ] ) ) {
				$normalized[ $key ] = array();
			}
		}

		$normalized['threat_count'] = max( 0, (int) $normalized['threat_count'] );
		$normalized['processed']    = max( 0, (int) $normalized['processed'] );

		// Threat selalu mengalahkan status keamanan parsial agar tidak menjadi safe.
		if ( ! empty( $normalized['threats'] ) || $normalized['threat_count'] > 0 ) {
			$normalized['security_status'] = self::SECURITY_THREAT;
		}

		// Alias untuk consumer lama, tanpa menghilangkan kontrak baru.
		$normalized['status'] = $normalized['security_status'];
		$normalized['state']  = $normalized['execution_state'];

		return $normalized;
	}

	/**
	 * Menggabungkan beberapa hasil parsial tanpa menurunkan severity.
	 *
	 * Array coverage, error, skipped, dan threats digabungkan dengan deduplikasi
	 * berbasis representasi serialized. Counter threat/processed memakai nilai
	 * terbesar agar penggabungan checkpoint tidak menggandakan hitungan batch.
	 *
	 * @param array ...$results Hasil scan parsial.
	 * @return array Hasil gabungan yang sudah dinormalisasi.
	 */
	public static function merge( ...$results ) {
		if ( empty( $results ) ) {
			return self::defaults();
		}

		$merged = self::normalize( array_shift( $results ) );

		foreach ( $results as $result ) {
			$current = self::normalize( $result );

			$merged['run_id']         = $current['run_id'] ?: $merged['run_id'];
			$merged['security_status'] = self::more_severe_security_status( $merged['security_status'], $current['security_status'] );
			$merged['coverage_status'] = self::more_severe_coverage_status( $merged['coverage_status'], $current['coverage_status'] );
			$merged['execution_state'] = self::more_severe_execution_state( $merged['execution_state'], $current['execution_state'] );
			$merged['coverage']         = self::merge_arrays( $merged['coverage'], $current['coverage'] );
			$merged['errors']           = self::merge_arrays( $merged['errors'], $current['errors'] );
			$merged['skipped']          = self::merge_arrays( $merged['skipped'], $current['skipped'] );
			$merged['threats']          = self::merge_arrays( $merged['threats'], $current['threats'] );
			$merged['threat_count']     = max( $merged['threat_count'], $current['threat_count'] );
			$merged['processed']        = max( $merged['processed'], $current['processed'] );
			$merged['started_at']       = $merged['started_at'] ?: $current['started_at'];
			$merged['completed_at']     = $current['completed_at'] ?: $merged['completed_at'];
			$merged['last_heartbeat']   = $current['last_heartbeat'] ?: $merged['last_heartbeat'];
		}

		return self::normalize( $merged );
	}

	/**
	 * Menentukan status ringkas yang aman untuk ditampilkan di dashboard.
	 *
	 * Threat selalu memiliki prioritas tertinggi. Dengan demikian kombinasi
	 * threat + coverage degraded tetap menghasilkan `threat`, sementara detail
	 * coverage tetap tersedia pada hasil normalisasi untuk ditampilkan sebagai
	 * peringatan tambahan.
	 *
	 * @param mixed $result Hasil scan.
	 * @return string Kode status dashboard.
	 */
	public static function dashboard_status( $result = array() ) {
		$result = self::normalize( $result );

		if ( self::SECURITY_THREAT === $result['security_status'] ) {
			return self::SECURITY_THREAT;
		}

		if ( self::COVERAGE_FAILED === $result['coverage_status'] ) {
			return self::EXECUTION_FAILED;
		}

		if ( self::COVERAGE_DEGRADED === $result['coverage_status'] ) {
			return self::COVERAGE_DEGRADED;
		}

		if ( self::SECURITY_PENDING === $result['security_status'] ) {
			return self::SECURITY_PENDING;
		}

		if ( self::EXECUTION_RUNNING === $result['execution_state'] ) {
			return self::EXECUTION_RUNNING;
		}

		if ( self::EXECUTION_DEFERRED === $result['execution_state'] ) {
			return self::SECURITY_PENDING;
		}

		return self::SECURITY_SAFE;
	}

	/**
	 * Alias eksplisit untuk consumer yang memakai istilah get_*.
	 *
	 * @param mixed $result Hasil scan.
	 * @return string Kode status dashboard.
	 */
	public static function get_dashboard_status( $result = array() ) {
		return self::dashboard_status( $result );
	}

	/**
	 * Mengembalikan prioritas status keamanan yang lebih berat.
	 *
	 * @param string $left  Status pertama.
	 * @param string $right Status kedua.
	 * @return string Status dengan severity lebih tinggi.
	 */
	private static function more_severe_security_status( $left, $right ) {
		$priority = array(
			self::SECURITY_SAFE    => 0,
			self::SECURITY_PENDING => 1,
			self::SECURITY_THREAT  => 2,
		);

		return ( $priority[ $right ] ?? 1 ) > ( $priority[ $left ] ?? 1 ) ? $right : $left;
	}

	/**
	 * Mengembalikan prioritas coverage yang lebih berat.
	 *
	 * @param string $left  Status pertama.
	 * @param string $right Status kedua.
	 * @return string Status coverage dengan severity lebih tinggi.
	 */
	private static function more_severe_coverage_status( $left, $right ) {
		$priority = array(
			self::COVERAGE_COMPLETE => 0,
			self::COVERAGE_DEGRADED => 1,
			self::COVERAGE_FAILED   => 2,
		);

		return ( $priority[ $right ] ?? 1 ) > ( $priority[ $left ] ?? 1 ) ? $right : $left;
	}

	/**
	 * Mengembalikan state eksekusi yang paling konservatif.
	 *
	 * @param string $left  State pertama.
	 * @param string $right State kedua.
	 * @return string State dengan severity lebih tinggi.
	 */
	private static function more_severe_execution_state( $left, $right ) {
		$priority = array(
			self::EXECUTION_COMPLETED => 0,
			self::EXECUTION_DEFERRED  => 1,
			self::EXECUTION_RUNNING   => 2,
			self::EXECUTION_FAILED    => 3,
		);

		return ( $priority[ $right ] ?? 2 ) > ( $priority[ $left ] ?? 2 ) ? $right : $left;
	}

	/**
	 * Menormalkan status keamanan.
	 *
	 * @param mixed $status Status input.
	 * @return string Status valid.
	 */
	private static function normalize_security_status( $status ) {
		$status = strtolower( trim( (string) $status ) );
		return in_array( $status, array( self::SECURITY_SAFE, self::SECURITY_THREAT, self::SECURITY_PENDING ), true )
			? $status
			: self::SECURITY_PENDING;
	}

	/**
	 * Menormalkan status coverage.
	 *
	 * @param mixed $status Status input.
	 * @return string Status valid.
	 */
	private static function normalize_coverage_status( $status ) {
		$status = strtolower( trim( (string) $status ) );
		return in_array( $status, array( self::COVERAGE_COMPLETE, self::COVERAGE_DEGRADED, self::COVERAGE_FAILED ), true )
			? $status
			: self::COVERAGE_DEGRADED;
	}

	/**
	 * Menormalkan state eksekusi.
	 *
	 * @param mixed $state State input.
	 * @return string State valid.
	 */
	private static function normalize_execution_state( $state ) {
		$state = strtolower( trim( (string) $state ) );
		return in_array( $state, array( self::EXECUTION_RUNNING, self::EXECUTION_COMPLETED, self::EXECUTION_FAILED, self::EXECUTION_DEFERRED ), true )
			? $state
			: self::EXECUTION_RUNNING;
	}

	/**
	 * Menggabungkan array dengan deduplikasi konservatif.
	 *
	 * @param array $left  Array pertama.
	 * @param array $right Array kedua.
	 * @return array Array gabungan.
	 */
	private static function merge_arrays( array $left, array $right ) {
		$merged = array_merge( $left, $right );
		$unique = array();

		foreach ( $merged as $item ) {
			$key = is_scalar( $item ) ? (string) $item : wp_json_encode( $item );
			if ( false === $key ) {
				$key = serialize( $item );
			}
			$unique[ $key ] = $item;
		}

		return array_values( $unique );
	}
}
