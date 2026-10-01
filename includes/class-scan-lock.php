<?php
/**
 * Lease lock untuk memastikan hanya satu pemindaian aktif per site.
 *
 * Lock ini sengaja berdiri sendiri agar dapat digunakan oleh Cron, traffic
 * fallback, AJAX, dan pemindaian manual tanpa coupling ke Scanner.
 *
 * @package WPRootGuard
 * @since   3.3.0
 */

namespace WPRootGuard;

// Mencegah akses langsung ke file.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class ScanLock
 *
 * Mengelola satu lease lock pemindaian per site menggunakan Options API.
 *
 * Akuisisi pertama menggunakan add_option(), yang bersifat atomic pada
 * database WordPress sehingga dua request yang sama-sama melihat lock kosong
 * tidak dapat menjadi owner secara bersamaan. Pengambilalihan lock stale,
 * refresh, dan release memakai conditional SQL berdasarkan serialisasi state
 * yang diharapkan. Ini menghindari pola delete-then-add yang membuka race
 * window.
 *
 * Options API tidak menyediakan compare-and-swap lintas semua object cache.
 * Karena itu conditional query dan invalidasi cache dipakai sebagai batas
 * konsistensi terbaik untuk single-site WordPress. Pemanggil tetap harus
 * memeriksa nilai boolean dari refresh/release dan tidak menganggap lease
 * masih valid setelah operasi tersebut gagal.
 *
 * @package WPRootGuard
 * @since   3.3.0
 */
class ScanLock {

	/**
	 * Option yang menyimpan state lock site saat ini.
	 */
	const OPTION_KEY = 'wp_root_guard_scan_lock';

	/**
	 * Durasi lease default dalam detik.
	 */
	const DEFAULT_LEASE_SECONDS = 900;

	/**
	 * Batas minimum lease untuk mencegah konfigurasi tidak berguna.
	 */
	const MIN_LEASE_SECONDS = 30;

	/**
	 * Batas maksimum lease agar lock stale tidak bertahan tanpa batas.
	 */
	const MAX_LEASE_SECONDS = 86400;

	/**
	 * Durasi lease instance ini.

	 * @var int
	 */
	private $lease_seconds;

	/**
	 * Konstruktor.
	 *
	 * @param int $lease_seconds Durasi lease dalam detik.
	 */
	public function __construct( $lease_seconds = self::DEFAULT_LEASE_SECONDS ) {
		$this->lease_seconds = min(
			self::MAX_LEASE_SECONDS,
			max( self::MIN_LEASE_SECONDS, absint( $lease_seconds ) )
		);
	}

	/**
	 * Mendapatkan durasi lease instance.
	 *
	 * @return int Durasi lease dalam detik.
	 */
	public function get_lease_seconds() {
		return $this->lease_seconds;
	}

	/**
	 * Mencoba memperoleh lock baru atau mengambil alih lock stale.
	 *
	 * @param string $context Sumber pemindaian, misalnya cron, traffic, ajax.
	 * @return array|false Structured lock state jika berhasil, false jika busy.
	 */
	public function acquire( $context = 'unknown' ) {
		$now   = time();
		$state = $this->get_state();

		if ( $state && ! $this->is_stale( $state ) ) {
			return false;
		}

		$new_state = $this->new_state( $context, $now );

		// add_option() gagal secara atomic ketika request lain sudah membuat key.
		if ( ! $state ) {
			if ( add_option( self::OPTION_KEY, $this->state_for_storage( $new_state ), '', 'no' ) ) {
				return $new_state;
			}

			return false;
		}

		// Lock stale diambil alih dengan compare-and-swap, bukan delete-then-add.
		if ( $this->compare_and_swap( $state, $new_state ) ) {
			return $new_state;
		}

		return false;
	}

	/**
	 * Memperbarui heartbeat dan memperpanjang lease owner.
	 *
	 * @param string $run_id        ID run yang memperoleh lock.
	 * @param string $fencing_token Token owner saat lock diperoleh.
	 * @return array|false State baru jika berhasil, false jika bukan owner/stale.
	 */
	public function refresh( $run_id, $fencing_token ) {
		$state = $this->get_state();

		if ( ! $this->matches_owner( $state, $run_id, $fencing_token ) || $this->is_stale( $state ) ) {
			return false;
		}

		$now       = time();
		$new_state = $state;
		$new_state['heartbeat_at'] = $now;
		$new_state['expires_at']   = $now + $this->lease_seconds;
		$new_state['status']       = 'active';

		return $this->compare_and_swap( $state, $new_state ) ? $new_state : false;
	}

	/**
	 * Melepaskan lock jika credential cocok dengan owner.
	 *
	 * Conditional delete memastikan owner lama tidak dapat menghapus lock baru
	 * setelah lease-nya diambil alih oleh request lain.
	 *
	 * @param string $run_id        ID run owner.
	 * @param string $fencing_token Token owner.
	 * @return bool True jika lock berhasil dilepas.
	 */
	public function release( $run_id, $fencing_token ) {
		$state = $this->get_state();

		if ( ! $this->matches_owner( $state, $run_id, $fencing_token ) ) {
			return false;
		}

		return $this->compare_and_delete( $state );
	}

	/**
	 * Memeriksa apakah credential masih menjadi owner lease aktif.
	 *
	 * @param string $run_id        ID run owner.
	 * @param string $fencing_token Token owner.
	 * @return bool True jika credential cocok dan lease belum stale.
	 */
	public function is_owner( $run_id, $fencing_token ) {
		$state = $this->get_state();

		return $this->matches_owner( $state, $run_id, $fencing_token ) && ! $this->is_stale( $state );
	}

	/**
	 * Memeriksa apakah state sudah melewati waktu expiry.
	 *
	 * State kosong atau malformed dianggap stale agar fail closed.
	 *
	 * @param array|null $state State tertentu; null membaca state database.
	 * @return bool True jika lock tidak ada, malformed, atau sudah expired.
	 */
	public function is_stale( $state = null ) {
		if ( null === $state ) {
			$state = $this->get_state();
		}

		return ! is_array( $state ) || empty( $state['expires_at'] ) || (int) $state['expires_at'] <= time();
	}

	/**
	 * Mengambil structured state lock saat ini.
	 *
	 * @return array|null State lock dengan status active/stale, atau null.
	 */
	public function get_state() {
		$state = get_option( self::OPTION_KEY, false );

		if ( ! is_array( $state ) || empty( $state['run_id'] ) || empty( $state['fencing_token'] ) ) {
			return null;
		}

		$state['status'] = $this->is_stale_without_read( $state ) ? 'stale' : 'active';

		return $state;
	}

	/**
	 * Membuat state lock baru.
	 *
	 * @param string $context Context sumber scan.
	 * @param int    $now     Unix timestamp saat lock dibuat.
	 * @return array State lock baru.
	 */
	private function new_state( $context, $now ) {
		$run_id = function_exists( 'wp_generate_uuid4' ) ? wp_generate_uuid4() : uniqid( 'wp-root-guard-', true );

		try {
			$fencing_token = bin2hex( random_bytes( 32 ) );
		} catch ( \Throwable $exception ) {
			$fencing_token = function_exists( 'wp_generate_password' )
				? wp_generate_password( 64, true, true )
				: hash( 'sha256', uniqid( 'wp-root-guard-', true ) . microtime( true ) );
		}

		return array(
			'run_id'        => sanitize_text_field( (string) $run_id ),
			'context'       => sanitize_key( (string) $context ) ?: 'unknown',
			'fencing_token' => sanitize_text_field( (string) $fencing_token ),
			'acquired_at'   => (int) $now,
			'heartbeat_at'  => (int) $now,
			'expires_at'    => (int) ( $now + $this->lease_seconds ),
			'lease_seconds' => (int) $this->lease_seconds,
			'status'        => 'active',
		);
	}

	/**
	 * Membandingkan credential dengan state owner.
	 *
	 * @param array|null $state        State lock.
	 * @param string     $run_id       Run ID.
	 * @param string     $fencing_token Fencing token.
	 * @return bool True jika kedua credential cocok.
	 */
	private function matches_owner( $state, $run_id, $fencing_token ) {
		return is_array( $state )
			&& isset( $state['run_id'], $state['fencing_token'] )
			&& hash_equals( (string) $state['run_id'], (string) $run_id )
			&& hash_equals( (string) $state['fencing_token'], (string) $fencing_token );
	}

	/**
	 * Compare-and-swap state pada row option yang sama.
	 *
	 * @param array $expected State yang sebelumnya dibaca.
	 * @param array $replacement State pengganti.
	 * @return bool True jika tepat satu row berhasil diubah.
	 */
	private function compare_and_swap( $expected, $replacement ) {
		global $wpdb;

		if ( ! isset( $wpdb->options ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return false;
		}

		$old_value = maybe_serialize( $this->state_for_storage( $expected ) );
		$new_value = maybe_serialize( $this->state_for_storage( $replacement ) );
		$query     = $wpdb->prepare(
			"UPDATE {$wpdb->options} SET option_value = %s, autoload = 'no' WHERE option_name = %s AND option_value = %s LIMIT 1",
			$new_value,
			self::OPTION_KEY,
			$old_value
		);
		$updated   = 1 === (int) $wpdb->query( $query );

		if ( $updated ) {
			$this->invalidate_option_cache();
		}

		return $updated;
	}

	/**
	 * Conditional delete state owner.
	 *
	 * @param array $expected State owner yang diharapkan.
	 * @return bool True jika tepat satu row dihapus.
	 */
	private function compare_and_delete( $expected ) {
		global $wpdb;

		if ( ! isset( $wpdb->options ) || ! method_exists( $wpdb, 'prepare' ) ) {
			return false;
		}

		$query   = $wpdb->prepare(
			"DELETE FROM {$wpdb->options} WHERE option_name = %s AND option_value = %s LIMIT 1",
			self::OPTION_KEY,
			maybe_serialize( $this->state_for_storage( $expected ) )
		);
		$deleted = 1 === (int) $wpdb->query( $query );

		if ( $deleted ) {
			$this->invalidate_option_cache();
		}

		return $deleted;
	}

	/**
	 * Menghapus field turunan sebelum state dibandingkan dengan database.
	 *
	 * Status active/stale dihitung saat dibaca dan tidak disimpan sebagai bagian
	 * dari nilai canonical option. Hal ini menjaga compare-and-swap tetap cocok
	 * walaupun state menjadi stale setelah option terakhir ditulis.
	 *
	 * @param array $state State lock.
	 * @return array State canonical untuk penyimpanan.
	 */
	private function state_for_storage( $state ) {
		unset( $state['status'] );

		return $state;
	}

	/**
	 * Mengecek expiry tanpa membaca option lagi.
	 *
	 * @param array $state State lock.
	 * @return bool True jika stale.
	 */
	private function is_stale_without_read( $state ) {
		return empty( $state['expires_at'] ) || (int) $state['expires_at'] <= time();
	}

	/**
	 * Menghapus cache option setelah query langsung ke database.
	 *
	 * @return void
	 */
	private function invalidate_option_cache() {
		if ( function_exists( 'wp_cache_delete' ) ) {
			wp_cache_delete( self::OPTION_KEY, 'options' );
		}
	}
}
