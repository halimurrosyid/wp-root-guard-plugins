<?php
/**
 * Pengelola penjadwalan WP-Cron untuk pemindaian berkala dan pembersihan IP.
 *
 * Berkas ini berisi class Cron yang bertanggung jawab untuk:
 * 1. Menambahkan interval kustom ke WP-Cron (5 menit, 15 menit, 30 menit).
 * 2. Menjadwalkan dan membatalkan cron event pemindaian dan prune IP secara idempoten.
 * 3. Menangani callback eksekusi pemindaian latar belakang (background scan).
 * 4. Menangani penjadwalan ulang saat interval scan diubah di pengaturan.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */

namespace WPRootGuard;

// Mencegah akses langsung ke file.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class Cron
 *
 * Mengelola penjadwalan WP-Cron, interval kustom, dan eksekusi tugas di latar belakang.
 *
 * @package WPRootGuard
 * @since   1.0.0
 */
class Cron {

	/**
	 * Nama hook cron untuk pemindaian root directory.
	 */
	const SCAN_HOOK = 'wp_root_guard_cron_scan';

	/**
	 * Nama hook cron untuk pembersihan IP terblokir yang telah kedaluwarsa.
	 */
	const PRUNE_HOOK = 'wp_root_guard_prune_ips';

	/** Single-event continuation for an interrupted or deferred scan. */
	const CONTINUE_HOOK = 'wp_root_guard_scan_continue';

	/**
	 * Nama option lock untuk fallback pemindaian berbasis traffic.
	 */
	const TRAFFIC_SCAN_LOCK_OPTION = 'wp_root_guard_traffic_scan_lock';

	/**
	 * Mendaftarkan filter dan action untuk WP-Cron.
	 *
	 * @return void
	 */
	public function init() {
		self::register_schedules();
		add_action( self::SCAN_HOOK, array( $this, 'run_background_scan' ) );
		add_action( self::PRUNE_HOOK, array( __CLASS__, 'run_prune_tasks' ) );
		add_action( self::CONTINUE_HOOK, array( $this, 'run_scan_continuation' ) );
		// Fallback dashboard-first: jika WP-Cron loopback tidak tersedia,
		// request website tetap dapat menjalankan scan yang sudah jatuh tempo.
		add_action( 'wp_loaded', array( __CLASS__, 'maybe_run_due_scan' ), 999 );

		// Activation hook berjalan sebelum plugins_loaded, sehingga interval kustom
		// mungkin belum terdaftar ketika schedule pertama dibuat. Pulihkan event
		// yang hilang pada request aktif berikutnya tanpa membuat duplikat.
		self::schedule_event();
	}

	/**
	 * Mendaftarkan interval kustom sebelum pemanggilan wp_schedule_event().
	 *
	 * Dipanggil juga saat activation hook karena Cron::init() belum berjalan
	 * ketika plugin pertama kali diaktifkan.
	 *
	 * @return void
	 */
	public static function register_schedules() {
		add_filter( 'cron_schedules', array( __CLASS__, 'add_cron_interval' ) );
	}

	/**
	 * Menambahkan interval kustom (5 menit, 15 menit, 30 menit) ke daftar jadwal cron WordPress.
	 *
	 * @param array $schedules Daftar jadwal cron saat ini.
	 * @return array Daftar jadwal cron setelah ditambah interval kustom.
	 */
	public static function add_cron_interval( $schedules ) {
		if ( ! is_array( $schedules ) ) {
			$schedules = array();
		}

		$schedules['every_5_minutes'] = array(
			'interval' => 300,
			'display'  => esc_html__( 'Setiap 5 Menit', 'wp-root-guard' ),
		);
		$schedules['every_15_minutes'] = array(
			'interval' => 900,
			'display'  => esc_html__( 'Setiap 15 Menit', 'wp-root-guard' ),
		);
		$schedules['every_30_minutes'] = array(
			'interval' => 1800,
			'display'  => esc_html__( 'Setiap 30 Menit', 'wp-root-guard' ),
		);

		return $schedules;
	}

	/**
	 * Menjadwalkan pemindaian otomatis dan pembersihan IP berdasarkan interval di pengaturan.
	 *
	 * Method ini bersifat idempoten; tidak akan membuat duplikat jadwal
	 * jika event sudah terdaftar di WP-Cron.
	 *
	 * @return bool True jika event tersedia atau berhasil dijadwalkan.
	 */
	public static function schedule_event() {
		self::register_schedules();

		$interval = 'every_5_minutes';
		if ( class_exists( __NAMESPACE__ . '\\Settings' ) ) {
			$settings = Settings::get_settings();
			if ( ! empty( $settings['scan_interval'] ) ) {
				$interval = $settings['scan_interval'];
			}
		}

		$schedules = wp_get_schedules();
		if ( ! isset( $schedules[ $interval ] ) ) {
			$interval = 'hourly';
		}

		$success = true;

		$scan_event = wp_get_scheduled_event( self::SCAN_HOOK );
		if ( ! $scan_event || $scan_event->schedule !== $interval ) {
			// Migrasikan event lama bertipe "single" atau interval lama
			// menjadi event recurring sesuai pengaturan aktif.
			if ( $scan_event ) {
				wp_clear_scheduled_hook( self::SCAN_HOOK );
			}

			$result = wp_schedule_event( time() + 60, $interval, self::SCAN_HOOK, array(), true );
			if ( is_wp_error( $result ) ) {
				$success = false;
				self::log_schedule_failure( self::SCAN_HOOK, $result->get_error_message() );
			}
		}

		$prune_event = wp_get_scheduled_event( self::PRUNE_HOOK );
		if ( ! $prune_event || $prune_event->schedule !== 'hourly' ) {
			if ( $prune_event ) {
				wp_clear_scheduled_hook( self::PRUNE_HOOK );
			}

			$result = wp_schedule_event( time() + 60, 'hourly', self::PRUNE_HOOK, array(), true );
			if ( is_wp_error( $result ) ) {
				$success = false;
				self::log_schedule_failure( self::PRUNE_HOOK, $result->get_error_message() );
			}
		}

		return $success;
	}

	/**
	 * Mengambil status scheduler untuk dashboard admin.
	 *
	 * @return array Status event, interval, overdue, dan konfigurasi WP-Cron.
	 */
	public static function get_schedule_status() {
		self::register_schedules();

		$settings = class_exists( __NAMESPACE__ . '\\Settings' ) ? Settings::get_settings() : array();
		$interval = ! empty( $settings['scan_interval'] ) ? sanitize_key( $settings['scan_interval'] ) : 'every_5_minutes';
		$schedules = wp_get_schedules();
		$interval_seconds = isset( $schedules[ $interval ]['interval'] ) ? (int) $schedules[ $interval ]['interval'] : 300;
		$event = wp_get_scheduled_event( self::SCAN_HOOK );
		$now = time();
		$lock = new ScanLock();
		$lock_state = $lock->get_state();
		$batch_run = class_exists( __NAMESPACE__ . '\\ScanBatchRunner' ) ? ScanBatchRunner::get_active_run() : array();
		$queue_state = ! empty( $batch_run ) ? $batch_run : ( class_exists( __NAMESPACE__ . '\\ScanQueue' ) ? ScanQueue::get_state() : array() );
		$server_guard = class_exists( __NAMESPACE__ . '\\ServerGuard' ) ? ServerGuard::get_status() : array();
		$quarantine = class_exists( __NAMESPACE__ . '\\QuarantineStorage' ) ? QuarantineStorage::resolve_directory() : array();

		return array(
			'hook'              => self::SCAN_HOOK,
			'configured_interval' => $interval,
			'interval_seconds'  => $interval_seconds,
			'scheduled'         => (bool) $event,
			'recurrence'        => $event ? (string) $event->schedule : '',
			'next_timestamp'    => $event ? (int) $event->timestamp : 0,
			'is_due'            => $event ? (int) $event->timestamp <= $now : false,
			'configuration_ok'  => (bool) ( $event && $event->schedule === $interval ),
			'cron_disabled'     => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
			'traffic_fallback'  => true,
			'lock_active'       => is_array( $lock_state ) && ! $lock->is_stale( $lock_state ),
			'lock_context'      => is_array( $lock_state ) && isset( $lock_state['context'] ) ? $lock_state['context'] : '',
			'queue_state'       => is_array( $queue_state ) && isset( $queue_state['status'] ) ? $queue_state['status'] : 'idle',
			'server_guard'      => is_array( $server_guard ) && isset( $server_guard['status'] ) ? $server_guard['status'] : 'unknown',
			'server_guard_family' => is_array( $server_guard ) && isset( $server_guard['server_family'] ) ? $server_guard['server_family'] : 'unknown',
			'quarantine_source' => is_array( $quarantine ) && isset( $quarantine['source'] ) ? $quarantine['source'] : 'none',
			'quarantine_ready'  => is_array( $quarantine ) && isset( $quarantine['status'] ) && 'ready' === $quarantine['status'],
		);
	}

	/** Run bounded maintenance associated with the hourly prune hook. */
	public static function run_prune_tasks() {
		if ( class_exists( __NAMESPACE__ . '\\Blocker' ) ) {
			Blocker::prune_expired_ips();
		}
		if ( class_exists( __NAMESPACE__ . '\\ScanStore' ) ) {
			ScanStore::cleanup_completed_runs( 7 );
		}
	}

	/**
	 * Menjalankan scan yang jatuh tempo dari request WordPress biasa.
	 *
	 * WP-Cron bukan daemon. Pada shared hosting atau Docker dengan loopback
	 * yang gagal, event tetap tersimpan tetapi tidak pernah dieksekusi. Fallback
	 * ini menjaga proteksi tetap berjalan ketika ada traffic tanpa memanggil
	 * wp-cron.php secara manual. Lock mencegah dua request menjalankan scan
	 * secara bersamaan.
	 *
	 * @return void
	 */
	public static function maybe_run_due_scan() {
		if ( wp_doing_cron() || wp_doing_ajax() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}

		$active = class_exists( __NAMESPACE__ . '\\ScanBatchRunner' ) ? ScanBatchRunner::get_active_run() : array();
		$has_active_run = ! empty( $active );
		if ( $has_active_run && ! empty( $active['next_retry_at'] ) && (int) $active['next_retry_at'] > time() ) {
			return;
		}
		$event = wp_get_scheduled_event( self::SCAN_HOOK );
		if ( ! $has_active_run && ( ! $event || (int) $event->timestamp > time() ) ) { return; }
		if ( $has_active_run && get_transient( 'wp_root_guard_traffic_batch_throttle' ) ) { return; }
		if ( $has_active_run ) { set_transient( 'wp_root_guard_traffic_batch_throttle', 1, 15 ); }

		// Scanner owns the only global lock. A second traffic-only lock used to
		// leave stale state after fatal errors and could suppress valid scans.
		$result = class_exists( __NAMESPACE__ . '\\Scanner' ) ? Scanner::perform_scan( 'traffic' ) : array();
		$failed = is_array( $result ) && isset( $result['status'] ) && 'failed' === $result['status'];
		if ( $event && (int) $event->timestamp <= time() ) { self::advance_scan_event( $event, $failed ? 60 : null ); }
	}

	/**
	 * Mengambil lock lintas-request dengan option database.
	 *
	 * @return bool True jika request ini menjadi pemilik lock.
	 */
	private static function acquire_traffic_scan_lock() {
		$now   = time();
		$lock  = get_option( self::TRAFFIC_SCAN_LOCK_OPTION, array() );
		$until = is_array( $lock ) && isset( $lock['until'] ) ? (int) $lock['until'] : 0;

		if ( $until > $now ) {
			return false;
		}

		if ( $until > 0 ) {
			delete_option( self::TRAFFIC_SCAN_LOCK_OPTION );
		}

		return add_option(
			self::TRAFFIC_SCAN_LOCK_OPTION,
			array(
				'run_id' => wp_generate_uuid4(),
				'until'  => $now + 900,
			),
			'',
			'no'
		);
	}

	/**
	 * Melepaskan lock fallback traffic.
	 *
	 * @return void
	 */
	private static function release_traffic_scan_lock() {
		delete_option( self::TRAFFIC_SCAN_LOCK_OPTION );
	}

	/** Schedule one bounded retry; duplicate events are never created. */
	public static function schedule_scan_continuation( $delay = 30 ) {
		if ( ! wp_next_scheduled( self::CONTINUE_HOOK ) ) {
			wp_schedule_single_event( time() + max( 15, (int) $delay ), self::CONTINUE_HOOK, array(), true );
		}
	}

	/** Continue a deferred run through the same global scanner lock. */
	public function run_scan_continuation() {
		if ( class_exists( __NAMESPACE__ . '\\Scanner' ) ) {
			$result = Scanner::perform_scan( 'continuation' );
			if ( is_array( $result ) && 'deferred' === ( $result['execution_state'] ?? '' ) ) {
				self::schedule_scan_continuation( 60 );
			}
		}
	}

	/**
	 * Memindahkan event recurring ke jadwal berikutnya setelah fallback selesai.
	 *
	 * @param object $event Event WP-Cron yang sudah jatuh tempo.
	 * @param int|null $delay Penundaan khusus dalam detik.
	 * @return void
	 */
	private static function advance_scan_event( $event, $delay = null ) {
		if ( ! is_object( $event ) || empty( $event->schedule ) ) {
			return;
		}

		$current = wp_get_scheduled_event( self::SCAN_HOOK );
		if ( ! $current || (int) $current->timestamp !== (int) $event->timestamp ) {
			return;
		}

		wp_unschedule_event( (int) $event->timestamp, self::SCAN_HOOK, isset( $event->args ) ? $event->args : array() );

		$schedules = wp_get_schedules();
		$interval  = isset( $schedules[ $event->schedule ]['interval'] ) ? (int) $schedules[ $event->schedule ]['interval'] : 300;
		$next      = time() + ( null !== $delay ? max( 60, (int) $delay ) : max( 60, $interval ) );
		wp_schedule_event( $next, $event->schedule, self::SCAN_HOOK, isset( $event->args ) ? $event->args : array(), true );
	}

	/**
	 * Menjadwalkan ulang event cron pemindaian saat opsi interval diubah di pengaturan.
	 *
	 * @param string $new_interval Interval baru yang dipilih user.
	 * @return bool True jika event scan berhasil dijadwalkan ulang.
	 */
	public static function reschedule_event( $new_interval ) {
		self::register_schedules();

		$scan_timestamp = wp_next_scheduled( self::SCAN_HOOK );
		if ( $scan_timestamp ) {
			wp_unschedule_event( $scan_timestamp, self::SCAN_HOOK );
		}
		wp_clear_scheduled_hook( self::SCAN_HOOK );

		$valid_interval = sanitize_key( $new_interval );
		$schedules      = wp_get_schedules();
		if ( empty( $valid_interval ) || ! isset( $schedules[ $valid_interval ] ) ) {
			$valid_interval = 'every_5_minutes';
		}

		$result  = wp_schedule_event( time(), $valid_interval, self::SCAN_HOOK, array(), true );
		$success = ! is_wp_error( $result );
		if ( ! $success ) {
			self::log_schedule_failure( self::SCAN_HOOK, $result->get_error_message() );
		}

		// Pastikan hook prune IP tetap terjadwal.
		if ( ! wp_next_scheduled( self::PRUNE_HOOK ) ) {
			$prune_result = wp_schedule_event( time(), 'hourly', self::PRUNE_HOOK, array(), true );
			if ( is_wp_error( $prune_result ) ) {
				$success = false;
				self::log_schedule_failure( self::PRUNE_HOOK, $prune_result->get_error_message() );
			}
		}

		return $success;
	}

	/**
	 * Mencatat kegagalan pendaftaran event tanpa menghentikan request WordPress.
	 *
	 * @param string $hook  Nama hook yang gagal dijadwalkan.
	 * @param string $error Pesan error dari WordPress.
	 * @return void
	 */
	private static function log_schedule_failure( $hook, $error ) {
		if ( class_exists( __NAMESPACE__ . '\\Logger' ) ) {
			Logger::log(
				esc_html__( 'Gagal menjadwalkan pemindaian otomatis', 'wp-root-guard' ),
				sanitize_text_field( (string) $hook . ': ' . (string) $error ),
				esc_html__( 'Error', 'wp-root-guard' )
			);
		}
	}

	/**
	 * Membatalkan jadwal pemindaian otomatis dan pembersihan IP (misal saat deaktivasi atau reset).
	 *
	 * @return void
	 */
	public static function unschedule_event() {
		$scan_timestamp = wp_next_scheduled( self::SCAN_HOOK );
		if ( $scan_timestamp ) {
			wp_unschedule_event( $scan_timestamp, self::SCAN_HOOK );
		}
		wp_clear_scheduled_hook( self::SCAN_HOOK );

		$prune_timestamp = wp_next_scheduled( self::PRUNE_HOOK );
		if ( $prune_timestamp ) {
			wp_unschedule_event( $prune_timestamp, self::PRUNE_HOOK );
		}
		wp_clear_scheduled_hook( self::PRUNE_HOOK );
		wp_clear_scheduled_hook( self::CONTINUE_HOOK );
	}

	/**
	 * Callback yang dieksekusi oleh WP-Cron untuk memindai root folder di latar belakang.
	 *
	 * @return void
	 */
	public function run_background_scan() {
		if ( ! class_exists( __NAMESPACE__ . '\\Settings' ) || ! class_exists( __NAMESPACE__ . '\\Scanner' ) ) {
			return;
		}

		$settings = Settings::get_settings();
		if ( empty( $settings ) ) {
			return;
		}

		Scanner::perform_scan( 'cron' );
	}
}
