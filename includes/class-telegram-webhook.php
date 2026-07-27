<?php
/**
 * Mengelola callback Webhook REST API Telegram untuk tombol aksi interaktif.
 *
 * @package WPRootGuard
 */

namespace WPRootGuard;

// Mencegah akses langsung.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class TelegramWebhook
 *
 * Menangani penerimaan webhook dari Telegram Bot API dengan 4 lapis proteksi keamanan.
 */
class TelegramWebhook {

	/**
	 * Mendaftarkan rute REST API WordPress untuk Telegram Callback.
	 */
	public function init() {
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
	}

	/**
	 * Mendapatkan atau membuat Kunci Rahasia Situs Unik (Secret Key) untuk HMAC & Header Token.
	 *
	 * @return string Secret Key 64-karakter.
	 */
	public static function get_site_secret() {
		$secret = get_option( 'wp_root_guard_tg_secret', '' );
		if ( empty( $secret ) ) {
			$secret = wp_generate_password( 64, true, true );
			update_option( 'wp_root_guard_tg_secret', $secret );
		}
		return $secret;
	}

	/**
	 * Mendaftarkan endpoint REST API: POST /wp-json/wp-root-guard/v1/telegram-callback
	 */
	public function register_rest_routes() {
		register_rest_route(
			'wp-root-guard/v1',
			'/telegram-callback',
			array(
				'methods'             => 'POST',
				'callback'            => array( $this, 'handle_callback' ),
				'permission_callback' => '__return_true', // Verifikasi keamanan dilakukan secara kriptografi di dalam handler
			)
		);
	}

	/**
	 * Memproses permintaan callback webhook yang masuk dari Telegram.
	 *
	 * @param \WP_REST_Request $request Permintaan HTTP REST API.
	 * @return \WP_REST_Response Respons REST API.
	 */
	public function handle_callback( $request ) {
		$secret_key = self::get_site_secret();

		// ==========================================
		// LAPIS 1: VERIFIKASI SECRET TOKEN HEADER
		// ==========================================
		$incoming_token = $request->get_header( 'x-telegram-bot-api-secret-token' );
		if ( empty( $incoming_token ) || ! hash_equals( $secret_key, $incoming_token ) ) {
			Logger::log(
				esc_html__( 'Percobaan Akses Webhook Ilegal (Invalid Secret Header)', 'wp-root-guard' ),
				Blocker::get_client_ip(),
				esc_html__( 'Blocked', 'wp-root-guard' )
			);
			return new \WP_REST_Response( array( 'status' => 'error', 'message' => 'Forbidden' ), 403 );
		}

		$params = $request->get_json_params();
		if ( empty( $params ) || ! is_array( $params ) ) {
			return new \WP_REST_Response( array( 'status' => 'error', 'message' => 'Invalid JSON' ), 400 );
		}

		// Periksa apakah ini adalah Callback Query (Klik Tombol Interaktif)
		if ( empty( $params['callback_query'] ) ) {
			return new \WP_REST_Response( array( 'status' => 'ok', 'message' => 'Ignored non-callback' ), 200 );
		}

		$callback       = $params['callback_query'];
		$callback_id    = isset( $callback['id'] ) ? sanitize_text_field( $callback['id'] ) : '';
		$from_user_id   = isset( $callback['from']['id'] ) ? (string) $callback['from']['id'] : '';
		$chat_id        = isset( $callback['message']['chat']['id'] ) ? (string) $callback['message']['chat']['id'] : '';
		$message_id     = isset( $callback['message']['message_id'] ) ? (int) $callback['message']['message_id'] : 0;
		$callback_data  = isset( $callback['data'] ) ? sanitize_text_field( $callback['data'] ) : '';

		$settings = Settings::get_settings();
		$configured_chat_id = (string) trim( $settings['telegram_chat_id'] );
		$bot_token          = trim( $settings['telegram_bot_token'] );

		// ==========================================
		// LAPIS 3: VERIFIKASI OTORISASI USER/CHAT ID
		// ==========================================
		if ( ! empty( $configured_chat_id ) && $chat_id !== $configured_chat_id && $from_user_id !== $configured_chat_id ) {
			self::answer_callback_query( $bot_token, $callback_id, esc_html__( '⚠️ Akses Ditolak: Anda tidak memiliki wewenang untuk mengeksekusi tindakan ini.', 'wp-root-guard' ), true );
			return new \WP_REST_Response( array( 'status' => 'error', 'message' => 'Unauthorized user' ), 403 );
		}

		// ==========================================
		// LAPIS 2: VERIFIKASI TANDA TANGAN HMAC-SHA256
		// ==========================================
		// Format callback_data: action:type:item_name:timestamp:signature
		$parts = explode( ':', $callback_data );
		if ( count( $parts ) < 5 ) {
			self::answer_callback_query( $bot_token, $callback_id, esc_html__( '❌ Data tombol tidak valid.', 'wp-root-guard' ), true );
			return new \WP_REST_Response( array( 'status' => 'error', 'message' => 'Malformed callback data' ), 400 );
		}

		$action    = $parts[0];
		$type      = $parts[1];
		$item_name = $parts[2];
		$timestamp = (int) $parts[3];
		$signature = $parts[4];

		// Cek anti-replay (Maksimal 48 jam)
		if ( ( time() - $timestamp ) > 172800 ) {
			self::answer_callback_query( $bot_token, $callback_id, esc_html__( '⚠️ Tombol tindakan ini sudah kadaluarsa (> 48 jam).', 'wp-root-guard' ), true );
			return new \WP_REST_Response( array( 'status' => 'error', 'message' => 'Expired token' ), 400 );
		}

		// Verifikasi ulang Tanda Tangan HMAC
		$expected_sig = substr( hash_hmac( 'sha256', "{$action}|{$type}|{$item_name}|{$timestamp}", $secret_key ), 0, 16 );
		if ( ! hash_equals( $expected_sig, $signature ) ) {
			Logger::log(
				esc_html__( 'Percobaan Manipulation Callback Signature Telegram', 'wp-root-guard' ),
				$item_name,
				esc_html__( 'Blocked', 'wp-root-guard' )
			);
			self::answer_callback_query( $bot_token, $callback_id, esc_html__( '🚫 Tanda tangan keamanan tidak cocok (Manipulasi Terdeteksi).', 'wp-root-guard' ), true );
			return new \WP_REST_Response( array( 'status' => 'error', 'message' => 'Invalid HMAC Signature' ), 403 );
		}

		// ==========================================
		// LAPIS 4: PEMBERSIHAN PATH TRAVERSAL STRICT & EKSEKUSI
		// ==========================================
		$item_name = sanitize_text_field( $item_name );
		if ( false !== strpos( $item_name, '..' ) ) {
			self::answer_callback_query( $bot_token, $callback_id, esc_html__( '🚫 Terdeteksi percobaan Path Traversal!', 'wp-root-guard' ), true );
			return new \WP_REST_Response( array( 'status' => 'error', 'message' => 'Path traversal attempt' ), 400 );
		}

		$wib_now = Scanner::get_wib_time();
		$success_msg = '';
		$new_status  = '';

		switch ( $action ) {
			case 'quarantine':
				if ( 'folder' === $type ) {
					$res = Scanner::quarantine_folder( $item_name );
				} elseif ( 'core_file' === $type ) {
					$res = Scanner::quarantine_core_file( $item_name );
				} else {
					$res = Scanner::quarantine_file( $item_name );
				}

				if ( false !== $res ) {
					$success_msg = sprintf( esc_html__( '✅ Berkas/Folder "%s" berhasil DIKARANTINA ke Vault Terisolasi!', 'wp-root-guard' ), $item_name );
					$new_status  = "🔒 *DIKARANTINA via Telegram oleh Admin* ({$wib_now})";
				} else {
					$success_msg = sprintf( esc_html__( '⚠️ Gagal mengkarantina "%s" (Berkas mungkin sudah dipindahkan/dihapus).', 'wp-root-guard' ), $item_name );
				}
				break;

			case 'trust':
				Settings::add_to_whitelist( $item_name );
				$success_msg = sprintf( esc_html__( '🛡️ Berkas/Folder "%s" berhasil DITAMBAHKAN ke Whitelist Kustom!', 'wp-root-guard' ), $item_name );
				$new_status  = "🛡️ *DIPERCAYAI (Whitelisted) via Telegram oleh Admin* ({$wib_now})";
				Logger::log(
					esc_html__( 'Item dipercayai via Telegram', 'wp-root-guard' ),
					$item_name,
					esc_html__( 'Safe', 'wp-root-guard' )
				);
				break;

			case 'delete':
				$abs_target = ABSPATH . $item_name;
				if ( is_dir( $abs_target ) ) {
					$res = Scanner::delete_folder_directly( $item_name );
				} else {
					$res = Scanner::delete_file_directly( $item_name );
				}

				if ( $res ) {
					$success_msg = sprintf( esc_html__( '🗑️ Berkas/Folder "%s" berhasil DIHAPUS PERMANEN dari server!', 'wp-root-guard' ), $item_name );
					$new_status  = "🗑️ *DIHAPUS PERMANEN via Telegram oleh Admin* ({$wib_now})";
				} else {
					$success_msg = sprintf( esc_html__( '⚠️ Gagal menghapus "%s" (Berkas mungkin sudah tidak ada).', 'wp-root-guard' ), $item_name );
				}
				break;

			default:
				$success_msg = esc_html__( 'Aksi tidak dikenal.', 'wp-root-guard' );
				break;
		}

		// 1. Tampilkan Pop-Up Toast di aplikasi Telegram
		self::answer_callback_query( $bot_token, $callback_id, $success_msg, true );

		// 2. Perbarui teks pesan Telegram untuk mencerminkan status terbaru
		if ( ! empty( $new_status ) && ! empty( $message_id ) && ! empty( $chat_id ) ) {
			$orig_text = isset( $callback['message']['text'] ) ? $callback['message']['text'] : '';
			if ( ! empty( $orig_text ) ) {
				$updated_text  = $orig_text . "\n\n━━━━━━━━━━━━━━━━━━━━━━\n" . $new_status;
				self::edit_message_text( $bot_token, $chat_id, $message_id, $updated_text );
			}
		}

		return new \WP_REST_Response( array( 'status' => 'success', 'message' => $success_msg ), 200 );
	}

	/**
	 * Mengirim respons answerCallbackQuery ke Telegram Bot API untuk menampilkan pop-up toast.
	 *
	 * @param string $token Bot Token Telegram.
	 * @param string $callback_id Callback Query ID.
	 * @param string $text Teks pesan pop-up.
	 * @param bool   $show_alert True jika ingin menampilkan dialog alert pop-up.
	 */
	public static function answer_callback_query( $token, $callback_id, $text, $show_alert = true ) {
		if ( empty( $token ) || empty( $callback_id ) ) {
			return;
		}

		$url  = "https://api.telegram.org/bot{$token}/answerCallbackQuery";
		$body = array(
			'callback_query_id' => $callback_id,
			'text'              => $text,
			'show_alert'        => $show_alert,
		);

		wp_remote_post(
			$url,
			array(
				'body'      => $body,
				'timeout'   => 5,
				'blocking'  => false,
				'sslverify' => false,
			)
		);
	}

	/**
	 * Mengedit teks pesan Telegram yang sudah ada setelah aksi dieksekusi.
	 *
	 * @param string $token Bot Token Telegram.
	 * @param string $chat_id Chat ID Telegram.
	 * @param int    $message_id ID Pesan Telegram.
	 * @param string $text Teks baru.
	 */
	public static function edit_message_text( $token, $chat_id, $message_id, $text ) {
		if ( empty( $token ) || empty( $chat_id ) || empty( $message_id ) ) {
			return;
		}

		$url  = "https://api.telegram.org/bot{$token}/editMessageText";
		$body = array(
			'chat_id'    => $chat_id,
			'message_id' => $message_id,
			'text'       => $text,
		);

		wp_remote_post(
			$url,
			array(
				'body'      => $body,
				'timeout'   => 5,
				'blocking'  => false,
				'sslverify' => false,
			)
		);
	}

	/**
	 * Mengurutkan dan mereturn URL Webhook REST API situs untuk didaftarkan ke Telegram API.
	 *
	 * @return string URL Webhook REST API.
	 */
	public static function get_webhook_url() {
		return rest_url( 'wp-root-guard/v1/telegram-callback' );
	}

	/**
	 * Daftarkan Webhook URL ke Telegram API (setWebhook).
	 *
	 * @param string $token Bot Token Telegram.
	 * @return bool True jika berhasil didaftarkan.
	 */
	public static function register_webhook_with_telegram( $token ) {
		$token = trim( $token );
		if ( empty( $token ) ) {
			return false;
		}

		$webhook_url = self::get_webhook_url();
		$secret_key  = self::get_site_secret();

		$url  = "https://api.telegram.org/bot{$token}/setWebhook";
		$body = array(
			'url'          => $webhook_url,
			'secret_token' => $secret_key,
		);

		$response = wp_remote_post(
			$url,
			array(
				'body'      => $body,
				'timeout'   => 15,
				'blocking'  => true,
				'sslverify' => false,
			)
		);

		if ( is_wp_error( $response ) ) {
			return false;
		}

		$code = wp_remote_retrieve_response_code( $response );
		return 200 === $code;
	}
}
