# Dokumentasi Struktur Proyek: WP Root Guard

> **Catatan Konteks untuk AI / Developer**:
> Berkas ini menyajikan arsitektur, pemetaan direktori, relasi antarmodul, tanggung jawab setiap kelas/file, hook lifecycles, serta aliran data dari plugin WordPress **WP Root Guard** (versi 3.1.2) secara lengkap dan mendalam. Gunakan dokumen ini sebagai peta referensi utama sebelum melakukan analisis, refaktorisasi, atau pembuatan fitur baru.

---

## 1. Ikhtisar Arsitektur Sistem

Plugin ini mengadopsi pola arsitektur **Modular Object-Oriented Programming (OOP)** dengan pembagian peran yang ketat antara bootstrap, background scheduling (cron), core security engine, pencegatan request (blocker), dan antarmuka administratif (admin GUI & dashboard widget).

```
[WordPress Core Hook Runner]
        │
        ├──► Entry Point: wp-root-guard.php (Autoloader, Lifecycles)
        │
        ├──► Orchestrator: includes/class-plugin.php
        │         ├──► includes/class-blocker.php      (Init priority 1 - Firewall & .htaccess)
        │         ├──► includes/class-cron.php         (WP-Cron scheduler & background scan)
        │         ├──► includes/class-updater.php      (GitHub Releases updater)
        │         ├──► admin/class-admin.php           (UI, AJAX endpoints, Form dispatchers)
        │         └──► admin/class-dashboard.php       (WP Dashboard Status Widget)
        │
        └──► Core Engine Services (Static Utility Providers)
                  ├──► includes/class-scanner.php      (Detection, SVN restore, diff, quarantine)
                  ├──► includes/class-baseline.php     (FS snapshot baseline.json generator)
                  ├──► includes/class-settings.php     (Options API wrapper & Whitelists)
                  └──► includes/class-logger.php       (Audit trail logger & CSV export)
```

---

## 2. Pohon Direktori Lengkap & Informasi File

```text
wp-root-guard-plugins/
├── .git/                                # Repositori kontrol versi Git
├── .github/                             # Konfigurasi workflow GitHub (CI / Release)
├── admin/                               # Lapisan Antarmuka Pengguna & Admin Controller
│   ├── css/
│   │   └── wp-root-guard-admin.css      # Stylesheet UI admin (606 baris)
│   ├── class-admin.php                  # Controller halaman admin, form POST, AJAX, modal (2.040 baris)
│   └── class-dashboard.php              # Widget status dashboard WordPress (111 baris)
├── docs/
│   └── STRUCTURE.md                     # [Dokumen ini] Peta struktur proyek detail untuk AI/Devs
├── includes/                            # Lapisan Logika Bisnis & Mesin Keamanan (Security Engine)
│   ├── class-activator.php              # Handler aktivasi plugin (43 baris)
│   ├── class-baseline.php               # Generator & pembaca baseline.json (232 baris)
│   ├── class-blocker.php                # Interseptor HTTP, pencegah webshell, IP blocker (255 baris)
│   ├── class-cron.php                   # Pengelola interval & eksekusi WP-Cron (91 baris)
│   ├── class-deactivator.php            # Handler deaktivasi plugin (32 baris)
│   ├── class-logger.php                 # Penyimpan log audit aktivitas keamanan (77 baris)
│   ├── class-plugin.php                 # Kelas koordinasi registrasi hook (105 baris)
│   ├── class-scanner.php                # Engine pemindaian, diff, self-healing, karantina (1.491 baris)
│   ├── class-settings.php               # Manajemen opsi pengaturan & whitelist (211 baris)
│   └── class-updater.php                # Integrator auto-update via GitHub Releases (245 baris)
├── languages/
│   └── wp-root-guard.pot                # Template berkas terjemahan gettext (63 baris)
├── PRD.md                               # Product Requirement Document & Technical Specification
├── README.md                            # Dokumentasi publik, fitur, panduan, dan changelog rilis
├── readme.txt                           # Format dokumentasi standar repositori WordPress.org
├── uninstall.php                        # Skrip penghapusan bersih data & aturan .htaccess (64 baris)
└── wp-root-guard.php                    # Berkas bootstrap utama plugin & autoloader (97 baris)
```

---

## 3. Rincian Peran & Tanggung Jawab Tiap Berkas

### A. Root Directory (Bootstrap & Lifecycle)

| Berkas | Namespace / Lingkup | Baris | Peran & Tanggung Jawab Utama |
|---|---|:---:|---|
| [`wp-root-guard.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/wp-root-guard.php) | Global & `WPRootGuard\` | 97 | 1. Memeriksa konstanta `ABSPATH`.<br>2. Mendefinisikan konstanta global (`WP_ROOT_GUARD_VERSION`, `WP_ROOT_GUARD_FILE`, `WP_ROOT_GUARD_PATH`, `WP_ROOT_GUARD_URL`).<br>3. Mendaftarkan kustom PSR-like Autoloader untuk namespace `WPRootGuard\` ke pola `class-{name}.php`.<br>4. Mendaftarkan `register_activation_hook` dan `register_deactivation_hook`.<br>5. Memeriksa versi minimum runtime PHP (PHP 8.1+) dan menjalankan plugin via `wp_root_guard_run()`. |
| [`uninstall.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/uninstall.php) | Global | 64 | Dijalankan otomatis saat administrator menghapus plugin secara permanen dari WordPress admin:<br>1. Menghapus jadwal WP-Cron `wp_root_guard_cron_scan`.<br>2. Menghapus seluruh opsi di tabel `wp_options` (13 kunci opsi/transient).<br>3. Membersihkan blok aturan IP penyerang dari berkas root `.htaccess` menggunakan regex boundary marker.<br>4. Menghapus direktori snapshot baseline `wp-content/uploads/wp-root-guard/` beserta file `baseline.json`. |

---

### B. Direktori `includes/` (Core Security Engine & Business Logic)

| Berkas & Kelas | Tanggung Jawab & Fitur Utama | Ketergantungan / Relasi |
|---|---|---|
| [`class-plugin.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-plugin.php)<br>`WPRootGuard\Plugin` | Mengorkestrasi pemuatan komponen dan mendaftarkan hooks utama (`plugins_loaded` untuk i18n). Menginisialisasi kelas `Cron`, `Blocker`, `Updater`, serta jika di dashboard (`is_admin()`), menginisialisasi `Admin` dan `Dashboard`. | Menginstansiasi `Cron`, `Blocker`, `Updater`, `Admin\Admin`, `Admin\Dashboard`. |
| [`class-activator.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-activator.php)<br>`WPRootGuard\Activator` | Dijalankan saat plugin diaktifkan. Membuat baseline awal snapshot folder & berkas root via `Baseline::create_baseline()`, serta menjadwalkan event WP-Cron berkala via `Cron::schedule_event()`. | Memanggil `Baseline` dan `Cron`. |
| [`class-deactivator.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-deactivator.php)<br>`WPRootGuard\Deactivator` | Dijalankan saat plugin dinonaktifkan. Menghapus jadwal event WP-Cron melalui `Cron::unschedule_event()`. | Memanggil `Cron`. |
| [`class-baseline.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-baseline.php)<br>`WPRootGuard\Baseline` | Mengelola *golden snapshot* kondisi awal website:<br>1. Memindai folder root non-rekursif (`scan_root_folders`).<br>2. Memindai file root dan menghitung MD5 hash (`scan_root_files`).<br>3. Menyimpan dan membaca file JSON di `wp-content/uploads/wp-root-guard/baseline.json`. | Berinteraksi langsung dengan filesystem root (`ABSPATH`) dan uploads dir. |
| [`class-blocker.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-blocker.php)<br>`WPRootGuard\Blocker` | Modul proteksi aktif dan firewall mini:<br>1. Terpasang pada hook `init` prioritas 1.<br>2. Mencegat percobaan eksekusi PHP di dalam `wp-content/uploads/` (`.php`, `.phtml`, `.phar`, `.inc`, dll).<br>3. Mencegat query string berbahaya (`cmd=`, `shell=`, `eval(`, `base64_decode(`).<br>4. Mendeteksi IP pengakses via `get_client_ip()`.<br>5. Memblokir IP penyerang dengan menulis aturan ke berkas root `.htaccess` (Apache 2.4 `Require not ip` dan Apache 2.2 `Deny from`) serta fallback blokir via PHP untuk server Nginx/IIS.<br>6. Menampilkan halaman blokir custom HTTP 403 Forbidden. Pengecualian penuh untuk administrator (`manage_options`). | Menggunakan `Settings`, `Logger`, `Scanner`, filesystem root `.htaccess`. |
| [`class-cron.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-cron.php)<br>`WPRootGuard\Cron` | Mengelola penjadwalan otomatis di latar belakang:<br>1. Menambahkan interval kustom WP-Cron via filter `cron_schedules` (5 menit, 15 menit, 30 menit).<br>2. Menjadwalkan / membatalkan / menjadwal ulang event hook `wp_root_guard_cron_scan`.<br>3. Callback `run_background_scan()` yang memicu `Scanner::perform_scan()`. | Memanggil `Settings` dan `Scanner`. |
| [`class-logger.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-logger.php)<br>`WPRootGuard\Logger` | Mengelola audit trail riwayat aktivitas keamanan:<br>1. Menyimpan entri log (Timestamp WIB, Event, Nama Berkas/Folder, Status) ke opsi `wp_root_guard_logs`.<br>2. Mengimplementasikan rolling ring-buffer (maksimal 100 entri terbaru).<br>3. Menyediakan method `get_logs()` dan `clear_logs()`. | Menggunakan `Scanner::get_wib_time()` dan WordPress Options API. |
| [`class-scanner.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php)<br>`WPRootGuard\Scanner` | **Jantung & Engine Pemindaian Utama Plugin** (1.491 baris):<br>1. `perform_scan()`: Melakukan pemindaian komprehensif 4 tahap (Folder Asing Root, Berkas Asing Root, Integritas Berkas Core WordPress via Checksums API, dan Pemindaian Berkas PHP di `wp-content/uploads/`).<br>2. Normalisasi line-ending (`\r\n` ke `\n`) saat verifikasi hash MD5 berkas core.<br>3. `get_core_checksums()`: Mengontak WordPress.org Checksums API dengan caching transient 24 jam.<br>4. `restore_core_file()`: Mengunduh kode asli resmi dari SVN resmi WordPress.org (`core.svn.wordpress.org/tags/{version}/{path}`) dan menimpa berkas lokal yang rusak (Self-Healing). Dilengkapi validasi allowlist prefix dan proteksi Path Traversal (`realpath`).<br>5. `get_file_diff()`: Membandingkan kode lokal vs upstream SVN baris demi baris (maksimal 300 baris diff).<br>6. `scan_file_for_webshell()`: Mencocokkan 24+ signature webshell/backdoor populer.<br>7. `inspect_file_content()`: Menganalisis baris file untuk Secure Code Inspector.<br>8. `quarantine_folder()`, `quarantine_file()`, `quarantine_core_file()`: Memindahkan ancaman ke Dedicated Quarantine Vault (`uploads/wp-root-guard-quarantine/`) dengan penguncian ganda `.htaccess` (`Require all denied`) dan `index.html`.<br>9. `restore_quarantined_folder()`: Mengembalikan item karantina ke path aslinya.<br>10. `delete_file_directly()`: Menghapus permanen file asing/penyusup.<br>11. Notifikasi multi-channel: Mengirim peringatan ke Telegram Bot API dan Email Administrator dengan proteksi anti-spam (`wp_root_guard_notified_threats`). | Menggunakan `Baseline`, `Settings`, `Logger`, Remote HTTP API WordPress.org & SVN, Telegram Bot API. |
| [`class-settings.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-settings.php)<br>`WPRootGuard\Settings` | Mengelola konfigurasi dan whitelist:<br>1. Whitelist bawaan folder (`wp-admin`, `wp-content`, `wp-includes`, `.well-known`, `cgi-bin`).<br>2. Whitelist bawaan berkas root standar WordPress (20 berkas resmi seperti `index.php`, `wp-login.php`, `.htaccess`, `robots.txt`).<br>3. Manajemen whitelist kustom user (`wp_root_guard_whitelist`).<br>4. Opsi pengaturan umum (`wp_root_guard_settings`): interval scan, toggle uploads scan, toggle IP blocker, toggle auto quarantine, konfigurasi Telegram, konfigurasi email. | Berinteraksi dengan WordPress Options API. |
| [`class-updater.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-updater.php)<br>`WPRootGuard\Updater` | Integrasi pembaruan otomatis langsung dari rilis GitHub (`halimurrosyid/wp-root-guard-plugins`):<br>1. Filter `pre_set_site_transient_update_plugins` & `site_transient_update_plugins`.<br>2. Filter `plugins_api` untuk menampilkan changelog popup modal rilis di dashboard plugin WordPress.<br>3. Caching respon API GitHub selama 12 jam. | Mengontak GitHub Releases API. |

---

### C. Direktori `admin/` (Presentation & Administration Layer)

| Berkas & Kelas | Tanggung Jawab & Komponen |
|---|---|
| [`class-admin.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php)<br>`WPRootGuard\Admin\Admin` | **Controller Administratif Utama** (2.040 baris):<br>1. Mendaftarkan menu admin via hook `admin_menu`.<br>2. `handle_admin_actions()`: Menangani aksi form POST/GET (Scan manual, Rebuild baseline, Reset baseline, Trust, Untrust, Quarantine, Delete, Restore Core SVN, Block/Unblock IP, Bulk Actions, Save Settings, Test Telegram, Test Email, Restore Quarantine, Delete Quarantine, Export CSV).<br>3. `render_threat_notice()`: Hook `admin_notices` untuk banner merah peringatan jika ada ancaman aktif.<br>4. `enqueue_styles()`: Memuat CSS admin.<br>5. Endpoint AJAX: `ajax_get_scan_queue` (antrean item scan), `ajax_run_scan` (eksekusi scan ber-rate-limit), `ajax_inspect_file` (data preview kode modal).<br>6. `render_admin_page()`: Menampilkan UI lengkap: Tab Dashboard (Status Card AMAN/BAHAYA, Ringkasan, Floating Sticky Bulk Actions Bar, 4 Tabel Ancaman, Tabel Karantina, Tabel Whitelist, Tabel IP Terblokir, Tabel Log dengan pagination dinamis, Pop-up Comparative Diff Viewer, Pop-up Secure Code Inspector Modal), dan Tab Settings.<br>7. Inline JavaScript (Baris 1585–1791) untuk interaktivitas AJAX scanner, checkboxes, dan modal dialog. |
| [`class-dashboard.php`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-dashboard.php)<br>`WPRootGuard\Admin\Dashboard` | Menambahkan widget ringkasan pada Dashboard utama WordPress (`index.php`) via hook `wp_dashboard_setup`. Menampilkan status proteksi saat ini (🛡️ Aman / ⚠️ Bahaya), waktu pemindaian terakhir, jumlah ancaman, dan tombol cepat "Scan Now". |
| [`css/wp-root-guard-admin.css`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/css/wp-root-guard-admin.css) | File stylesheet styling antarmuka: status cards, modern badges, floating bulk action bar, pop-up modal overlay, side-by-side diff table layout (merah/hijau), loading bar, dan responsive tables. |

---

## 4. Aliran Data & Penyimpanan (Data Storage Model)

### A. Tabel `wp_options` (WordPress Options API)

| Kunci Opsi / Transient | Tipe Data | Deskripsi Isi |
|---|---|---|
| `wp_root_guard_settings` | Array | Pengaturan global: `scan_interval`, `enable_uploads_php_scan`, `enable_ip_blocker`, `enable_auto_quarantine`, `enable_email_notifications`, `admin_email`, `enable_telegram_notifications`, `telegram_bot_token`, `telegram_chat_id`. |
| `wp_root_guard_whitelist` | Array | Daftar nama folder/berkas yang dipercayai oleh admin (Custom Whitelist). |
| `wp_root_guard_last_scan` | Array | Metadata scan terakhir: `last_scan` (datetime), `status` (`safe` / `threat`), `unknown_count`, array `unknown_folders`. |
| `wp_root_guard_unknown_folders` | Array | Array seluruh objek ancaman aktif yang belum dikarantina/dipercaya. |
| `wp_root_guard_quarantined_folders` | Array | Riwayat item yang sedang berada di dalam karantina beserta original path dan quarantine path. |
| `wp_root_guard_notified_threats` | Array | Daftar hash identifier ancaman yang sudah dikirim ke Telegram/email (mencegah spam notifikasi berulang). |
| `wp_root_guard_blocked_ips` | Array Asosiatif | Daftar IP terblokir: `[ '1.2.3.4' => [ 'ip' => '1.2.3.4', 'reason' => '...', 'time' => '...' ] ]`. |
| `wp_root_guard_logs` | Array | Riwayat log aktivitas keamanan (maksimal 100 entri rolling buffer). |
| `wp_root_guard_core_checksums` | Transient (24h) | Cache data checksums resmi WordPress.org (`relative_path => expected_md5`). |
| `wp_root_guard_latest_github_release` | Transient (12h) | Cache rilis terbaru dari API GitHub. |
| `wprg_scan_rate_{user_id}` | Transient (20s) | Rate limiter untuk mencegah spam klik tombol pemindaian via AJAX. |
| `wprg_fix_error_{user_id}` | Transient (60s) | Penyimpan pesan diagnostik alasan kegagalan pemulihan berkas core. |
| `wprg_bulk_fix_errors_{user_id}` | Transient (60s) | Penyimpan daftar kegagalan saat aksi massal perbaikan core. |

### B. Penyimpanan Berkas Fisik (Filesystem Storage)

| Lokasi Fisik | Tujuan & Karakteristik Keamanan |
|---|---|
| `wp-content/uploads/wp-root-guard/baseline.json` | Menyimpan daftar struktur folder & hash berkas root rujukan. Dilindungi file `index.php` kosong. |
| `wp-content/uploads/wp-root-guard-quarantine/` | **Dedicated Quarantine Vault**. Semua file/folder yang diisolasi dipindahkan ke sini dengan prefix nama `__quarantine_{name}_{timestamp}`. Dilindungi oleh `.htaccess` (`Require all denied` / `Deny from all`) dan `index.html`. |
| Root `ABSPATH/.htaccess` | Disisipkan aturan pemblokiran IP penyerang dinamis di antara marker boundary `# BEGIN WP Root Guard Blocked IPs` dan `# END WP Root Guard Blocked IPs`. |

---

## 5. Matriks Alur Permintaan (Request Life-Cycle Flow)

```
1. HTTP Request Masuk ke Server
   │
   ▼
[WordPress Core: wp-settings.php]
   │
   ▼
[wp-root-guard.php (Autoloader terdaftar)]
   │
   ▼
[Plugin::run()]
   │
   ├─► Action: 'init' (Priority 1) ──► Blocker::intercept_malicious_requests()
   │     ├─► Apakah URI mengarah ke file PHP di /uploads/ ?
   │     │     └─► Ya ──► Blocker::block_ip() -> Tulis .htaccess -> wp_die(403)
   │     ├─► Apakah Query String berisi pola Webshell (cmd=, eval, dll)?
   │     │     └─► Ya ──► Blocker::block_ip() -> Tulis .htaccess -> wp_die(403)
   │     └─► Apakah IP klien ada di daftar IP terblokir?
   │           └─► Ya ──► wp_die(403)
   │
   ├─► Background Scheduler: 'wp_root_guard_cron_scan'
   │     └─► Memicu Scanner::perform_scan() di latar belakang secara terjadwal.
   │
   ├─► Filter Update: 'site_transient_update_plugins'
   │     └─► Updater::check_update() memeriksa rilis GitHub API.
   │
   └─► Jika Area Admin (is_admin()):
         ├─► Action: 'admin_menu' ──► Mendaftarkan halaman Root Guard.
         ├─► Action: 'admin_init' ──► Admin::handle_admin_actions() (POST form dispatcher).
         ├─► Action: 'admin_notices' ──► Menampilkan banner jika ada ancaman aktif.
         ├─► Action: 'wp_ajax_wp_root_guard_run_scan' ──► Scanner::perform_scan() via AJAX.
         └─► Action: 'wp_ajax_wp_root_guard_inspect_file' ──► Scanner::inspect_file_content().
```

---

## 6. Titik Kritis untuk Pengembangan & Refaktorisasi (Engineering Notes)

Berdasarkan tinjauan arsitektur kode saat ini, berikut catatan penting bagi AI / pengembang sebelum memodifikasi kode:

1. **Ukuran File `class-admin.php` Monolitik (2.040 baris)**:
   - File ini menggabungkan controller pemrosesan form, handler AJAX, rendering HTML tabel, modal pop-up, dan 200+ baris JavaScript inline.
   - **Rencana Refaktor**: Pisahkan rendering HTML ke folder `admin/views/` (misal `tab-dashboard.php`, `tab-settings.php`, `modal-diff.php`), dan pindahkan kode JavaScript ke `admin/js/wp-root-guard-admin.js`.
2. **Kredensial Default Telegram Bot**:
   - Di [includes/class-settings.php#L152-L164](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-settings.php#L152-L164), terdapat token bot dan chat ID default hardcoded. Ini harus segera dikosongkan secara default demi privasi pengguna.
3. **Penyempurnaan Penentuan IP Klien**:
   - Di [includes/class-blocker.php#L35-L46](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-blocker.php#L35-L46), `get_client_ip()` membaca raw header `HTTP_X_FORWARDED_FOR` tanpa validasi trusted proxy. Perlu difilter agar tidak rentan IP spoofing.
4. **Ketiadaan Hook Lifecycle Update WordPress Core**:
   - Saat WordPress auto-update, baseline lokal tidak otomatis diperbarui, berpotensi memicu alarm *Modified Core File* palsu. Perlu dipasang hook `upgrader_process_complete` atau `_core_updated_successfully`.
5. **Ketiadaan Cron Prune IP Terblokir**:
   - IP yang diblokir saat ini berstatus permanen. Perlu ditambahkan durasi auto-expire dan hook cron pembersih berkala agar berkas `.htaccess` tidak membengkak.
