# Katalog Fitur & Spesifikasi Teknis: WP Root Guard

> **Catatan Konteks untuk AI / Developer**:
> Berkas ini menyajikan inventarisasi lengkap seluruh fitur plugin **WP Root Guard** (versi 3.1.2) yang diekstraksi langsung dari *deep scan* terhadap basis kode nyata (`admin/`, `includes/`, dan berkas pendukung). Dokumen ini menguraikan status implementasi, mekanisme kerja internal, berkas & baris kode sumber terkait, opsi konfigurasi, serta celah/keterbatasan teknis dari masing-masing fitur.

---

## 1. Matriks Ringkasan Fitur (Feature Matrix)

| Modul Fitur | Kategori | Status di Kode | Lokasi File Kunci | Efisiensi & Kualitas |
|---|---|:---:|---|---|
| **Core Integrity Checksums** | Deteksi | ✅ Aktif | `includes/class-scanner.php:228-300` | Sangat Tinggi (API resmi + cache 24h) |
| **Root Folder & File Scan** | Deteksi | ✅ Aktif | `includes/class-baseline.php:158-232` | Tinggi (Non-rekursif, hemat memori) |
| **Uploads PHP & Webshell Scan** | Deteksi | ✅ Aktif | `includes/class-scanner.php:1438-1490` | Sedang (Rawan timeout di folder besar) |
| **Webshell Signature Detector** | Deteksi | ⚠️ Dasar | `includes/class-scanner.php:673-731` | Rendah–Sedang (Regex statis 24 pattern) |
| **Core Auto-Restore (Self-Healing)** | Remediasi | ✅ Aktif | `includes/class-scanner.php:498-595` | Sangat Tinggi (SVN Upstream resmi) |
| **Side-by-Side Diff Viewer** | Remediasi | ✅ Aktif | `includes/class-scanner.php:603-665` | Tinggi (Maksimal 300 baris diff) |
| **Dedicated Quarantine Vault** | Remediasi | ✅ Aktif | `includes/class-scanner.php:833-1021` | Tinggi (Kunci ganda .htaccess + index) |
| **Bulk Action Operations** | Remediasi | ✅ Aktif | `admin/class-admin.php:306-365` | Sangat Tinggi (Sticky bar & multi-target) |
| **Attacker IP Blocker (.htaccess)** | Proteksi | ⚠️ Berisiko | `includes/class-blocker.php:129-254` | Sedang (Permanen tanpa expiry, spoofing) |
| **HTTP Webshell Interceptor** | Proteksi | ✅ Aktif | `includes/class-blocker.php:49-120` | Tinggi (Eksekusi dini pada hook `init:1`) |
| **Secure Code Inspector** | Forensik | ✅ Aktif | `includes/class-scanner.php:739-830` | Tinggi (Read-only + Malware highlighter) |
| **Multi-Channel Alerting** | Notifikasi| ⚠️ Berisiko | `includes/class-scanner.php:1241-1408` | Cukup (Anti-spam aktif, token hardcoded) |
| **Security Audit Logger** | Forensik | ⚠️ Dasar | `includes/class-logger.php:21-77` | Sedang (Limit 100, tersimpan di Options) |
| **Auto-Updater via GitHub** | Pemeliharaan| ✅ Aktif | `includes/class-updater.php:72-245` | Tinggi (Cache transien 12 jam) |

---

## 2. Bedah Detail Fitur Deteksi (Detection Engine)

### 2.1 Pemindaian Folder & Berkas Root Non-Rekursif
* **Implementasi Kode**: [`includes/class-baseline.php:158-232`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-baseline.php#L158-L232)
* **Mekanisme Kerja**:
  1. Menggunakan PHP `DirectoryIterator` pada direktori `ABSPATH` secara non-rekursif tingkat pertama.
  2. Mengabaikan file sistem dot (`.` dan `..`) serta folder dengan prefix karantina (`__quarantine_`).
  3. Menghitung MD5 hash dari setiap berkas di root (`scan_root_files()`).
  4. Mencocokkan folder dan berkas yang ditemukan terhadap gabungan:
     * Baseline rujukan awal (`uploads/wp-root-guard/baseline.json`)
     * Default folder whitelist (`wp-admin`, `wp-content`, `wp-includes`, `.well-known`, `cgi-bin`)
     * Default file whitelist (20 berkas resmi WordPress: `index.php`, `wp-login.php`, dll)
     * User custom whitelist (`wp_root_guard_whitelist`).
* **Output Status**: `Unknown Folder`, `Unknown File`, `Modified File`.

### 2.2 Core File Integrity Scanner (Checksums API WordPress.org)
* **Implementasi Kode**: [`includes/class-scanner.php:228-364`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L228-L364) & [`includes/class-scanner.php:447-484`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L447-L484)
* **Mekanisme Kerja**:
  1. Mengambil data checksums resmi via API:
     `https://api.wordpress.org/core/checksums/1.0/?version={wp_version}&locale={locale}`
  2. Menyimpan respon di Transient API `wp_root_guard_core_checksums` selama 24 jam.
  3. **Normalisasi Karakter Baris Baru**: Kode lokal dinormalisasi dari `\r\n` (CRLF Windows/FTP) ke `\n` (LF) sebelum hash dihitung ulang untuk mencegah *false positive*.
  4. **Pengecualian Aman**: Berkas `wp-config.php` sengaja dilewati agar modifikasi kredensial database pengguna tidak dianggap ancaman core.
* **Klasifikasi Temuan**:
  - `Missing Core File`: Berkas resmi terdaftar di API tetapi fisik file tidak ada di server.
  - `Modified Core File`: Berkas core resmi ada tetapi isi kode berubah dari upstream WordPress.org.
  - `Suspicious Core Injection`: Berkas tidak resmi yang sengaja ditanam penyerang di dalam direktori sensitif `wp-admin/` dan `wp-includes/`.

### 2.3 Uploads PHP Security Guard
* **Implementasi Kode**: [`includes/class-scanner.php:1438-1490`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L1438-L1490)
* **Mekanisme Kerja**:
  1. Menggunakan `RecursiveIteratorIterator` pada direktori `wp-content/uploads/`.
  2. Secara eksplisit mengecualikan path direktori karantina (`wp-root-guard-quarantine/`) agar tidak terdeteksi berulang kali.
  3. Mendeteksi berkas dengan ekstensi script berbahaya yang dapat dieksekusi: `php`, `phtml`, `php3`, `php4`, `php5`, `php7`, `phps`, `phar`, `inc`.
* **Output Status**: `PHP File in Uploads` (Sangat Berbahaya).

### 2.4 Webshell Signature & Malware Pattern Matching
* **Implementasi Kode**: [`includes/class-scanner.php:673-731`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L673-L731)
* **Mekanisme Kerja**:
  - Membaca isi berkas berukuran < 1 MB dengan ekstensi `php`, `htaccess`, `html`, `txt`.
  - Mencocokkan isi file terhadap 24 signature regex statis:
    * Eksekusi Dinamis: `eval\(`, `create_function\(`, `assert\(`
    * Eksekusi Sistem/OS: `system\(`, `exec\(`, `shell_exec\(`, `passthru\(`, `popen\(`, `proc_open\(`, `pcntl_exec\(`
    * Dekompresi/Enkripsi: `base64_decode\(`, `gzinflate\(`, `gzuncompress\(`, `str_rot13\(`, `convert_uudecode\(`
    * Dynamic Execution: `\$_POST\s*\[\s*['"][a-zA-Z0-9_\-]+['"]\s*\]\s*\(`, `\$_GET...`
    * Backdoor Tags: `c99shell`, `r57shell`, `b374k`, `wso_version`, `marvins`, `alfa_data`.

---

## 3. Bedah Detail Fitur Remediasi (Remediation & Self-Healing)

### 3.1 Self-Healing Core Auto-Restore (SVN WordPress.org Upstream)
* **Implementasi Kode**: [`includes/class-scanner.php:498-595`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L498-L595)
* **Mekanisme Kerja**:
  1. Menerima `$relative_path` berkas yang rusak/termodifikasi.
  2. **Allowlist Prefix Check**: Hanya memproses berkas resmi (`wp-admin/`, `wp-includes/`, `wp-login.php`, `wp-settings.php`, `wp-load.php`, dll).
  3. **Path Traversal Strict Guard**: Memverifikasi jalur absolut dengan `realpath( ABSPATH )` untuk mencegah manipulasi URL-encoded traversal (`../`).
  4. Mengunduh kode sumber asli via HTTP GET ke:
     `https://core.svn.wordpress.org/tags/{$wp_version}/{$relative_path}`
  5. Menimpa berkas lokal yang rusak dengan kode asli dari SVN secara atomik.
  6. Melaporkan status sukses atau pesan kegagalan spesifik (timeout, HTTP error 404, atau write permission denied).

### 3.2 Visual Side-by-Side Diff Viewer
* **Implementasi Kode**: [`includes/class-scanner.php:603-665`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L603-L665) & Modal UI di [`admin/class-admin.php:753-814`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php#L753-L814)
* **Mekanisme Kerja**:
  1. Mengunduh konten resmi dari SVN WordPress.org secara on-the-fly.
  2. Membaca konten berkas lokal Anda.
  3. Menstandarkan baris (`str_replace("\r", "", ...)`) dan memecah menjadi array baris.
  4. Membandingkan baris per baris; perbedaan ditampung dalam array.
  5. **Safety Guard**: Membatasi perbedaan maksimal **300 baris** (`$max_diff = 300`) agar browser dan server tidak crash saat memproses berkas besar.
  6. Menampilkan tabel pembanding visual: kolom hijau (Resmi WordPress.org) vs kolom merah (Kode Lokal Anda).

### 3.3 Dedicated Quarantine Vault
* **Implementasi Kode**: [`includes/class-scanner.php:833-1021`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L833-L1021)
* **Lokasi Fisik**: `wp-content/uploads/wp-root-guard-quarantine/`
* **Mekanisme Kerja**:
  1. Direktori vault otomatis dilengkapi file pelindung:
     - `.htaccess`: Berisi aturan Apache 2.4 (`Require all denied`) dan Apache 2.2 (`Deny from all`).
     - `index.html`: Berisi komentar kosong untuk mencegah directory listing.
  2. Saat diisolasi, berkas/folder diganti namanya menjadi `__quarantine_{clean_name}_{timestamp}` lalu dipindahkan via `rename()` ke dalam vault.
  3. Menyimpan riwayat data isolasi di `wp_root_guard_quarantined_folders`.
  4. Mendukung pemulihan kembali (*Restore*) ke lokasi asal via `restore_quarantined_folder()` atau penghapusan permanen via `delete_quarantined_folder_permanently()`.

### 3.4 Floating Sticky Bulk Action Toolbar
* **Implementasi Kode**: [`admin/class-admin.php:941-962`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php#L941-L962) & [`admin/class-admin.php:306-365`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php#L306-L365)
* **Fitur**:
  - Toolbar melayang (*sticky*) saat pengguna menggeser (*scroll*) halaman.
  - Multi-checkbox terintegrasi lintas tabel.
  - Opsi Aksi Massal:
    * `bulk_fix_core`: Memperbaiki seluruh berkas core yang dipilih via SVN dalam 1 klik.
    * `bulk_trust`: Menambahkan banyak item sekaligus ke Custom Whitelist.
    * `bulk_quarantine`: Mengisolasi banyak berkas/folder asing ke Quarantine Vault.
    * `bulk_delete`: Menghapus permanen banyak berkas penyusup sekaligus dari server.

---

## 4. Bedah Detail Fitur Proteksi Aktif (Prevention & Blocking)

### 4.1 HTTP Malicious Request Interceptor
* **Implementasi Kode**: [`includes/class-blocker.php:49-120`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-blocker.php#L49-L120)
* **Hook**: `init` dengan prioritas **1** (dieksekusi sebelum modul WordPress lain berjalan).
* **Mekanisme Pengecekan**:
  1. **Exclusion Guard**: Tidak pernah mencegat pengguna dengan kapabilitas `manage_options` atau saat berada di area `is_admin()`.
  2. **Aturan 1 (Uploads Execution)**: Memeriksa apakah `$_SERVER['REQUEST_URI']` mengarah ke folder `/wp-content/uploads/` dengan ekstensi eksekusi script.
  3. **Aturan 2 (Webshell Queries)**: Memeriksa apakah `$_SERVER['QUERY_STRING']` mengandung parameter `cmd=`, `shell=`, `c99=`, `r57=`, `eval(`, atau `base64_decode(`.
  4. **Aturan 3 (Blacklist Check)**: Memeriksa apakah IP klien terdaftar di array IP terblokir.
  5. **Respon**: Mengirimkan header `HTTP/1.1 403 Forbidden` dan menampilkan template peringatan blokir custom informatif.

### 4.2 Dynamic `.htaccess` IP Blocker & PHP Fallback
* **Implementasi Kode**: [`includes/class-blocker.php:129-254`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-blocker.php#L129-L254)
* **Mekanisme Kerja**:
  1. Menyimpan data IP penyerang di opsi `wp_root_guard_blocked_ips`.
  2. Menyinkronkan daftar IP ke berkas root `.htaccess` di antara marker:
     ```apache
     # BEGIN WP Root Guard Blocked IPs
     <IfModule mod_authz_core.c>
         Require not ip 1.2.3.4
     </IfModule>
     <IfModule !mod_authz_core.c>
         Order allow,deny
         Allow from all
         Deny from 1.2.3.4
     </IfModule>
     # END WP Root Guard Blocked IPs
     ```
  3. **Fallback Nginx / IIS**: Jika server web tidak memproses `.htaccess`, pengecekan IP otomatis dijalankan di tingkat PHP via `Blocker::intercept_malicious_requests()`.

---

## 5. Bedah Detail Fitur Forensik & Monitoring

### 5.1 Secure Code Inspector (Modal Viewer)
* **Implementasi Kode**: [`includes/class-scanner.php:739-830`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L739-L830) & AJAX di [`admin/class-admin.php:559-575`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php#L559-L575)
* **Mekanisme Kerja**:
  1. Administrator mengklik tombol `👁️ Lihat Isi` pada berkas apa pun (tabel temuan, karantina, atau whitelist).
  2. Validasi Path Traversal ketat via `realpath()`.
  3. File dibaca baris per baris secara read-only.
  4. **Malware Highlighting**: Setiap baris kode dipindai secara terpisah. Jika baris mengandung signature berbahaya (seperti `eval` atau `shell_exec`), baris tersebut diberi sorotan warna merah dan label bahaya.
  5. Menghitung total skor bahaya (*total dangers*) dan menampilkannya pada header modal.

### 5.2 Activity Logger & UTF-8 CSV Export
* **Implementasi Kode**: [`includes/class-logger.php:21-77`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-logger.php#L21-L77) & [`admin/class-admin.php:447-480`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php#L447-L480)
* **Mekanisme Kerja**:
  1. Mencatat seluruh event keamanan (Scan Selesai, Folder Terdeteksi, Berkas Dipulihkan, IP Diblokir, Baseline Direset).
  2. Membatasi riwayat maksimal **100 entri terbaru** (rolling ring-buffer).
  3. **Ekspor CSV**: Mengunduh seluruh log ke berkas `.csv` dengan penulisan Byte Order Mark `\xEF\xBB\xBF` (UTF-8 BOM) sehingga karakter aksen dan penanggalan Indonesia terbaca sempurna di Microsoft Excel.
  4. **Paginasi Dinamis**: Menampilkan 20 entri pertama, dengan tombol ekspansi tanpa perlu reload halaman.

### 5.3 Multi-Channel Incident Alerting (Telegram & Email)
* **Implementasi Kode**: [`includes/class-scanner.php:1241-1408`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-scanner.php#L1241-L1408)
* **Mekanisme Kerja**:
  1. **Anti-Spam State Tracking**: Mengkomparasi temuan terhadap riwayat `wp_root_guard_notified_threats`. Notifikasi hanya dikirim jika ditemukan ancaman baru.
  2. Format penanggalan menggunakan standar **WIB (Asia/Jakarta UTC+7)** dengan nama bulan berbahasa Indonesia (`Scanner::get_wib_time()`).
  3. Mengirimkan rincian: Nama berkas, Path, Status proteksi, Indikasi malware, dan Tautan instan ke Dashboard Admin.
  4. Pengiriman Telegram menggunakan metode HTTP POST ke endpoint `https://api.telegram.org/bot{token}/sendMessage` dengan format Markdown.

---

## 6. Bedah Detail Fitur Pemeliharaan & Ekosistem

### 6.1 Interactive AJAX Scanner & Rate Limiting
* **Implementasi Kode**: [`admin/class-admin.php:534-555`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php#L534-L555) & JS di [`admin/class-admin.php:1726-1790`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/admin/class-admin.php#L1726-L1790)
* **Mekanisme Kerja**:
  1. Tombol "Pindai Sekarang" menampilkan panel scanner animasi futuristik (*pulse wave & progress bar*).
  2. Mengambil antrean berkas/folder via `ajax_get_scan_queue` untuk visualisasi persentase 0%–100%.
  3. **Rate Limiting Guard**: Dibatasi maksimal 1 kali scan setiap 20 detik per user menggunakan Transients API `wprg_scan_rate_{user_id}` untuk mencegah request flood ke server.

### 6.2 GitHub Auto-Updater Integration
* **Implementasi Kode**: [`includes/class-updater.php:72-245`](file:///mnt/storage/PuTI/project/wp-root-guard-plugins/includes/class-updater.php#L72-L245)
* **Mekanisme Kerja**:
  1. Terhubung langsung ke GitHub Releases API (`repos/halimurrosyid/wp-root-guard-plugins/releases/latest`).
  2. Menyimpan respon rilis di Transient API selama 12 jam (`wp_root_guard_latest_github_release`).
  3. Membandingkan `WP_ROOT_GUARD_VERSION` dengan `tag_name` rilis remote via `version_compare()`.
  4. Menyuntikkan URL paket download `.zip` ke transient `update_plugins` WordPress untuk pembaruan native 1-klik.

---

## 7. Celah & Keterbatasan Teknis Fitur (Technical Gaps)

Dari deep scan kode di atas, berikut adalah keterbatasan fitur aktual yang ada di codebase saat ini:

1. **Ketiadaan Auto-Expire IP Blocker**:
   - IP yang diblokir di `Blocker::block_ip()` tidak memiliki timestamp kedaluwarsa. IP tersimpan selamanya di `.htaccess` kecuali dihapus manual satu-per-satu oleh administrator.
2. **Ketiadaan Auto-Rebuild Baseline pada Core Update**:
   - Saat WordPress auto-update, berkas core baru resmi akan dianggap sebagai *Modified Core File* sampai admin menekan tombol *Rebuild Baseline* manual.
3. **Penyimpanan Log di `wp_options` dengan Default Autoload**:
   - `wp_root_guard_logs` disimpan via `update_option()`. Karena tidak diset `autoload = 'no'`, array 100 entri log selalu di-load ke RAM PHP pada setiap request web publik.
4. **Signature Matching Masih Statis**:
   - Belum mendeteksi payload terobfuskasi modern (variabel bertopeng `$$`, konkatenasi string dinamis `'e'.'v'.'a'.'l'`, atau pemanggilan terenkripsi hex/chr).
5. **Kredensial Default Telegram Masih Tercantum**:
   - Opsi default `telegram_bot_token` dan `telegram_chat_id` di `class-settings.php` masih memuat token developer secara hardcoded.
