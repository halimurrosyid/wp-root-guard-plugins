# WP Root Guard

🛡️ **WP Root Guard** adalah plugin WordPress yang sangat ringan dan efisien untuk mendeteksi folder, berkas asing, serta menjaga integritas berkas core di direktori root website Anda (`ABSPATH` / `public_html`), serta folder sistem `wp-admin` dan `wp-includes`. Plugin ini ditujukan untuk mendeteksi penyusupan malware (seperti judi slot atau webshell PHP) secara cepat dan melakukan pemulihan mandiri (*self-healing*) secara otomatis dari server resmi WordPress.org.

---

## Fitur Utama

- **Pemindaian Hemat Daya & Cepat**: Menggabungkan pemindaian folder root tingkat pertama secara non-rekursif dengan pencocokan nama berkas core yang instan, sehingga hemat sumber daya server.
- **Integritas Berkas Core (Core File Integrity Scanner) [BARU v1.3.0]**: Menghubungi API resmi WordPress.org untuk mengambil hash MD5 berkas asli. Mendeteksi jika berkas core WordPress di root, `wp-admin/`, dan `wp-includes/` mengalami perubahan isi (*Modified*) atau hilang (*Missing*).
- **Deteksi File Penyusup Core (Core Injection Detection) [BARU v1.3.0]**: Mendeteksi adanya berkas asing baru yang tidak dikenal yang ditanam di dalam folder sensitif `wp-admin/` dan `wp-includes/`.
- **Perbandingan Perbedaan Kode (Diff Viewer) [BARU v1.3.0]**: Menampilkan tabel pembanding visual kode baris per baris (*side-by-side code diff*) antara kode berkas lokal Anda (merah) dan kode resmi dari WordPress.org (hijau).
- **Perbaikan Otomatis Mandiri (Self-Healing / Auto-Restore) [BARU v1.3.0]**: Menyediakan tombol **Perbaiki Berkas** untuk mengunduh kode asli berkas core langsung dari server SVN resmi WordPress.org dan menimpa berkas lokal yang rusak dengan aman.
- **Karantina Otomatis (Auto-Quarantine)**: Secara otomatis mengisolasi folder asing, berkas asing root, dan berkas penyusup asing di folder core dengan memindahkannya ke direktori karantina dan memblokir akses web menggunakan `.htaccess`.
- **Notifikasi Telegram & Email**: Mengirim peringatan *real-time* instan ke Telegram Bot dan Email Administrator begitu ada ancaman baru terdeteksi, dilengkapi fitur anti-spam (hanya sekali kirim per temuan baru).
- **Pembaruan Otomatis dari GitHub**: Terintegrasi dengan pembaruan otomatis bawaan WordPress yang terhubung langsung ke rilis GitHub ini.

---

## Log Pembaruan (Changelog)

### v3.0.2 (27 Juli 2026)
- **Kompatibilitas NGINX / IIS**: Menambahkan pengecekan IP terblokir di tingkat PHP sebagai fallback untuk server web yang tidak memproses aturan `.htaccess`.
- **Audit & Pemantapan Stabilitas**: Pembersihan total bug tipe data, perbaikan penanganan exception, dan penguatan keamanan menyeluruh.

### v3.0.1 (27 Juli 2026)
- **Perbaikan Bug Kritis (Critical Error Fix)**: Memperbaiki *switch fall-through* di `handle_admin_actions` yang memicu fatal error `Cannot modify header information`.
- **Perbaikan Akses Administrator**: `Blocker::intercept_malicious_requests()` kini mengeksklusi area admin (`is_admin()` & `manage_options`) agar Administrator tidak pernah terblokir.
- **Type Safety**: Menambahkan sanitasi string pada daftar notifikasi `$notified` sebelum `array_intersect()` untuk mencegah `TypeError: Array to string conversion`.
- **Log Safeguards**: Menambahkan penanganan `is_array()` dan `isset()` pada pembacaan entri log aktivitas.

### v3.0.0 (27 Juli 2026)
- **Fitur Baru**: **Export Log CSV** — tombol unduh log aktivitas ke file `.csv` dengan encoding UTF-8 (kompatibel Excel) kini tersedia di header tabel log.
- **Fitur Baru**: **Paginasi Log** — log ditampilkan 20 entri terbaru terlebih dahulu. Entri lama dapat dibuka dengan tombol "Tampilkan Log Lainnya" tanpa reload halaman.
- **Fitur Baru**: **Badge Jumlah Entri Log** — jumlah total entri log ditampilkan sebagai badge informatif di header tabel.
- **Keamanan**: **Rate Limiting AJAX Scan** — pemindaian via AJAX kini dibatasi 1x per 20 detik per pengguna menggunakan WordPress Transients API untuk mencegah flood/penyalahgunaan.
- **Perbaikan Bug Kritis**: `scan_uploads_for_php_files()` kini **mengeksklusi folder karantina** (`wp-root-guard-quarantine/`) — berkas yang sudah dikarantina tidak lagi muncul berulang sebagai ancaman baru.
- **Perbaikan Bug**: Notifikasi email/Telegram kini **benar-benar per-ancaman** — ancaman baru yang menggantikan ancaman lama yang sudah ditangani akan selalu mengirim notifikasi baru.
- **Perbaikan**: `get_file_diff()` dibatasi maksimal 300 baris perbedaan untuk mencegah timeout/lambat pada berkas core berukuran besar.

### v2.9.0 (27 Juli 2026)
- **Keamanan**: Penguatan proteksi **Path Traversal** di 4 fungsi kritis (`inspect_file_content`, `restore_core_file`, `get_file_diff`, `delete_file_directly`) menggunakan `realpath()` — mencegah serangan via path URL-encoded atau double-slash.
- **Keamanan**: Tambahan validasi allowlist prefix path pada `restore_core_file()` — hanya berkas core WordPress resmi (`wp-admin/`, `wp-includes/`, dll) yang dapat dipulihkan.
- **Bug Fix**: `enable_ip_blocker` kini benar-benar tersimpan saat klik Simpan Pengaturan (sebelumnya toggle tidak berfungsi karena field tidak dikirim ke backend).
- **Bug Fix**: Tabel **Folder Asing** kini punya tombol **Karantina** yang sebelumnya hilang, konsisten dengan tabel ancaman lainnya.
- **Bug Fix**: HTML wrapper `<div class="rg-card">` yang hilang di Tabel 1 dan Tabel 2 telah diperbaiki — styling card kini konsisten.
- **Bug Fix**: Teks *empty state* Tabel 1 dan 3 yang masih bahasa Inggris telah diterjemahkan ke Bahasa Indonesia.
- **Perbaikan**: Pesan sukses uji coba Telegram diperbarui — tidak lagi salah menyebut "Tombol Interaktif".
- **Perbaikan**: `uninstall.php` kini membersihkan **semua opsi database** dan blok IP di `.htaccess` secara otomatis saat plugin dihapus permanen.

### v2.8.0 (27 Juli 2026)
- **Redesain Tampilan & UI/UX Mayor**: **Sticky Floating Bulk Action Bar & Intuitive Threat Badging** — Bar Aksi Massal kini melayang secara dinamis (*Sticky*) saat pengguna menggeser (*scroll*) halaman, dilengkapi *Badge Ringkasan Jumlah Ancaman* pada setiap header tabel, dan penyempurnaan tombol aksi agar jauh lebih intuitif dan mudah digunakan.

### v2.7.0 (27 Juli 2026)
- **Fitur Utama Baru**: **Pemulihan Berkas Core Masal (Bulk Core Auto-Repair)** — Menambahkan pilihan `🛠️ Perbaiki Core Masal (Unduh dari WordPress.org)` pada *Bar Aksi Massal (Bulk Actions)*. Administrator kini dapat mencentang semua berkas core yang terindikasi berubah/dimodifikasi lalu menekan tombol **Terapkan (Apply)** untuk memulihkan seluruh berkas tersebut secara otomatis langsung dari SVN resmi WordPress.org dalam 1 kali klik.

### v2.6.0 (27 Juli 2026)
- **Fitur Baru**: **Kolom Waktu Modifikasi Berkas Core (WIB)** — Menambahkan kolom *Waktu Modifikasi / Terdeteksi* pada Tabel Integritas Berkas Core (`wp-admin`, `wp-includes`, `root`) dengan format Waktu Indonesia Barat (WIB), sehingga Administrator dapat melihat tanggal dan jam tepat kapan berkas core dimodifikasi atau disusupi.

### v2.5.1 (27 Juli 2026)
- **Bugfix & Akurasi Pemindaian**: **Penyelesaian Diskrepan Line-Ending (CRLF vs LF)** — Menambahkan normalisasi otomatis karakter perpindahan baris (`\r\n` ke `\n`) saat menghitung MD5 hash berkas core, sehingga berkas asli resmi tidak akan lagi mengalami *false positive* (terdeteksi dimodifikasi padahal kodenya sama persis).

### v2.5.0 (27 Juli 2026)
- **Refactoring Keamanan Utama**: **Pure 100% Read-Only Telegram Notification Architecture** — Menghapus seluruh fungsionalitas Webhook REST API eksekusi jarak jauh, sehingga notifikasi Telegram kembali murni 100% *Read-Only Notification* (hanya mengirim informasi peringatan tanpa membuka akses endpoint eksekusi eksternal), menjamin tingkat keamanan tertinggi bagi situs web Anda.

### v2.4.1 (27 Juli 2026)
- **Bugfix**: Perbaikan *Fatal Error* saat pendaftaran/sinkronisasi Webhook Telegram akibat belum di-impornya namespace `use WPRootGuard\TelegramWebhook;` pada berkas `admin/class-admin.php`.

### v2.4.0 (27 Juli 2026)
- **Fitur Utama Mayor**: **Tombol Aksi Interaktif Telegram & REST API Webhook Remote Execution System** — Penambahan papan tombol interaktif (*Inline Keyboard Buttons*) langsung pada notifikasi Telegram untuk eksekusi 1-klik: **🔒 Karantina**, **🛡️ Whitelist**, dan **🗑️ Hapus Permanen**. Dilengkapi 4 lapis keamanan kriptografi tanpa celah (*X-Telegram-Bot-Api-Secret-Token 64-bit*, *HMAC-SHA256 Signed Payload*, *Telegram Chat ID Authorization Lock*, dan *Path Traversal Strict Guard*).

### v2.3.1 (24 Juli 2026)
- **Bugfix**: Perbaikan pengabaian Whitelist Kustom (`user_whitelist`) pada berkas terdaftar yang mengalami perubahan nilai hash MD5 (seperti `.htaccess`), sehingga berkas yang sudah dipercayai tidak akan lagi dimunculkan kembali sebagai ancaman modifikasi.

### v2.3.0 (24 Juli 2026)
- **Fitur Baru**: **WIB Timezone Standardization (Asia/Jakarta UTC+7)** — Format penanggalan dan waktu pada notifikasi Telegram, notifikasi Email, tabel karantina, tabel IP terblokir, serta Log Aktivitas Keamanan kini secara penuh distandarkan menggunakan zona waktu Indonesia (WIB) berformat Bahasa Indonesia (contoh: `24 Juli 2026 15:12 WIB`).

### v2.2.0 (24 Juli 2026)
- **Fitur Baru**: **Zero-Configuration Telegram Multi-Site Deployment** — Penerapan Kredensial Default Telegram Bot Token & Chat ID secara otomatis, sehingga plugin langsung aktif terhubung ke Telegram begitu dipasang di situs web mana pun tanpa perlu melakukan pengaturan ulang secara manual.

### v2.1.2 (24 Juli 2026)
- **UX Update**: Pengayaan deskripsi lengkap dan instruksi instalasi pada pop-up modal detail rilis plugin di dasbor WordPress (`plugins_api`), sehingga informasi fitur unggulan tampil dengan lengkap dan rapi.

### v2.1.1 (24 Juli 2026)
- **Bugfix**: Perbaikan *Fatal Error* / *HTTP Error 500* saat pengiriman pesan uji coba Telegram karena belum terdeklarasikannya metode `Scanner::send_telegram_message()`.

### v2.1.0 (24 Juli 2026)
- **Fitur Baru**: **Inspektur Kode Universal (Universal Code Inspection)** — Penambahan tombol **`👁️ Lihat Isi`** pada seluruh tabel di dasbor, termasuk pada tabel **Daftar Karantina** dan **Whitelist Kustom**, sehingga Anda dapat menginspeksi isi berkas kapan pun di mana pun dengan aman.

### v2.0.0 (24 Juli 2026)
- **Fitur Baru & Arsitektur Mayor**: **Vault Karantina Terisolasi Khusus (Dedicated Quarantine Vault)** — Seluruh berkas dan folder yang dikarantina kini dipindahkan ke direktori khusus `wp-content/uploads/wp-root-guard-quarantine/` yang secara otomatis dilindungi aturan `.htaccess` berlapis (`Require all denied` / `Deny from all`) dan `index.html` tersembunyi. Direktori root `public_html` Anda kini 100% rapi dan bebas dari file berpola `__quarantine_`.

### v1.9.1 (24 Juli 2026)
- **Bugfix & UX Update**: Perbaikan gaya CSS pada pop-up modal *Inspektur Kode Berkas* agar tersembunyi (`display: none`) secara otomatis pada saat halaman dimuat, serta penambahan indikator persentase pemuatan (*loading progress bar* 0% - 100%) dan tombol tutup instan (ESC / tombol &times;).

### v1.9.0 (23 Juli 2026)
- **Fitur Baru**: **Inspektur Kode Berkas (Secure Code Inspector)** — Fitur pop-up modal inspeksi isi berkas read-only yang aman lengkap dengan penandaan warna stabilo merah otomatis (*Malware Signature Highlighting*) pada setiap baris kode yang mengandung fungsi webshell berbahaya (`eval`, `base64_decode`, `shell_exec`, `system`, `passthru`, `gzinflate`, dll).

### v1.8.1 (23 Juli 2026)
- **Bugfix**: Perbaikan *Fatal Error* pemanggilan `use WPRootGuard\Blocker;` pada file admin yang sempat menyebabkan bagian bawah dasbor (termasuk Log Aktivitas) terhenti saat proses render.

### v1.8.0 (23 Juli 2026)
- **Fitur Baru**: **Blocker Akses Webshell & IP Penyerang (.htaccess)** — Sistem pencegatan otomatis untuk percobaan eksekusi berkas PHP di folder media `uploads/` dan query string webshell injection, serta pemblokiran otomatis IP penyerang di berkas root `.htaccess` dengan penguncian instant 403 Forbidden.

### v1.7.0 (23 Juli 2026)
- **Fitur Baru**: **Fitur Aksi Massal (Bulk Actions)** — Penambahan checkbox checklist pada setiap tabel temuan scan dan toolbar *Bulk Action Bar* untuk mengeksekusi penanganan massal (*Trust*, *Karantina*, atau *Hapus Permanen*) pada banyak ancaman sekaligus dengan 1-klik.

### v1.6.0 (23 Juli 2026)
- **Fitur Baru**: **Uploads PHP Security Guard** — Pemindaian rekursif otomatis pada direktori `wp-content/uploads/` untuk mengisolasi, mendeteksi, dan menghapus berkas eksekusi PHP atau webshell berbahaya yang ditanam hacker di folder media unggahan.

### v1.5.0 (23 Juli 2026)
- **Penyempurnaan Tampilan UI**: Perbaikan dan penataan ulang tampilan kartu *Status Perlindungan* (AMAN/BAHAYA) menggunakan tata letak flexbox modern agar ikon dan teks tidak bertumpuk di browser apapun.
- **Fitur Baru**: Fitur Pengaturan **Jadwal Pemindaian Otomatis (Scan Schedule)** pada tab Pengaturan dengan pilihan interval: *Setiap 5 Menit, 15 Menit, 30 Menit, 1 Jam, 12 Jam, dan 24 Jam*.

### v1.4.3 (23 Juli 2026)
- **Fitur Baru**: Penambahan tombol aksi **`🗑️ Hapus`** (Delete Directly) pada tabel Integritas Core dan Berkas Asing Root untuk memfasilitasi penghapusan langsung file penyusup/sampah tanpa perlu dikarantina terlebih dahulu.

### v1.4.2 (23 Juli 2026)
- **Penyempurnaan**: Pembaruan URL informasi plugin dan tautan situs pembuat ke halaman profil staf Telkom University.

### v1.4.1 (23 Juli 2026)
- **Perbaikan**: Penyempurnaan sistem pembaruan otomatis (Auto-Updater) langsung dari dasbor WordPress via filter `site_transient_update_plugins` untuk injeksi notifikasi versi baru secara instan.

### v1.4.0 (14 Juli 2026)
- **Penyempurnaan**: Kepatuhan penuh terhadap standar koding WordPress (WPCS) termasuk *prefixing* nama fungsi global (`wp_root_guard_*`), pembersihan *output escaping*, dan penambahan anotasi Linter.

### v1.3.0 (14 Juli 2026)
- **Fitur Baru**: Integrasi dengan API Checksums resmi WordPress.org untuk verifikasi keaslian berkas core.
- **Fitur Baru**: Deteksi berkas core yang dirubah (*Modified*), hilang (*Missing*), atau berkas asing penyusup (*Injection*) di folder `wp-admin` dan `wp-includes`.
- **Fitur Baru**: Penambahan Visualisasi Perbedaan Kode (Diff Viewer) baris-per-baris dengan sorotan warna merah/hijau.
- **Fitur Baru**: Penambahan tombol aksi Perbaikan Otomatis (*Self-Healing / Restore*) untuk memulihkan berkas core dari SVN WordPress.org secara instan.
- **Penyempurnaan**: Pemisahan tabel dasbor khusus untuk Integritas Berkas Core dan fungsionalitas karantina berkas core asing.

### v1.2.0 (14 Juli 2026)
- **Fitur Baru**: Menambahkan deteksi Berkas Asing baru di root.
- **Fitur Baru**: Menambahkan pengecekan Integritas Berkas (kalkulasi hash MD5 baseline) untuk mendeteksi modifikasi berkas core di tingkat root.
- **Fitur Baru**: Menambahkan Pemindai Tanda Tangan Webshell untuk mendeteksi fungsi PHP berbahaya (seperti `eval`, `base64_decode`).

### v1.1.0 (14 Juli 2026)
- **Fitur Baru**: Menambahkan sistem Karantina Otomatis (Auto-Quarantine) dengan penguncian akses `.htaccess`.
- **Fitur Baru**: Menambahkan Notifikasi Peringatan Instan ke Telegram Bot API dan Email Administrator.
- **Fitur Baru**: Menambahkan Tab Pengaturan (Settings) di dasbor admin.

---

## Instalasi

1. Unduh repositori ini sebagai ZIP atau ambil berkas `wp-root-guard.zip`.
2. Unggah ke dasbor WordPress Anda melalui **Plugins -> Add New -> Upload Plugin**.
3. Aktifkan plugin.
4. Buka menu **Dashboard -> Root Guard** untuk mulai menggunakannya.

---

## Hak Cipta & Lisensi

- Pembuat: **Mujaddid Halimurrosyid**
- Situs Web: [ajidmujaddid.staff.telkomuniversity.ac.id](https://ajidmujaddid.staff.telkomuniversity.ac.id/)
- Lisensi: GPL v2 atau yang lebih baru.