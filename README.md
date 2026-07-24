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