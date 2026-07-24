=== WP Root Guard ===
Contributors: indahweb, mujaddid-halimurrosyid
Tags: security, slot, root, guard, slots, protection, integrity, scanner, self-healing, diff
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 8.1
Stable tag: 2.3.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Mendeteksi folder, berkas asing, perubahan berkas core (wp-admin, wp-includes, root), komparasi kode diff, dan perbaikan otomatis aman dari WordPress.org.

== Description ==

WP Root Guard adalah plugin keamanan WordPress profesional, super ringan, dan efisien yang dirancang khusus untuk melindungi direktori root (`public_html`), direktori sistem (`wp-admin` & `wp-includes`), serta folder media (`wp-content/uploads/`) dari serangan malware judi slot, backdoor, dan webshell injection.

Dengan integrasi API Checksums resmi WordPress.org, plugin ini dapat mendeteksi perubahan isi kode berkas core, kehilangan berkas core, atau adanya berkas asing penyusup di dalam folder core. Dilengkapi visualisasi komparasi perbedaan kode (diff view) dan tombol perbaikan otomatis untuk memulihkan berkas core dari SVN WordPress.org secara instan.

= Fitur Keamanan Unggulan =
* Integritas Core Checksums WordPress.org API: Mendeteksi modifikasi, pemalsuan, atau penghapusan berkas core resmi WordPress secara real-time.
* Perbaikan Berkas Core Otomatis: Memulihkan berkas core yang rusak/terinjeksi secara instan langsung dari SVN resmi WordPress.org.
* Uploads PHP Security Guard: Memindai dan mengisolasi berkas eksekusi PHP ilegal di dalam folder media wp-content/uploads/.
* Attacker IP Blocker & .htaccess Access Guard: Mencegat percobaan eksekusi webshell dan otomatis memblokir IP penyerang di .htaccess.
* Inspektur Kode Berkas (Secure Code Inspector): Menginspeksi isi berkas read-only yang aman dengan penandaan warna stabilo merah otomatis (Malware Signature Highlighting).
* Notifikasi Instan Real-Time: Pengiriman notifikasi peringatan instan ke Telegram Bot API dan Email Administrator.
* Vault Karantina Terisolasi Khusus: Menyimpan seluruh berkas terisolasi di wp-content/uploads/wp-root-guard-quarantine/ yang dikunci ketat dengan .htaccess.

== Installation ==

1. Unggah folder `wp-root-guard` ke direktori `/wp-content/plugins/`.
2. Aktifkan plugin melalui menu 'Plugins' di WordPress.
3. Buka menu 'Dashboard -> Root Guard' untuk melihat status keamanan.

== Frequently Asked Questions ==

= Apakah fitur perbaikan berkas core aman digunakan? =
Ya, fitur perbaikan mengunduh berkas core asli secara langsung dari server SVN resmi WordPress.org sesuai versi WordPress terpasang Anda, lalu menimpanya dengan aman.

= Apakah plugin ini memindai folder wp-content? =
Tidak, karena wp-content berisi berkas dinamis tema, plugin ini berfokus mengamankan area sistem core WordPress (root, wp-admin, wp-includes) serta mendeteksi berkas eksekusi PHP ilegal di folder uploads media.

== Changelog ==

= 2.3.1 =
* Perbaikan komprehensif pada pengabaian Whitelist Kustom (user_whitelist) untuk berkas terdaftar yang mengalami perubahan integritas/hash (seperti .htaccess).

= 2.3.0 =
* Standarisasi Zona Waktu Indonesia Barat (WIB / Asia/Jakarta UTC+7) pada seluruh notifikasi Telegram, email, tabel karantina, tabel IP terblokir, dan log aktivitas keamanan.

= 2.2.0 =
* Penerapan Kredensial Default Telegram Bot Token & Chat ID terkonfigurasi otomatis (Zero-Configuration Multi-Site Deployment).

= 2.1.2 =
* Pengayaan deskripsi rincian fitur keamanan lengkap dan instruksi instalasi di modal detail plugin WordPress (plugins_api).

= 2.1.1 =
* Perbaikan Fatal Error / Error 500 saat melakukan uji coba kirim notifikasi Telegram (penambahan metode send_telegram_message yang hilang).

= 2.1.0 =
* Penambahan Tombol Lihat Isi (Code Inspector) pada seluruh tabel dasbor termasuk Daftar Karantina dan Whitelist Kustom.

= 2.0.0 =
* Rilis Utama: Pemindahan seluruh berkas dan folder karantina ke folder khusus terisolasi wp-content/uploads/wp-root-guard-quarantine/ dengan proteksi .htaccess berlapis agar direktori root public_html tetap bersih.

= 1.9.1 =
* Perbaikan gaya tampilan modal Inspektur Kode agar tersembunyi (display: none) secara default pada saat halaman dimuat.
* Penambahan indikator persentase pemuatan (0% - 100%) dan tombol tutup instan (&times; dan ESC).

= 1.9.0 =
* Penambahan Fitur Inspektur Kode Berkas (Secure Code Inspector) dengan penandaan warna stabilo merah otomatis (Malware Signature Highlighting) untuk bagian kode berbahaya.

= 1.8.1 =
* Perbaikan Fatal Error terkait pemanggilan kelas Blocker namespace yang menyebabkan bagian log hilang.

= 1.8.0 =
* Penambahan Fitur Blocker Akses Webshell & IP Penyerang Otomatis (Attacker IP Blocker via .htaccess).

= 1.7.0 =
* Penambahan Fitur Aksi Massal (Bulk Actions) dengan checkbox pada seluruh tabel hasil temuan scan untuk Trust, Karantina, atau Hapus Permanen sekaligus.

= 1.6.0 =
* Penambahan Pemindai Keamanan Berkas PHP di Folder Uploads (wp-content/uploads/ Security Guard).
* Isolasi dan karantina otomatis untuk berkas eksekusi PHP atau webshell yang disisipkan di dalam direktori media uploads.

= 1.5.0 =
* Penataan ulang tampilan Status Card (Aman/Bahaya) menggunakan flexbox modern anti-tumpang tindih.
* Penambahan fitur Pengaturan Jadwal Pemindaian Otomatis (5 Menit, 15 Menit, 30 Menit, 1 Jam, 12 Jam, 24 Jam).

= 1.4.3 =
* Penambahan tombol aksi Hapus Permanen (Delete Directly) untuk berkas asing/penyusup tanpa perlu melalui tahap karantina.

= 1.4.2 =
* Pembaruan URL informasi plugin dan tautan situs pembuat ke profil Telkom University.

= 1.4.1 =
* Perbaikan dan penyempurnaan sistem pembaruan otomatis (Auto-Updater) langsung dari dasbor WordPress via filter site_transient_update_plugins.

= 1.4.0 =
* Penyesuaian penuh dengan WordPress Coding Standards (WPCS): prefixing fungsi global, escaping output keamanan, dan anotasi phpcs.

= 1.3.0 =
* Penambahan verifikasi integritas berkas core via API Checksums resmi WordPress.org.
* Deteksi berkas core yang dirubah (Modified), hilang (Missing), atau disisipkan (Injected) di folder wp-admin dan wp-includes.
* Penambahan pembanding kode visual (Diff Viewer) baris-per-baris lokal vs asli resmi.
* Penambahan fitur perbaikan otomatis (Self-Healing / Restore) berkas core dari SVN WordPress.org.

= 1.2.0 =
* Penambahan deteksi Berkas Asing baru di root.
* Penambahan pengecekan Integritas Berkas (kalkulasi hash MD5 baseline) di root.
* Penambahan Pemindai Tanda Tangan Webshell untuk mendeteksi fungsi PHP berbahaya (seperti eval, base64_decode).

= 1.1.0 =
* Penambahan fitur Karantina Otomatis (Auto-Quarantine) dengan penguncian akses .htaccess.
* Penambahan sistem Notifikasi Peringatan Instan ke Telegram Bot API dan Email Administrator.
* Penambahan Tab Pengaturan (Settings) di dasbor admin.
