=== WP Root Guard ===
Contributors: indahweb, mujaddid-halimurrosyid
Tags: security, slot, root, guard, slots, protection, integrity, scanner, self-healing, diff
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 8.1
Stable tag: 1.6.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Mendeteksi folder, berkas asing, perubahan berkas core (wp-admin, wp-includes, root), komparasi kode diff, dan perbaikan otomatis aman dari WordPress.org.

== Description ==

WP Root Guard adalah plugin keamanan WordPress yang sangat ringan dan efisien. Plugin ini dirancang khusus untuk mendeteksi folder, berkas asing, serta menjaga integritas berkas core di direktori root WordPress Anda (`ABSPATH` / `public_html`), serta folder sistem `wp-admin` dan `wp-includes` dari ancaman malware judi slot atau webshell backdoor.

Dengan integrasi API Checksums resmi WordPress.org, plugin ini dapat mendeteksi perubahan isi kode berkas core, kehilangan berkas core, atau adanya berkas asing penyusup di dalam folder core. Dilengkapi visualisasi komparasi perbedaan kode (diff view) dan tombol perbaikan otomatis untuk memulihkan berkas core dari SVN WordPress.org secara instan.

== Installation ==

1. Unggah folder `wp-root-guard` ke direktori `/wp-content/plugins/`.
2. Aktifkan plugin melalui menu 'Plugins' di WordPress.
3. Buka menu 'Dashboard -> Root Guard' untuk melihat status keamanan.

== Frequently Asked Questions ==

= Apakah fitur perbaikan berkas core aman digunakan? =
Ya, fitur perbaikan mengunduh berkas core asli secara langsung dari server SVN resmi WordPress.org sesuai versi WordPress terpasang Anda, lalu menimpanya dengan aman.

= Apakah plugin ini memindai folder wp-content? =
Tidak, karena wp-content berisi berkas dinamis tema, plugin, dan media unggahan Anda. WP Root Guard berfokus mengamankan area sistem core WordPress (root, wp-admin, wp-includes) untuk mencegah celah eksekusi backdoor utama.

== Changelog ==

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
