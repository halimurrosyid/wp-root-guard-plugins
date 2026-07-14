=== WP Root Guard ===
Contributors: indahweb, mujaddid-halimurrosyid
Tags: security, slot, root, guard, slots, protection, malware, scanner
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 8.1
Stable tag: 1.2.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Mendeteksi folder dan berkas asing/mencurigakan yang muncul di root directory WordPress Anda untuk mencegah malware judi slot.

== Description ==

WP Root Guard adalah plugin keamanan WordPress yang sangat ringan dan efisien. Plugin ini dirancang khusus untuk mendeteksi folder dan berkas asing/mencurigakan yang muncul secara tiba-tiba di root directory WordPress Anda (seperti ABSPATH atau public_html), yang biasanya merupakan indikasi penyusupan malware judi slot atau webshell PHP.

Dengan pendekatan non-rekursif, plugin ini hanya memindai direktori tingkat pertama di root WordPress Anda dan membandingkannya dengan baseline aman. WP Root Guard sangat hemat sumber daya server dan cepat (selesai dalam hitungan milidetik).

== Installation ==

1. Unggah folder `wp-root-guard` ke direktori `/wp-content/plugins/`.
2. Aktifkan plugin melalui menu 'Plugins' di WordPress.
3. Buka menu 'Dashboard -> Root Guard' untuk mengelola dan melihat status keamanan.

== Frequently Asked Questions ==

= Apakah plugin ini melakukan pemindaian isi file? =
Ya, versi ini memindai isi berkas PHP asing baru atau berkas hasil modifikasi secara ringan untuk mendeteksi tanda tangan webshell berbahaya.

= Seberapa sering pemindaian otomatis berjalan? =
Secara default, pemindaian berjalan setiap 5 menit sekali menggunakan sistem WP Cron bawaan WordPress.

== Changelog ==

= 1.2.0 =
* Penambahan deteksi Berkas Asing baru di root.
* Penambahan pengecekan Integritas Berkas (kalkulasi hash MD5 baseline) untuk mendeteksi modifikasi berkas core (seperti index.php).
* Penambahan Pemindai Tanda Tangan Webshell untuk mendeteksi fungsi PHP berbahaya (seperti eval, base64_decode).
* Modifikasi sistem karantina agar mendukung pemindahan berkas asing secara aman.
* Pemisahan antarmuka dasbor dengan tabel khusus temuan berkas asing/dimodifikasi.

= 1.1.0 =
* Penambahan fitur Karantina Otomatis (Auto-Quarantine) dengan penguncian akses .htaccess.
* Penambahan sistem Notifikasi Peringatan Instan ke Telegram Bot API dan Email Administrator.
* Penambahan Tab Pengaturan (Settings) di dasbor admin.
* Modifikasi modul pemindaian agar mengabaikan direktori yang sedang dikarantina.

= 1.0.1 =
* Update informasi pembuat dan situs resmi (Mujaddid Halimurrosyid - indahweb.com).

= 1.0.0 =
* Rilis perdana dengan fitur Baseline, Pemindaian Root Non-rekursif, Whitelist Kustom, Notifikasi Admin, dan Dashboard Widget.
