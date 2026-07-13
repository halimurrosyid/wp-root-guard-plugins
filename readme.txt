=== WP Root Guard ===
Contributors: indahweb, mujaddid-halimurrosyid
Tags: security, slot, root, guard, slots, protection, malware, scanner
Requires at least: 6.0
Tested up to: 6.6
Requires PHP: 8.1
Stable tag: 1.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Mendeteksi folder asing/mencurigakan yang muncul di root directory WordPress Anda untuk mencegah malware judi slot.

== Description ==

WP Root Guard adalah plugin keamanan WordPress yang sangat ringan dan efisien. Plugin ini dirancang khusus untuk mendeteksi folder asing/mencurigakan yang muncul secara tiba-tiba di root directory WordPress Anda (seperti ABSPATH atau public_html), yang biasanya merupakan indikasi penyusupan malware judi slot.

Dengan pendekatan non-rekursif, plugin ini hanya memindai direktori tingkat pertama di root WordPress Anda dan membandingkannya dengan baseline aman. WP Root Guard tidak memindai file atau membaca isi subfolder secara mendalam, menjadikannya sangat hemat sumber daya server dan cepat (selesai dalam hitungan milidetik).

== Installation ==

1. Unggah folder `wp-root-guard` ke direktori `/wp-content/plugins/`.
2. Aktifkan plugin melalui menu 'Plugins' di WordPress.
3. Buka menu 'Dashboard -> Root Guard' untuk mengelola dan melihat status keamanan.

== Frequently Asked Questions ==

= Apakah plugin ini melakukan pemindaian file? =
Tidak, versi pertama ini hanya mendeteksi folder baru yang mencurigakan di direktori root tingkat pertama.

= Seberapa sering pemindaian otomatis berjalan? =
Secara default, pemindaian berjalan setiap 5 menit sekali menggunakan sistem WP Cron bawaan WordPress.

== Changelog ==

= 1.0.1 =
* Update informasi pembuat dan situs resmi (Mujaddid Halimurrosyid - indahweb.com).

= 1.0.0 =
* Rilis perdana dengan fitur Baseline, Pemindaian Root Non-rekursif, Whitelist Kustom, Notifikasi Admin, dan Dashboard Widget.
