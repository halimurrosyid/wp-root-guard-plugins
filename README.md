# WP Root Guard

🛡️ **WP Root Guard** adalah plugin WordPress yang sangat ringan dan efisien untuk mendeteksi folder dan berkas asing/mencurigakan yang muncul di direktori root website WordPress Anda (`ABSPATH` / `public_html`). Plugin ini ditujukan untuk mendeteksi penyusupan malware (seperti judi slot atau webshell PHP) secara cepat tanpa membebani kinerja server.

---

## Fitur Utama

- **Pemindaian Non-Rekursif**: Hanya memindai direktori tingkat pertama di root WordPress. Tidak membaca file atau masuk ke subfolder (seperti `wp-content`), sehingga proses scan selesai dalam waktu kurang dari 0.01 detik dan ramah sumber daya.
- **Learning Mode & Baseline (Folder & Berkas)**: Secara otomatis merekam folder dan seluruh berkas yang ada di root saat pertama kali diaktifkan sebagai "baseline" aman. Baseline disimpan dalam format JSON di `wp-content/uploads/wp-root-guard/baseline.json`.
- **Integritas Berkas Inti (File Integrity Check) [BARU v1.2.0]**: Mencatat hash MD5 dari seluruh berkas root standar. Jika ada modifikasi atau injeksi kode pada berkas inti (seperti `index.php`), plugin akan langsung membunyikan alarm bahaya.
- **Pemindai Tanda Tangan Webshell (Webshell Scanner) [BARU v1.2.0]**: Memindai isi berkas PHP asing atau berkas hasil modifikasi untuk mendeteksi fungsi-fungsi berbahaya seperti `eval()`, `base64_decode()`, `shell_exec()`, dll.
- **Karantina Otomatis (Auto-Quarantine)**: Secara otomatis mengamankan folder atau berkas asing terdeteksi dengan memindahkannya ke direktori karantina dan meletakkan file `.htaccess` berisi perintah `Deny from all` untuk memblokir akses web.
- ** whitelist & Pemulihan (Restore)**: Administrator dapat menandai folder/berkas asing sebagai "Trust" (Whitelist) atau memulihkannya kembali dari karantina.
- **Notifikasi Telegram & Email**: Mengirim peringatan *real-time* instan ke Telegram Bot dan Email Administrator begitu ada folder/berkas asing baru terdeteksi atau berkas inti dimodifikasi, dilengkapi fitur anti-spam (hanya sekali kirim per temuan baru).
- **Tab Pengaturan Terintegrasi**: Halaman konfigurasi di dasbor admin untuk mengelola sakelar Karantina Otomatis, pengiriman Notifikasi, serta tombol Kirim Uji Coba Telegram/Email.
- **Pembaruan Otomatis dari GitHub**: Terintegrasi dengan pembaruan otomatis bawaan WordPress yang terhubung langsung ke rilis GitHub ini.

---

## Log Pembaruan (Changelog)

### v1.2.0 (14 Juli 2026)
- **Fitur Baru**: Menambahkan deteksi Berkas Asing baru di root.
- **Fitur Baru**: Menambahkan pengecekan Integritas Berkas (kalkulasi hash MD5 baseline) untuk mendeteksi modifikasi berkas core (seperti `index.php` atau `wp-load.php`).
- **Fitur Baru**: Menambahkan Pemindai Tanda Tangan Webshell untuk mendeteksi fungsi PHP berbahaya (seperti `eval`, `base64_decode`).
- **Penyempurnaan**: Memodifikasi sistem karantina agar mendukung pemindahan berkas asing secara aman.
- **Penyempurnaan**: Memisahkan antarmuka dasbor dengan tabel visual khusus temuan berkas asing/dimodifikasi.

### v1.1.0 (14 Juli 2026)
- **Fitur Baru**: Menambahkan sistem Karantina Otomatis (Auto-Quarantine) dengan ganti nama otomatis dan penguncian akses `.htaccess`.
- **Fitur Baru**: Menambahkan Notifikasi Peringatan Instan ke Telegram Bot API dan Email Administrator.
- **Fitur Baru**: Menambahkan Tab Pengaturan (Settings) di dasbor admin dengan tombol Uji Coba Koneksi.
- **Penyempurnaan**: Memodifikasi modul pemindaian agar mengabaikan direktori yang sedang dikarantina.

### v1.0.1 (13 Juli 2026)
- Menambahkan integrasi GitHub Auto-Updater.
- Mengatur informasi kontak pembuat: Mujaddid Halimurrosyid dan situs resmi `indahweb.com`.
- Peningkatan keamanan nonce dan pembersihan direktori.

### v1.0.0 (13 Juli 2026)
- Rilis perdana plugin dengan arsitektur OOP dan namespace `WPRootGuard`.
- Fitur Baseline JSON, Scan Instan, Whitelist Kustom, Logger, WP Cron (5 Menit), dan Widget Dashboard.

---

## Instalasi

1. Unduh repositori ini sebagai ZIP atau ambil berkas `wp-root-guard.zip`.
2. Unggah ke dasbor WordPress Anda melalui **Plugins -> Add New -> Upload Plugin**.
3. Aktifkan plugin.
4. Buka menu **Dashboard -> Root Guard** untuk mulai menggunakannya.

---

## Hak Cipta & Lisensi

- Pembuat: **Mujaddid Halimurrosyid**
- Situs Web: [indahweb.com](https://indahweb.com)
- Lisensi: GPL v2 atau yang lebih baru.