# WP Root Guard

🛡️ **WP Root Guard** adalah plugin WordPress yang sangat ringan dan efisien untuk mendeteksi folder asing/mencurigakan yang muncul di direktori root website WordPress Anda (`ABSPATH` / `public_html`). Plugin ini ditujukan untuk mendeteksi penyusupan malware (seperti folder judi slot) secara cepat tanpa membebani kinerja server.

---

## Fitur Utama

- **Pemindaian Non-Rekursif**: Hanya memindai direktori tingkat pertama di root WordPress. Tidak membaca file atau masuk ke subfolder (seperti `wp-content`), sehingga proses scan selesai dalam waktu kurang dari 0.01 detik dan ramah sumber daya.
- **Learning Mode & Baseline**: Secara otomatis merekam folder yang ada saat plugin pertama kali diaktifkan sebagai "baseline" aman. Baseline disimpan dalam format JSON di `wp-content/uploads/wp-root-guard/baseline.json`.
- **Karantina Otomatis (Auto-Quarantine) [BARU v1.1.0]**: Secara otomatis mengamankan folder asing terdeteksi dengan mengganti nama folder dan meletakkan file `.htaccess` berisi perintah `Deny from all` untuk memblokir seluruh akses HTTP.
- **Sistem Whitelist & Manajemen Karantina**:
  - Whitelist Bawaan: `wp-admin`, `wp-content`, `wp-includes`, `.well-known`, dan `cgi-bin`.
  - Whitelist Kustom: Administrator dapat menandai folder asing sebagai "Trust Folder" atau memulihkannya (*restore*) dari karantina.
  - Hapus Permanen: Menghapus direktori karantina secara rekursif langsung dari dasbor WordPress.
- **Notifikasi Telegram & Email [BARU v1.1.0]**: Mengirim peringatan *real-time* instan ke Telegram Bot dan Email Administrator begitu ada folder asing baru yang terdeteksi, dilengkapi fitur anti-spam (notifikasi dikirim hanya sekali per ancaman baru).
- **Tab Pengaturan Terintegrasi [BARU v1.1.0]**: Halaman konfigurasi di dasbor admin untuk mengelola sakelar Karantina Otomatis, pengiriman Notifikasi, serta tombol Kirim Uji Coba Telegram/Email.
- **Pembaruan Otomatis dari GitHub**: Terintegrasi dengan pembaruan otomatis bawaan WordPress yang terhubung langsung ke rilis GitHub ini.

---

## Log Pembaruan (Changelog)

### v1.1.0 (14 Juli 2026)
- **Fitur Baru**: Menambahkan sistem Karantina Otomatis (Auto-Quarantine) dengan ganti nama otomatis dan penguncian akses `.htaccess`.
- **Fitur Baru**: Menambahkan Notifikasi Peringatan Instan ke Telegram Bot API dan Email Administrator.
- **Fitur Baru**: Menambahkan Tab Pengaturan (Settings) di dasbor admin dengan tombol Uji Coba Koneksi notifikasi.
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