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
- Situs Web: [indahweb.com](https://indahweb.com)
- Lisensi: GPL v2 atau yang lebih baru.