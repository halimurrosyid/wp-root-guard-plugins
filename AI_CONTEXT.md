# WP Root Guard — AI Context & Project Handover Guide

> **Panduan Konteks AI (AI Context & Handover)**  
> Berkas ini dirancang khusus agar model AI (Antigravity, Claude, ChatGPT, Cursor, GitHub Copilot) di perangkat mana pun dapat langsung memahami arsitektur, histori revisi, aturan teknis, dan alur kerja proyek WP Root Guard tanpa kehilangan konteks.

---

## 1. Ringkasan Eksekutif Proyek
* **Nama Plugin**: WP Root Guard (`wp-root-guard`)
* **Versi Saat Ini**: `3.7.5` (Stabil & Rilis)
* **Organisasi**: PuTI Telkom University (`it@365.telkomuniversity.ac.id`)
* **Website Produksi**: `https://it.telkomuniversity.ac.id/`
* **Repositori GitHub**: `https://github.com/halimurrosyid/wp-root-guard-plugins`
* **Target Lingkungan**: WordPress 6.0 – 6.6+, PHP 8.1+
* **Tujuan Utama**: Memproteksi direktori webroot (`ABSPATH`), direktori sistem (`wp-admin`, `wp-includes`), folder uploads (`wp-content/uploads`), tema, plugin, dan database dari serangan malware judi slot, backdoor webshell, dan injeksi berkas asing dengan kemampuan pemulihan mandiri (*self-healing* via WordPress.org SVN).

---

## 2. Struktur Direktori & Peran Modul
```
wp-root-guard/
├── wp-root-guard.php        # Bootstrap utama plugin, inisialisasi konstanta & autoloader PSR-4
├── admin/                   # Controller & Asset Admin WP
│   ├── class-admin.php      # Controller menu WP Admin, tab dasbor, AJAX endpoint
│   ├── css/admin.css        # Styling UI dasbor, tema "Dark Cyber Radar Scanner"
│   └── js/admin.js          # Logic pemindaian bertahap, UI ticker, modal inspeksi kode
├── includes/                # Business logic inti (Namespace WPRootGuard)
│   ├── class-scanner.php    # Engine deteksi malware, webshell regex, self-healing, quarantine
│   ├── class-scan-batch-runner.php # Pemindaian batch asynchronous untuk server berkapasitas terbatas
│   ├── class-updater.php    # Updater otomatis terintegrasi langsung ke GitHub Releases API
│   ├── class-cron.php       # Penjadwalan otomatis WP-Cron (bawaan: every_3_hours / 3 jam)
│   ├── class-baseline.php   # Manajemen baseline hash integritas berkas
│   ├── class-blocker.php    # IP Blocker & proteksi .htaccess terhadap upaya RCE
│   ├── class-logger.php     # Audit log aktivitas dan pencatatan riwayat ancaman
│   └── class-settings.php   # Manajemen opsi konfigurasi (wp_options)
├── languages/               # Berkas terjemahan i18n
├── docs/                    # Dokumentasi PRD, Fitur, Arsitektur, dan Sprint
├── scripts/                 # Alat bantu packaging & pengujian
│   ├── build-zip.ps1        # Skrip PowerShell pembuat paket rilis produksi ZIP
│   ├── build-zip.sh         # Skrip Bash pembuat paket ZIP (Linux/macOS)
│   └── test-e2e.sh          # Skrip pengujian end-to-end
└── dist/                    # Output ZIP produksi (diabaikan oleh git)
```

---

## 3. Sistem Pembaruan & Rilis (PENTING)
1. **GitHub Release Automation**:
   - Setiap kali tag `vX.Y.Z` dipush ke `origin`, GitHub Actions (`.github/workflows/release.yml`) otomatis membuat GitHub Release dan melampirkan berkas `wp-root-guard.zip`.
2. **WordPress Auto-Updater (`includes/class-updater.php`)**:
   - Plugin mendengarkan pembaruan langsung dari GitHub API `halimurrosyid/wp-root-guard-plugins`.
   - WordPress Admin dapat memperbarui langsung melalui menu **Dashboard -> Updates** atau **Plugins**.
3. **Mencegah Masalah Duplikasi Plugin (2 Folder Saat Update)**:
   - Slug direktori plugin **harus selalu** `wp-root-guard` (bukan `wp-root-guard-main` atau `wp-root-guard-3.7.x`).
   - Skrip `build-zip.ps1` dan GitHub Actions sudah dikonfigurasi untuk membungkus struktur ke dalam folder `wp-root-guard/`.

---

## 4. Mekanisme Pemindaian & Deteksi (Engine Heuristik)
Pemindai terdiri dari 6 lapisan proteksi:
1. **Root Directory Guard**: Mendeteksi folder dan berkas asing di root `public_html`.
2. **Core Integrity Check**: Memeriksa hash berkas core WordPress ke API resmi WordPress.org. Jika ada modifikasi atau berkas hilang, tersedia fitur *Self-Healing* (unduh ulang berkas asli dari SVN resmi).
3. **Uploads Execution Guard**: Memindai dan memblokir berkas PHP di `wp-content/uploads/`.
4. **Themes & Plugins Guard (`scan_theme_plugin_file`)**:
   - Mendeteksi berkas tersembunyi (*stealth dot-files* seperti `.alfa.php`).
   - Mendeteksi *Polyglot / Disguised Media Backdoors* (gambar berisi kode PHP).
   - Mendeteksi injeksi link slot/judi online.
   - Mendeteksi webshell populer (*C99, R57, WSO, Alfa, Weevely, p0wny, AnonymousFox*).
5. **Database Options & Posts Guard**:
   - Memindai opsi mencurigakan di `wp_options`.
   - Memindai artikel/konten injeksi judi di `wp_posts` dengan fitur 1-klik *Move to Trash*.
6. **Token-Level Comment Stripper (`strip_php_comments`)**:
   - **Aturan Wajib**: Kode PHP **harus** dibersihkan dari komentar (*docblocks*, `//`, `/* */`) menggunakan `strip_php_comments()` sebelum memeriksa pola eksekusi dinamis (*eval*, *assert*, *backtick*, *dropper*). Ini mencegah alarm palsu akibat dokumentasi Markdown atau PHPDoc.

---

## 5. Pelajaran dari False Positive (Jangan Diulangi!)
| Kasus | Penyebab | Solusi Permanen yang Telah Diterapkan |
|---|---|---|
| **Jetpack (Direct Backtick RCE)** | Markdown backtick di PHPDoc: `` `$_SERVER['HTTP_ACCEPT']` `` disalahartikan sebagai operator shell execution. | Hapus seluruh komentar via `strip_php_comments()` sebelum cek RCE; pola backtick diwajibkan berpasangan: ``/(?:^\|[^a-zA-Z0-9_\$])`\s*\$_(?:POST\|GET\|REQUEST\|COOKIE\|SERVER)\s*\[[^`]+`/i``. |
| **UpdraftPlus (Remote File Dropper)** | Penulisan backup PDF menggunakan `file_put_contents( ..., base64_decode( ... ) )`. | Perketat pola dropper agar HANYA mendeteksi jika data sumber berasal langsung dari superglobal (`$_POST/$_GET/$_REQUEST`) atau URL eksternal (`http://`). |
| **Gambar SVG (Fake Media Backdoor)** | Ikon SVG resmi memuat raster data URI (`data:image/png`). | Standar W3C raster image diakui sah pada `is_malicious_media_payload()`. |
| **Self-Detection** | Folder backup WP Root Guard sendiri terdeteksi sebagai malware. | Eksklusi mutlak berbasis path `WP_ROOT_GUARD_FILE` dan slug `wp-root-guard`. |

---

## 6. Prosedur Wajib Saat Melakukan Revisi / Bumping Versi
Jika pengguna meminta revisi atau fitur baru, AI **WAJIB** mengikuti langkah-langkah berikut secara berurutan:

1. **Implementasi Kode**:
   - Ikuti standar WordPress: **Tabs** untuk indentasi PHP, *snake_case* untuk fungsi/opsi, prefix `wp_root_guard_`, validasi nonce, dan kapabilitas `manage_options`.
2. **Bump Versi di 4 Tempat**:
   - `wp-root-guard.php`: Baris `* Version: X.Y.Z`
   - `wp-root-guard.php`: Baris `define( 'WP_ROOT_GUARD_VERSION', 'X.Y.Z' );`
   - `readme.txt`: Baris `Stable tag: X.Y.Z` & tambahkan catatan di blok `= X.Y.Z =`
   - `README.md`: Tambahkan catatan di blok `### vX.Y.Z (Tanggal)`
3. **Uji Sintaks (Linting)**:
   ```powershell
   php -l wp-root-guard.php
   php -l includes/class-scanner.php
   # Atau berkas lain yang diubah
   ```
4. **Build Paket ZIP Produksi**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/build-zip.ps1
   ```
5. **Git Commit, Tag & Push**:
   ```bash
   git add -A
   git commit -m "feat/fix: deskripsi perubahan (vX.Y.Z)"
   git tag vX.Y.Z
   git push origin main
   git push origin vX.Y.Z
   ```
6. **Verifikasi Rilis**:
   - GitHub Actions akan otomatis membuat rilis di GitHub dan melampirkan ZIP baru. Pengguna dapat langsung memperbarui via WordPress Admin.

---

## 7. Kredensial & Lingkungan Uji
> ⚠️ **Catatan Keamanan**: Jangan pernah commit kredensial sensitif ke Git. Jika pengguna memberikan kredensial sesi di chat, gunakan hanya untuk REST API pengecekan dan jangan simpan di berkas kode publik.

* **WordPress REST API Endpoint**: `https://it.telkomuniversity.ac.id/wp-json/wp/v2/`
* **Akun Admin**: Diberikan oleh pengguna di prompt jika diperlukan.
* **Perintah Uji REST API via PowerShell**:
  ```powershell
  $user = 'USERNAME'
  $pass = 'APP_PASSWORD'
  $pair = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($user + ':' + $pass))
  $headers = @{ Authorization = 'Basic ' + $pair }
  Invoke-RestMethod -Uri 'https://it.telkomuniversity.ac.id/wp-json/wp/v2/plugins' -Headers $headers
  ```
