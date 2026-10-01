# Sprint Plan: WP Root Guard Hardening

## Tujuan Sprint

Memperkuat fitur keamanan yang sudah ada agar lebih robust, aman untuk situs besar, mudah dipulihkan, dan mampu mendeteksi deaktivasi atau manipulasi plugin tanpa menciptakan lockout permanen. Status pemindaian harus membedakan situs yang benar-benar aman dari situs yang belum dapat diverifikasi secara lengkap.

## Kekurangan Fitur Existing

### 1. Performa Pemindaian

- Pemindaian `uploads`, `wp-admin`, dan `wp-includes` masih dapat berjalan secara rekursif penuh.
- Situs dengan banyak file berisiko mengalami timeout, memory exhaustion, atau beban I/O tinggi.
- Scan pertama saat aktivasi masih terlalu berat karena dapat memicu scan dan request remote secara langsung.

**Pengembangan:** tambahkan batch/chunk processing, checkpoint, batas waktu, dan pindahkan scan awal ke background job.

### 2. Self-Healing Core

- Konten remote ditulis setelah download tanpa validasi checksum resmi sebelum proses restore.
- Penulisan file belum sepenuhnya atomik.
- Kegagalan jaringan atau proses terputus dapat meninggalkan file dalam kondisi tidak lengkap.

**Pengembangan:** validasi checksum WordPress.org, tulis ke temporary file, gunakan `rename()` atomik, dan simpan backup sebelum restore.

### 3. Core dan Uploads Detection

- Deteksi webshell masih dominan berbasis signature statis.
- Malware yang menggunakan obfuscation, `chr()`, concatenation, hex encoding, atau variable function dapat terlewat.
- Deteksi uploads masih berfokus pada ekstensi file executable.

**Pengembangan:** tambahkan entropy analysis, deteksi dynamic function, double extension, `.user.ini`, konfigurasi server, dan pola polyglot file.

### 4. Baseline Integrity

- Baseline awal dapat dibuat ketika situs sudah lebih dulu terinfeksi.
- HMAC mendeteksi perubahan baseline, tetapi tidak menjamin isi baseline benar.
- Belum ada proses approval atau verifikasi baseline secara eksplisit oleh administrator.

**Pengembangan:** tambahkan wizard baseline awal, status `pending verification`, review perubahan, dan baseline versioning.

### 5. Auto-Quarantine

- Heuristik yang terlalu agresif berpotensi memindahkan file legitimate.
- Belum tersedia mode simulasi sebelum tindakan dilakukan.
- Pemulihan file karantina memerlukan validasi dan review manual yang lebih jelas.

**Pengembangan:** tambahkan dry-run, confidence score, approval threshold, backup metadata, dan rollback teruji.

### 6. IP Blocker dan `.htaccess`

- Perubahan otomatis pada `.htaccess` dapat berinteraksi buruk dengan konfigurasi Apache atau plugin lain.
- Belum ada validasi syntax sebelum aturan diterapkan.
- Backup dan rollback aturan belum menjadi alur utama.

**Pengembangan:** gunakan backup berversi, syntax validation, dry-run, rollback otomatis, serta fallback yang aman untuk NGINX/IIS.

### 7. Notifikasi

- Pengiriman Telegram/email belum memiliki retry queue yang kuat.
- Status delivery dan response provider belum dipantau secara menyeluruh.
- Pesan berpotensi memuat data sensitif seperti path internal.

**Pengembangan:** tambahkan retry terbatas, delivery log, cooldown, redaksi data sensitif, dan fallback notification channel.

### 8. Updater

- Paket update GitHub masih bergantung pada kepercayaan terhadap repository dan release.
- Validasi domain belum sama dengan validasi integritas paket.

**Pengembangan:** tambahkan SHA-256 manifest, signed release, pinned repository metadata, dan opsi update manual untuk lingkungan kritis.

### 9. Logging dan Forensik

- Log masih berbasis Options API dan kapasitasnya terbatas.
- Data log lebih sulit dianalisis untuk instalasi multisite atau incident response besar.

**Pengembangan:** pertimbangkan tabel khusus, event ID, actor ID, request ID, export JSON/CSV terstruktur, dan retention policy.

### 10. Maintainability dan Testing

- `admin/class-admin.php` dan `includes/class-scanner.php` masih besar dan memuat banyak tanggung jawab.
- Belum tersedia test suite komprehensif untuk path traversal, karantina, restore, blocker, cron, dan multisite.

**Pengembangan:** pisahkan controller/view/service, lalu tambahkan unit test, integration test, security regression test, dan stress test.

### 11. Fail-Open pada Core Integrity Scan

- Jika API checksum WordPress.org gagal atau circuit breaker aktif, pengecekan integritas core dapat dilewati.
- Hasil scan masih berpotensi ditampilkan sebagai `safe` walaupun core tidak berhasil diverifikasi.
- Error filesystem yang diabaikan juga belum dibedakan dari hasil pemindaian bersih.

**Pengembangan:** gunakan status scan `safe`, `threat`, `degraded`, dan `failed`; tampilkan komponen yang belum diverifikasi; kirim alert jika pemeriksaan core gagal berulang.

### 12. Blindspot Eksekusi Langsung di Uploads

- Blocker berjalan di hook WordPress `init`, sehingga tidak dieksekusi saat web server langsung menjalankan file PHP di `wp-content/uploads/`.
- Deteksi file berbahaya tidak sama dengan pencegahan eksekusi file tersebut.

**Pengembangan:** buat deny-execution rule untuk ekstensi script pada folder uploads untuk Apache; sediakan panduan/config generator NGINX dan IIS; verifikasi rule setelah dipasang.

### 13. Quarantine Vault Berada di Webroot

- Vault karantina berada di dalam `wp-content/uploads/`.
- Proteksi `.htaccess` hanya efektif pada Apache yang mengizinkan override; NGINX/IIS tidak memprosesnya.
- Berkas malware yang dikarantina dapat tetap terekspos bila konfigurasi server tidak mendukung.

**Pengembangan:** prioritaskan penyimpanan vault di luar document root; bila tidak tersedia, wajibkan server-level deny rule, randomize nama artefak, dan lakukan access verification setelah karantina.

### 14. Baseline Otomatis Saat Core Update

- Saat WordPress core diperbarui, baseline root dapat dibangun ulang dari kondisi filesystem saat itu.
- Perubahan berbahaya di root yang sudah ada sebelum update berisiko ikut dipercaya sebagai baseline baru.

**Pengembangan:** pisahkan baseline root dari metadata versi core; hanya refresh cache checksum/core yang resmi; setiap perubahan baseline root memerlukan approval administrator atau policy eksplisit.

### 15. Validasi Path dan Inspektur Berkas

- Beberapa operasi menggunakan pemeriksaan prefix path yang perlu boundary direktori ketat.
- Inspector dapat membaca berkas di bawah root hingga 2 MB, termasuk berkas konfigurasi sensitif bila dipanggil oleh admin.

**Pengembangan:** buat satu helper canonical path yang memeriksa `base + DIRECTORY_SEPARATOR`; gunakan allowlist berdasarkan jenis temuan; redact secret pada `wp-config.php`, `.env`, credential file, dan konfigurasi lain.

### 16. Cakupan Integritas Plugin, Theme, dan Persistence

- Tidak ada integrity scan untuk plugin, theme, atau MU-plugin.
- Belum ada audit persistence di database: administrator baru, cron event asing, opsi berbahaya, redirect, dan SEO-spam.
- Permission, ownership, dan file executable di area writable belum menjadi indikator risiko.

**Pengembangan:** tambahkan manifest/checksum untuk plugin/theme WordPress.org dan baseline approval untuk kode premium/custom; audit user, cron, option, permission, ownership, serta indikator redirect/database injection.

## Fitur Nice-to-Have: Anti-Deactivate yang Aman

Fitur anti-deactivate harus mencegah deaktivasi tidak sah tanpa membuat plugin tidak dapat dipulihkan oleh pemilik situs.

### Prioritas Tinggi

1. **Protected Deactivation Policy**
   - Hanya user atau role tertentu yang boleh menonaktifkan plugin.
   - Terapkan juga pada konteks multisite dan Network Admin.

2. **Break-Glass Recovery**
   - Sediakan jalur pemulihan melalui constant `wp-config.php`, WP-CLI, atau recovery key.
   - Recovery harus dapat menonaktifkan seluruh proteksi secara eksplisit.

3. **Deactivation Detection**
   - Deteksi perubahan pada daftar plugin aktif.
   - Kirim alert eksternal ketika deaktivasi terjadi di luar policy.

4. **Tamper-Evident Audit Log**
   - Catat user, IP, waktu, sumber perubahan, dan alasan deaktivasi.
   - Gunakan HMAC atau event chain untuk mendeteksi manipulasi log.

### Prioritas Menengah

5. **Plugin File Integrity Check**
   - Deteksi file plugin yang dihapus, diganti, atau dimodifikasi.

6. **Multisite Network Lock**
   - Kunci konfigurasi dari level network agar site administrator tidak dapat menonaktifkannya secara lokal.

7. **Safe Mode dan Maintenance Mode**
   - Nonaktifkan enforcement sementara saat update, debugging, restore, atau migrasi.

8. **Deactivation Watchdog Terbatas**
   - Reaktivasi otomatis hanya jika policy mengizinkan.
   - Gunakan cooldown, batas percobaan, dan pencegahan infinite loop.

### Prioritas Rendah

9. **Optional MU-Plugin Guardian**
   - Komponen pendamping opsional untuk memonitor status plugin.
   - Harus memiliki dokumentasi, uninstall bersih, dan jalur rollback yang jelas.

10. **Offline Emergency Notification**
    - Gunakan channel eksternal ketika plugin mendeteksi dirinya dinonaktifkan.

## Prioritas Sprint

| Prioritas | Area | Hasil yang Diharapkan |
|---|---|---|
| P0 | Restore checksum dan atomic write | Tidak menulis konten remote yang tidak tervalidasi |
| P0 | Batch scan dan background activation scan | Scan stabil pada situs besar |
| P0 | Status scan degraded/failed | Situs tidak dilabeli aman saat core atau filesystem tidak terverifikasi |
| P0 | Server-level uploads execution guard | File script di uploads tidak dapat dieksekusi langsung |
| P0 | Vault di luar webroot atau deny rule tervalidasi | Artefak karantina tidak dapat diakses publik di Apache/NGINX/IIS |
| P0 | Pisahkan baseline root dan core update | Core update tidak mempercayai ulang perubahan root yang mencurigakan |
| P0 | Canonical path helper dan inspector allowlist | Akses berkas sensitif dan path sibling tidak dapat lolos validasi |
| P0 | Break-glass recovery | Tidak terjadi lockout permanen |
| P1 | Deactivation detection dan audit | Deaktivasi tidak sah dapat diketahui |
| P1 | Baseline verification workflow | Baseline awal lebih terpercaya |
| P1 | Quarantine dry-run dan rollback | False positive lebih aman ditangani |
| P1 | Updater package verification | Risiko supply-chain berkurang |
| P1 | Plugin/theme/MU-plugin integrity | Modifikasi kode non-core dapat dideteksi |
| P1 | Persistence dan database audit | Rogue admin, cron, option, dan redirect mencurigakan dapat ditemukan |
| P2 | Heuristic/obfuscation detection | Cakupan deteksi malware meningkat |
| P2 | Refactor admin/scanner | Kode lebih mudah dirawat |
| P2 | Test suite dan stress testing | Regression dan risiko operasional berkurang |
| P3 | MU-Plugin Guardian opsional | Proteksi status plugin tingkat lanjut |

## Kriteria Selesai Sprint

- Restore hanya menerima konten yang checksum-nya sesuai sumber resmi.
- Scan besar dapat dilanjutkan setelah timeout atau request terputus.
- Scan yang tidak dapat memverifikasi core atau filesystem ditandai `degraded` atau `failed`, bukan `safe`.
- Script di uploads dan vault tidak dapat dieksekusi atau diakses publik pada Apache, NGINX, maupun IIS.
- Core update tidak membangun ulang baseline root tanpa approval/policy yang eksplisit.
- Semua operasi file memakai canonical path helper dengan boundary direktori yang ketat.
- Plugin dapat dipulihkan melalui break-glass mechanism.
- Deaktivasi tidak sah menghasilkan audit log dan notifikasi.
- Auto-quarantine memiliki dry-run dan rollback.
- Test keamanan dasar tersedia dan seluruh syntax check tetap lulus.
- Dokumentasi `README.md`, `PRD.md`, `FEATURES.md`, `STRUCTURE.md`, dan file ini konsisten.

## Summary

- Fokus utama: status scan yang jujur, eksekusi uploads, keamanan vault, validasi restore, baseline trust, updater security, dan recovery.
- Anti-deactivate harus bersifat terkontrol, transparan, dan selalu memiliki break-glass recovery.
- Prioritas tertinggi adalah batch scan, checksum-verified restore, server-level uploads guard, vault aman, status `degraded`, dan testing.
- MU-Plugin Guardian hanya disarankan sebagai fitur opsional setelah mekanisme recovery matang.
