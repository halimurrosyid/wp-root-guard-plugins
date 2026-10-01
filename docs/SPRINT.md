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

## Deep-Dive Addendum: Defence in Depth Webshell

Bagian ini mencatat hasil audit lebih mendalam terhadap engine deteksi yang berjalan saat ini. Kesimpulan audit: WP Root Guard saat ini adalah **baseline/anomaly scanner untuk root, core, dan uploads**, bukan scanner perilaku webshell menyeluruh. Deteksi webshell masih bergantung pada cakupan direktori dan signature regex sederhana.

### 17. Model Eksekusi Engine Saat Ini

Alur aktual secara konseptual adalah:

```text
WP-Cron / traffic request / scan manual
        -> Scanner::perform_scan()
        -> root level + core checksum + uploads PHP
        -> regex signature sederhana
        -> quarantine / log / notifikasi
```

Implikasinya:

- Jika sebuah file tidak termasuk scope scanner, file tersebut tidak pernah sampai ke tahap analisis kode.
- Jika signature tidak cocok secara literal, file dapat dilaporkan bersih walaupun memiliki perilaku berbahaya.
- Jika sebagian scope gagal dipindai, hasil akhir masih dapat terlihat sebagai `safe`.
- Quarantine dan notifikasi bekerja setelah deteksi; keduanya bukan pengganti kontrol pencegahan eksekusi di web server.

### 18. Blindspot Obfuscated Webshell

Implementasi `Scanner::scan_file_for_webshell()` pada `includes/class-scanner.php` menggunakan pencocokan regex terhadap konten mentah. Signature saat ini mencakup fungsi seperti `eval()`, `base64_decode()`, `system()`, `shell_exec()`, `gzinflate()`, dan beberapa nama webshell yang dikenal.

Keterbatasan:

- Tidak ada PHP tokenizer atau AST.
- Tidak ada analisis konteks antara kode, komentar, dan string.
- Tidak ada deteksi variable function atau callback dinamis.
- Tidak ada normalisasi string concatenation.
- Tidak ada decoding aman untuk `chr()`, `pack()`, `hex2bin()`, URL encoding, ROT13, atau payload gzip/zlib.
- Tidak ada deteksi payload base64/hex berlapis.
- Tidak ada deteksi dynamic `include`/`require` dan stream wrapper seperti `php://input` atau `data://`.
- Hanya ekstensi `php`, `htaccess`, `html`, dan `txt` yang dianalisis oleh signature scanner.
- File lebih besar dari 1 MB dilewati oleh `scan_file_for_webshell()` tanpa menjadi coverage gap.
- File `.phtml`, `.inc`, `.phar`, extensionless, atau polyglot dapat terdeteksi sebagai file uploads berdasarkan ekstensi, tetapi belum tentu dianalisis sebagai webshell.
- Regex mentah dapat menghasilkan false positive pada komentar, dokumentasi, atau kode benign yang menyebut nama fungsi berbahaya.

Pola evasion yang wajib masuk test corpus:

1. Penyusunan nama fungsi dari beberapa string.
2. Pemanggilan fungsi melalui variabel atau callback.
3. Payload yang dibentuk melalui `chr()`, `pack()`, `hex2bin()`, `strrev()`, array join, atau fungsi transformasi lain.
4. Payload terkompresi atau terenkripsi ringan dengan decoding bertingkat.
5. Penggunaan superglobal tidak langsung melalui variable variable atau `filter_input()`.
6. Kode loader di file kecil yang mengambil payload dari database, request body, atau remote endpoint.
7. Kode PHP yang disembunyikan di ekstensi media, file template, SVG, HTML, atau file polyglot.

**Solusi arsitektur:** buat `ObfuscationAnalyzer` terpisah dengan tokenizer/AST, normalisasi terbatas, safe decoder ber-batas waktu/ukuran/kedalaman, entropy analysis, dan risk scoring. Hasil decoding tidak boleh dieksekusi.

### 19. Blindspot Plugin Typosquatting dan Plugin Palsu

Belum ada pemeriksaan terhadap inventaris plugin, slug resmi, `Text Domain`, `Plugin URI`, `Update URI`, atau hash package plugin. Akibatnya plugin seperti berikut dapat luput:

```text
wp-content/plugins/akimset/
wp-content/plugins/akimset/akimset.php
Plugin Name: Akismet
```

Header plugin tidak dapat dijadikan bukti keaslian karena header dapat dipalsukan.

Rencana `Plugin Auditor`:

- Enumerasi plugin aktif dan nonaktif melalui `get_plugins()`.
- Bandingkan folder lokal, basename, slug, nama, text domain, dan URI.
- Gunakan WordPress.org Plugin API untuk query metadata resmi berdasarkan slug atau nama. Referensi: <https://developer.wordpress.org/reference/functions/plugins_api/>.
- Cache hasil positif dan negatif agar audit tidak membebani setiap request.
- Bedakan plugin resmi, plugin premium/custom, fork, unknown, dan suspicious identity.
- Simpan manifest SHA-256 untuk file plugin setelah approval.
- Tandai file sebagai `Modified After Approval` bila path sama tetapi hash berubah.
- Jangan melakukan auto-quarantine hanya karena fuzzy similarity; gunakan confidence score dan persetujuan admin untuk plugin/theme aktif.

Status dashboard yang disarankan:

```text
Verified Official
Verified Custom/Premium
Modified After Baseline
Suspicious Plugin Identity
Unknown / Unverified
```

WordPress.org API hanya memberikan metadata/repository information dan bukan bukti cryptographic bahwa seluruh file lokal identik dengan package resmi. Untuk assurance lebih tinggi tetap diperlukan verifikasi package atau manifest yang dipercaya.

### 20. Cakupan File dan Persistence yang Belum Lengkap

Baseline filesystem saat ini hanya memindai root secara non-rekursif. Scanner juga memeriksa core dan ekstensi executable tertentu di `uploads`, tetapi belum menjadi inventory seluruh webroot.

Scope prioritas:

```text
wp-admin/
wp-includes/
wp-content/plugins/
wp-content/themes/
wp-content/mu-plugins/
wp-content/advanced-cache.php
wp-content/object-cache.php
wp-content/db.php
wp-content/uploads/
.htaccess
.user.ini
wp-config.php
```

Persistence database yang perlu diaudit:

- administrator atau user baru;
- perubahan role dan capability;
- scheduled cron event asing;
- autoloaded option berisi payload;
- redirect injection;
- widget/post/page SEO spam;
- REST endpoint atau AJAX handler asing;
- URL remote mencurigakan pada option atau metadata;
- perubahan permission, ownership, dan executable bit.

`wp-config.php` tidak diverifikasi oleh Core Checksums API. Perubahannya hanya dapat tertangkap oleh baseline root yang valid dan belum dibangun setelah kompromi. Karena itu file konfigurasi perlu diperlakukan sebagai scope khusus dengan redaction pada inspector.

### 21. False-Safe dan Coverage Transparency

Saat checksum API gagal atau circuit breaker aktif, `get_core_checksums()` dapat mengembalikan `false` dan pemeriksaan core tidak dijalankan. Error iterator filesystem juga masih dapat diabaikan. Namun hasil scan dapat tetap menjadi `safe` bila tidak ada temuan lain.

Kontrak status wajib:

```text
safe     = seluruh scope aktif selesai diverifikasi tanpa error kritis
threat   = ancaman ditemukan
degraded = sebagian scope gagal, dilewati, atau belum diverifikasi
failed   = scan gagal total
```

Dashboard wajib mencatat:

- scope yang selesai;
- scope yang dilewati;
- file di atas size limit;
- permission denied;
- symlink yang ditemukan;
- checksum API failure;
- jumlah file yang belum dianalisis;
- error dan retry berikutnya;
- scan ID, waktu mulai, heartbeat, dan waktu selesai.

Tidak boleh menampilkan status `safe` hanya karena daftar ancaman kosong.

### 22. Baseline dan Trust Boundary

Baseline HMAC melindungi integritas `baseline.json`, tetapi tidak menjamin bahwa isi baseline awal memang bersih. Jika situs telah terinfeksi sebelum plugin diaktifkan atau sebelum rebuild, artefak malware dapat ikut dipercaya.

Risiko tambahan:

- baseline root menggunakan MD5;
- trust/whitelist berbasis path, bukan path plus hash;
- perubahan konten pada file trusted dapat tidak memicu alert;
- database dan WordPress salts berada dalam trust boundary yang sama;
- Core update tidak boleh mempercayai ulang seluruh perubahan root secara otomatis.

Model trust yang disarankan:

```text
path + SHA-256 + owner + permission + approved_at + approved_by + source
```

Trust baru berlaku terhadap fingerprint yang disetujui. Jika hash berubah, status harus kembali menjadi `Modified After Trust` dan memicu notifikasi.

### 23. Quarantine dan Server-Level Enforcement

Blocker berjalan pada lifecycle WordPress `init`. Request langsung ke file PHP di `uploads` dapat ditangani oleh Apache/Nginx sebelum WordPress memuat plugin. Oleh sebab itu deteksi plugin tidak menjamin pencegahan eksekusi.

Defense in depth yang diperlukan:

1. Deny execution rule pada `uploads` di level web server.
2. Vault karantina di luar document root jika memungkinkan.
3. `.htaccess` hanya sebagai adapter Apache.
4. Konfigurasi Nginx dan IIS sebagai adapter terpisah.
5. Self-test dari dashboard untuk memastikan request script ditolak.
6. Fallback `copy -> verify hash -> delete` jika `rename()` lintas filesystem gagal.
7. Backup, evidence metadata, rollback, dan verifikasi bahwa file benar-benar tidak dapat diakses publik.

Plugin dapat membuat generator aturan dan memandu admin, tetapi tidak dapat secara universal mengubah konfigurasi Nginx/shared hosting tanpa akses server.

### 24. Scheduler dan Scan Lock

WP-Cron bukan daemon. Event dapat terdaftar tetapi tidak dieksekusi sampai ada request yang memicu WP-Cron. Traffic fallback membantu situs yang menerima traffic, tetapi tidak menjamin scan pada situs sepi dan dapat menjalankan scan berat di request pengunjung.

Kekurangan operasional:

- scan cron, traffic, AJAX, dan manual belum memakai satu global lock;
- dua jalur dapat menjalankan scan bersamaan;
- belum ada resumable batch scanner untuk timeout;
- scan dapat memperlambat request foreground;
- tidak ada missed-run history yang cukup rinci;
- tidak ada mekanisme prioritas untuk incident scan.

Target:

- global lock database untuk semua jalur scan;
- queue/checkpoint per scope;
- bounded batch per request;
- heartbeat dan stale-run recovery;
- dashboard menampilkan `last_attempt`, `last_success`, `next_due`, `missed_count`, dan `coverage`;
- manual scan dapat memprioritaskan scope kritis tanpa membuat scan penuh bertumpuk.

Status implementasi P0.3 (1 Oktober 2026):

- setiap invokasi scanner memproses maksimal 100 item atau 5 detik;
- item, claim token, cursor direktori, scope, heartbeat, dan temuan disimpan pada tabel plugin; run aktif dipulihkan bila option cache hilang;
- claim stale dikembalikan ke antrean dan continuation WP-Cron dijadwalkan; traffic fallback melanjutkan checkpoint pada request berikutnya;
- notifikasi dan auto-quarantine diproses sesudah seluruh scope pemindaian selesai, bukan pada batch parsial;
- detail run terminal dibersihkan oleh hook prune setelah 7 hari.

Keterbatasan yang tetap harus diuji di lab: direktori datar yang sangat besar masih bergantung pada `scandir()` PHP dan perlu stress test pada shared hosting; tanpa traffic maupun external cron, continuation WP-Cron tetap tidak dapat berjalan sendiri karena WordPress bukan daemon.

### 25. Notifikasi dan Bukti Forensik

Identifier ancaman sudah menggunakan hash isi file untuk membedakan perubahan pada path yang sama. Namun state delivery masih global: jika salah satu channel berhasil, seluruh ancaman dapat dianggap sudah diberitahukan walaupun channel lain gagal.

Perbaikan:

- delivery state per channel dan per event;
- retry queue dengan exponential backoff dan batas percobaan;
- response provider dan HTTP status dicatat;
- event ID, scan ID, fingerprint, first seen, last seen, dan action history;
- notifikasi untuk threat baru, hash berubah, threat muncul kembali, quarantine gagal, dan coverage degraded;
- redaction untuk path/credential sensitif;
- log forensic terpisah dari Options API yang mudah tertimpa oleh log scan berulang.

### 26. Defence in Depth Target Architecture

```text
Layer 0  Web server deny-execution dan WAF/configuration guard
Layer 1  Inventory seluruh executable, loader, symlink, permission, dan ownership
Layer 2  Provenance: core checksum, plugin/theme identity, package/manifest hash
Layer 3  Static analysis: tokenizer/AST, safe decoding, entropy, risk scoring
Layer 4  Persistence audit: users, cron, options, redirects, REST/AJAX, content spam
Layer 5  Runtime/traffic signal: request anomaly, upload event, failed access, IP evidence
Layer 6  Containment: dry-run, confidence threshold, quarantine, backup, rollback
Layer 7  Notification/forensics: per-channel delivery state, evidence, audit trail
Layer 8  Scheduler health: checkpoint, lock, retry, degraded coverage, stale-run recovery
```

Kebijakan tindakan berdasarkan confidence:

- **High confidence + uploads executable:** quarantine otomatis setelah hash/evidence disimpan.
- **High confidence + unknown core injection:** quarantine dengan backup dan verifikasi.
- **Modified active plugin/theme:** alert critical, snapshot, dan approval admin; jangan langsung memindahkan file aktif tanpa rollback.
- **Suspicious identity/obfuscation score sedang:** detect-only dan review manual.
- **Unknown/unverified karena API gagal:** status `degraded`, bukan `safe` dan bukan auto-delete.

### 27. Prioritas Implementasi Hasil Deep Dive

#### P0 — sebelum production

1. Status `degraded/failed` dan coverage report.
2. Global scan lock untuk semua trigger.
3. Batch/resumable scanner.
4. Server-level uploads/vault execution guard.
5. Vault di luar webroot atau deny rule tervalidasi.
6. Checksum-verified atomic restore dengan backup/rollback.
7. Pemisahan baseline root dan core update.
8. Canonical path helper dengan boundary direktori yang ketat.
9. Inspector allowlist dan redaction secret.

#### P1 — menutup blindspot utama

1. `Plugin Auditor` untuk typosquatting dan plugin authenticity status.
2. Manifest SHA-256 plugin/theme/MU-plugin/drop-in.
3. Persistence/database audit.
4. Trust berbasis path plus hash.
5. Per-channel notification delivery state dan retry.
6. Quarantine dry-run, evidence, dan rollback.
7. Signed release/checksum manifest untuk updater.

#### P2 — advanced malware analysis

1. `ObfuscationAnalyzer` berbasis tokenizer/AST.
2. Safe bounded decoder.
3. Entropy dan encoded payload scoring.
4. Dynamic call/include detection.
5. YARA/local signature rules.
6. Synthetic obfuscation test corpus dan regression suite.

### 28. Acceptance Test di Docker Lab

Test wajib setelah implementasi:

1. Buat plugin fixture harmless bernama `akimset`; dashboard harus menandainya `Suspicious Identity`, bukan menghapus otomatis.
2. Ubah isi plugin/theme yang sudah memiliki manifest; status harus menjadi `Modified After Approval`.
3. Uji file PHP obfuscated synthetic tanpa menjalankan payload; analyzer harus mendeteksi indikator gabungan.
4. Uji file lebih besar dari batas; hasil harus `degraded` atau menampilkan coverage gap, bukan `safe`.
5. Simulasikan checksum API gagal; core status harus `degraded`.
6. Simulasikan permission denied dan iterator error; error harus muncul di dashboard.
7. Jalankan scan manual, AJAX, traffic fallback, dan cron bersamaan; hanya satu scan yang boleh memperoleh lock.
8. Pastikan file PHP di uploads tidak dapat dieksekusi langsung oleh Apache/Nginx sesuai konfigurasi lab.
9. Pastikan file quarantine tidak dapat diakses publik.
10. Uji email berhasil/Telegram gagal dan sebaliknya; channel gagal harus memiliki retry state sendiri.
11. Uji restore dengan konten remote yang checksum-nya tidak cocok; file lokal tidak boleh ditimpa.
12. Uji baseline setelah simulasi kompromi; baseline harus berstatus pending/review dan tidak langsung dipercaya.

### 29. Kesimpulan Audit

Root cause terbesar bukan sekadar kurangnya signature regex. Ada tiga masalah arsitektur utama:

1. **Coverage:** lokasi executable dan persistence belum dipindai menyeluruh.
2. **Semantics:** engine belum memahami struktur, provenance, dan perilaku kode.
3. **Trust:** hasil kosong atau API gagal masih dapat terlihat sebagai aman.

Target sprint harus mengubah WP Root Guard dari scanner anomaly berbasis lokasi menjadi sistem verifikasi berlapis yang transparan terhadap coverage, konservatif terhadap auto-remediation, dan memiliki bukti forensik yang dapat diaudit.

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
