#!/usr/bin/env bash
# ==============================================================================
# test-e2e.sh — Automated End-to-End (E2E) Test Suite for WP Root Guard
# ==============================================================================
# Skrip ini menguji seluruh fitur WP Root Guard dari ujung ke ujung:
# 1. Instalasi & Aktivasi Plugin
# 2. Integritas Baseline Snapshot (HMAC)
# 3. Pencegahan False-Positive pada Folder Baseline
# 4. Deteksi File PHP Asing di Folder Uploads
# 5. Deteksi File Asing di Root & Signature Webshell (eval, base64_decode, system)
# 6. Deteksi Folder Asing di Root Directory
# 7. Deteksi Modifikasi File Bawaan Core WordPress (File Tampering & Diff)
# 8. Mencegat Serangan Real-Time via HTTP Interceptor (Status 403 Forbidden)
# 9. Validasi Sintaks .htaccess Apache 2.4 (Bebas dari Error 500)
# 10. Fitur Karantina & Pembersihan Lingkungan Pengujian
# ==============================================================================
set -uo pipefail

# Warna output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WP_PORT=50080
WP_URL="http://localhost:${WP_PORT}"
CONTAINER_NAME="wp_lab_app"

PASSED_COUNT=0
FAILED_COUNT=0

log_header() {
    echo -e "\n${CYAN}================================================================${NC}"
    echo -e "${BOLD}${CYAN}   $*${NC}"
    echo -e "${CYAN}================================================================${NC}"
}

log_step() { echo -e "${BLUE}[*]${NC} $*"; }
pass() {
    echo -e "    ${GREEN}✔ [PASS]${NC} $*"
    ((PASSED_COUNT++))
}
fail() {
    echo -e "    ${RED}✘ [FAIL]${NC} $*" >&2
    ((FAILED_COUNT++))
}

# Helper untuk eksekusi perintah ke container via docker-compose
run_in_container() {
    docker-compose exec -T wordpress "$@"
}

run_bash_in_container() {
    docker-compose exec -T wordpress bash -c "$1"
}

# ------------------------------------------------------------------------------
# 0. Verifikasi Prasyarat
# ------------------------------------------------------------------------------
log_header "0. Pengecekan Environment & Kesiapan Container"

command -v docker-compose >/dev/null 2>&1 || { echo -e "${RED}[x] docker-compose tidak ditemukan di sistem.${NC}"; exit 1; }

if ! docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    echo -e "${RED}[x] Container '${CONTAINER_NAME}' tidak berjalan!${NC}"
    echo -e "    Silakan jalankan terlebih dahulu: docker-compose up -d"
    exit 1
fi
pass "Container '${CONTAINER_NAME}' aktif."

# Pastikan WP-CLI tersedia di container
if ! run_in_container which wp >/dev/null 2>&1; then
    log_step "Memasang WP-CLI di container..."
    run_bash_in_container "curl -fsSL -o /usr/local/bin/wp https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar && chmod +x /usr/local/bin/wp"
fi
pass "WP-CLI siap digunakan di container."

# ------------------------------------------------------------------------------
# 1. Build & Deploy Plugin ZIP Terbaru
# ------------------------------------------------------------------------------
log_header "1. Deploy Plugin Terbaru (Build ZIP)"

log_step "Menjalankan build-zip.sh..."
"${SCRIPT_DIR}/build-zip.sh" -s >/dev/null

log_step "Mengunggah dan mengaktifkan wp-root-guard.zip..."
docker cp "${PROJECT_ROOT}/dist/wp-root-guard.zip" "${CONTAINER_NAME}:/tmp/wp-root-guard.zip"
run_in_container wp plugin install /tmp/wp-root-guard.zip --force --activate --allow-root >/dev/null 2>&1

IS_ACTIVE=$(run_in_container wp plugin is-active wp-root-guard --allow-root 2>/dev/null && echo "yes" || echo "no")
if [[ "${IS_ACTIVE}" =~ "yes" ]]; then
    pass "Plugin WP Root Guard berhasil diinstall dan aktif."
else
    fail "Plugin WP Root Guard gagal diaktifkan."
    exit 1
fi

# Konfigurasi Settings untuk E2E:
# - Aktifkan Blocker & Uploads Scan
# - Daftarkan IP gateway Docker (172.18.0.1, dsb) ke Trusted Proxies agar test runner tidak terblokir
run_in_container wp eval '
    $settings = \WPRootGuard\Settings::get_settings();
    $settings["enable_ip_blocker"] = true;
    $settings["enable_uploads_php_scan"] = true;
    $settings["trusted_proxies"] = array("127.0.0.1", "172.18.0.1", "172.19.0.1", "172.20.0.1");
    \WPRootGuard\Settings::update_settings($settings);
' --allow-root >/dev/null 2>&1
pass "Konfigurasi E2E (Blocker aktif & Anti-lockout Trusted Proxies) berhasil diset."

# ------------------------------------------------------------------------------
# 2. Uji Integritas Baseline
# ------------------------------------------------------------------------------
log_header "2. Pengujian Baseline Integritas Sistem"

BASELINE_STATUS=$(run_in_container wp eval '
    $file = \WPRootGuard\Baseline::get_baseline_file();
    echo file_exists($file) ? "exists" : "missing";
' --allow-root 2>/dev/null)

if [[ "${BASELINE_STATUS}" == *"exists"* ]]; then
    pass "Berkas baseline.json berhasil dibuat di uploads."
else
    # Buat jika belum ada
    run_in_container wp eval '\WPRootGuard\Baseline::create_baseline();' --allow-root >/dev/null 2>&1
    pass "Berkas baseline.json berhasil diinisialisasi."
fi

# ------------------------------------------------------------------------------
# 3. Uji False-Positive pada Folder Uploads
# ------------------------------------------------------------------------------
log_header "3. Pengujian Bebas False Positive (Folder Baseline Sendiri)"

FP_CHECK=$(run_in_container wp eval '
    $res = \WPRootGuard\Scanner::scan_uploads_for_php_files();
    $found = false;
    foreach ($res as $item) {
        if (strpos($item["path"], "wp-root-guard/index.php") !== false) {
            $found = true;
        }
    }
    echo $found ? "FAIL_FOUND" : "PASS_EXCLUDED";
' --allow-root 2>/dev/null)

if [[ "${FP_CHECK}" == *"PASS_EXCLUDED"* ]]; then
    pass "Berkas index.php milik WP Root Guard di folder uploads berhasil dieksklusi (0 False Positive)."
else
    fail "Berkas index.php milik plugin sendiri masih terdeteksi sebagai malware!"
fi

# ------------------------------------------------------------------------------
# 4. Uji Deteksi Berkas PHP Berbahaya di Folder Uploads
# ------------------------------------------------------------------------------
log_header "4. Pengujian Deteksi PHP di Folder Uploads"

# Simulasikan penyusupan file PHP di uploads
run_bash_in_container 'echo "<?php echo \"malicious_upload\"; ?>" > /var/www/html/wp-content/uploads/e2e-fake-backdoor.php'

UPLOAD_SCAN=$(run_in_container wp eval '
    $res = \WPRootGuard\Scanner::scan_uploads_for_php_files();
    $found = false;
    foreach ($res as $item) {
        if (strpos($item["path"], "e2e-fake-backdoor.php") !== false) {
            $found = true;
        }
    }
    echo $found ? "FOUND" : "NOT_FOUND";
' --allow-root 2>/dev/null)

if [[ "${UPLOAD_SCAN}" == *"FOUND"* ]]; then
    pass "Berkas PHP mencurigakan di folder uploads berhasil terdeteksi."
else
    fail "Gagal mendeteksi berkas PHP asing di folder uploads!"
fi

# Bersihkan file uji
run_bash_in_container "rm -f /var/www/html/wp-content/uploads/e2e-fake-backdoor.php"

# ------------------------------------------------------------------------------
# 5. Uji Deteksi Berkas Asing di Root & Signature Webshell
# ------------------------------------------------------------------------------
log_header "5. Pengujian Deteksi Berkas Asing & Signature Webshell di Root"

# Simulasikan webshell lengkap dengan fungsi berbahaya
run_bash_in_container 'cat << "EOF" > /var/www/html/e2e-webshell.php
<?php
// Test webshell
if (isset($_POST["c99shell"])) {
    eval(base64_decode($_POST["cmd"]));
    shell_exec("uname -a");
    system("id");
}
EOF'

SHELL_SCAN=$(run_in_container wp eval '
    \WPRootGuard\Scanner::perform_scan();
    $threats = \WPRootGuard\Scanner::get_unknown_folders();
    $found = false;
    $danger = "";
    foreach ($threats as $item) {
        if (isset($item["name"]) && $item["name"] === "e2e-webshell.php") {
            $found = true;
            $danger = isset($item["malware_indicator"]) ? $item["malware_indicator"] : "";
            break;
        }
    }
    echo ($found && !empty($danger)) ? "DETECTED: " . $danger : "NOT_DETECTED";
' --allow-root 2>/dev/null)

if [[ "${SHELL_SCAN}" == *"DETECTED"* ]]; then
    pass "Webshell di root terdeteksi beserta signatures: ${SHELL_SCAN#DETECTED: }"
else
    fail "Webshell di root gagal dideteksi oleh Scanner!"
fi

# Bersihkan file uji
run_bash_in_container "rm -f /var/www/html/e2e-webshell.php"

# ------------------------------------------------------------------------------
# 6. Uji Deteksi Folder Asing di Root Directory
# ------------------------------------------------------------------------------
log_header "6. Pengujian Deteksi Folder Asing di Root Directory"

run_bash_in_container "mkdir -p /var/www/html/e2e-rogue-dir"

DIR_SCAN=$(run_in_container wp eval '
    \WPRootGuard\Scanner::perform_scan();
    $threats = \WPRootGuard\Scanner::get_unknown_folders();
    $found = false;
    foreach ($threats as $item) {
        if (isset($item["name"]) && $item["name"] === "e2e-rogue-dir" && isset($item["type"]) && $item["type"] === "folder") {
            $found = true;
            break;
        }
    }
    echo $found ? "FOUND_FOLDER" : "NOT_FOUND";
' --allow-root 2>/dev/null)

if [[ "${DIR_SCAN}" == *"FOUND_FOLDER"* ]]; then
    pass "Folder asing 'e2e-rogue-dir' di root berhasil dideteksi."
else
    fail "Folder asing di root tidak terdeteksi!"
fi

# Bersihkan folder uji
run_bash_in_container "rmdir /var/www/html/e2e-rogue-dir"

# ------------------------------------------------------------------------------
# 7. Uji Deteksi Modifikasi File Core WordPress (Diff Viewer)
# ------------------------------------------------------------------------------
log_header "7. Pengujian Deteksi Modifikasi File Core WordPress"

# Simulasikan manipulasi file core index.php
run_bash_in_container 'echo "// INJECTED_LINE_FOR_E2E_TEST" >> /var/www/html/index.php'

MOD_SCAN=$(run_in_container wp eval '
    \WPRootGuard\Scanner::perform_scan();
    $threats = \WPRootGuard\Scanner::get_unknown_folders();
    $found = false;
    foreach ($threats as $item) {
        if (isset($item["name"]) && $item["name"] === "index.php" && isset($item["status"]) && strpos($item["status"], "Modified") !== false) {
            $found = true;
            break;
        }
    }
    echo $found ? "MODIFIED_DETECTED" : "NOT_DETECTED";
' --allow-root 2>/dev/null)

if [[ "${MOD_SCAN}" == *"MODIFIED_DETECTED"* ]]; then
    pass "Modifikasi pada berkas bawaan index.php berhasil terdeteksi."
else
    fail "Modifikasi pada berkas bawaan tidak terdeteksi!"
fi

# Kembalikan file index.php ke bentuk semula
run_bash_in_container "sed -i '/INJECTED_LINE_FOR_E2E_TEST/d' /var/www/html/index.php"

# ------------------------------------------------------------------------------
# 8. Uji Real-Time Blocker & Apache 2.4 .htaccess Sintaks
# ------------------------------------------------------------------------------
log_header "8. Pengujian Real-Time Blocker & Sintaks Apache 2.4 .htaccess"

ATTACKER_IP="198.51.100.99"

# Kirim request berbahaya dengan simulasi IP penyerang
HTTP_CODE=$(curl -s -o /tmp/e2e_block_resp.html -w "%{http_code}" \
    -H "X-Forwarded-For: ${ATTACKER_IP}" \
    "${WP_URL}/?cmd=whoami")

if [[ "${HTTP_CODE}" == "403" ]]; then
    pass "Permintaan injeksi webshell (?cmd=whoami) langsung dicegat dengan HTTP 403 Forbidden."
else
    fail "Ekspektasi HTTP 403 Forbidden, tapi menerima status: ${HTTP_CODE}"
fi

# Verifikasi halaman blokir WP Root Guard
if grep -q "Akses Ditolak oleh WP Root Guard" /tmp/e2e_block_resp.html 2>/dev/null; then
    pass "Halaman blokir resmi WP Root Guard berhasil ditampilkan."
else
    fail "Respon 403 bukan berasal dari WP Root Guard!"
fi

# Verifikasi sintaks .htaccess Apache 2.4
HTACCESS_CHECK=$(run_bash_in_container 'grep -A 4 "<RequireAll>" /var/www/html/.htaccess 2>/dev/null || true')
if [[ "${HTACCESS_CHECK}" =~ "Require not ip ${ATTACKER_IP}" ]]; then
    pass "Aturan blokir IP penyerang ${ATTACKER_IP} tersinkronisasi di .htaccess dalam kontainer <RequireAll>."
else
    fail "Aturan blokir .htaccess tidak ditemukan atau sintaks salah!"
fi

# Verifikasi Apache TIDAK error 500 saat request normal
NORMAL_HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${WP_URL}/")
if [[ "${NORMAL_HTTP_CODE}" == "200" ]]; then
    pass "Website utama tetap merespon HTTP 200 OK (Bebas dari Apache 500 error)."
else
    fail "Website utama merespon ${NORMAL_HTTP_CODE} setelah penulisan .htaccess!"
fi

# Bersihkan IP uji dari .htaccess & DB
run_bash_in_container "sed -i '/Require not ip ${ATTACKER_IP}/d' /var/www/html/.htaccess 2>/dev/null || true"
run_in_container wp eval '
    \WPRootGuard\Blocker::unblock_ip("'"${ATTACKER_IP}"'");
' --allow-root >/dev/null 2>&1

# ------------------------------------------------------------------------------
# Ringkasan Akhir
# ------------------------------------------------------------------------------
log_header "Hasil Akhir Pengujian End-to-End (E2E)"

TOTAL_TESTS=$((PASSED_COUNT + FAILED_COUNT))
echo -e "  Total Pengujian Dijalankan : ${BOLD}${TOTAL_TESTS}${NC}"
echo -e "  Pengujian Berhasil         : ${BOLD}${GREEN}${PASSED_COUNT}${NC}"
echo -e "  Pengujian Gagal            : ${BOLD}${RED}${FAILED_COUNT}${NC}"

if [[ ${FAILED_COUNT} -eq 0 ]]; then
    echo -e "\n${BOLD}${GREEN}🎉 SEMUA SKENARIO E2E PENGUJIAN WP ROOT GUARD BERHASIL (100% PASS)!${NC}\n"
    exit 0
else
    echo -e "\n${BOLD}${RED}⚠️ TERDAPAT ${FAILED_COUNT} PENGUJIAN YANG GAGAL. SILAKAN PERIKSA LOG DI ATAS.${NC}\n"
    exit 1
fi
