#!/usr/bin/env bash
# =============================================================
# build-zip.sh — Packaging WordPress Plugin WP Root Guard
# =============================================================
# Membuat paket berkas ZIP produksi siap install di WordPress.
# Mengabaikan file development, tests, docs, docker, dan git.
# =============================================================
set -euo pipefail

# Warna output terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log()  { echo -e "${GREEN}[+]${NC} $*"; }
info() { echo -e "${BLUE}[*]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# Direktori proyek
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Konfigurasi Default
PLUGIN_SLUG="wp-root-guard"
MAIN_PLUGIN_FILE="${PLUGIN_ROOT}/${PLUGIN_SLUG}.php"
OUTPUT_DIR="${PLUGIN_ROOT}/dist"
SKIP_LINT=0

# Parsing argumen
usage() {
    cat <<EOF
Penggunaan: $(basename "$0") [OPTIONS]

Opsi:
  -o, --output <dir>    Direktori tujuan penyimpanan file ZIP (default: ./dist)
  -s, --skip-lint       Lewati pengecekan sintaks PHP sebelum packaging
  -h, --help            Tampilkan bantuan ini

Contoh:
  ./scripts/build-zip.sh
  ./scripts/build-zip.sh -o /tmp/builds
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -s|--skip-lint)
            SKIP_LINT=1
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            die "Opsi tidak dikenal: $1 (Gunakan --help untuk panduan)"
            ;;
    esac
done

# 1. Cek prasyarat
command -v zip >/dev/null 2>&1 || die "Perintah 'zip' tidak ditemukan. Harap install paket zip terlebih dahulu."
[[ -f "${MAIN_PLUGIN_FILE}" ]] || die "File utama plugin tidak ditemukan: ${MAIN_PLUGIN_FILE}"

# 2. Ekstrak versi dari main plugin file
VERSION=$(grep -E '^[ \t\*]*Version:[ \t]*' "${MAIN_PLUGIN_FILE}" | head -n1 | sed -E 's/.*Version:[ \t]*([0-9\.]+).*/\1/' | tr -d '\r\n')
if [[ -z "${VERSION}" ]]; then
    VERSION=$(grep -E "define\(\s*'WP_ROOT_GUARD_VERSION'" "${MAIN_PLUGIN_FILE}" | head -n1 | sed -E "s/.*'([0-9\.]+)'.*/\1/" | tr -d '\r\n')
fi

if [[ -z "${VERSION}" ]]; then
    warn "Gagal mendeteksi versi secara otomatis. Menggunakan versi fallback 'latest'."
    VERSION="latest"
fi

ZIP_FILENAME="${PLUGIN_SLUG}-v${VERSION}.zip"
LATEST_ZIP_FILENAME="${PLUGIN_SLUG}.zip"

echo -e "${CYAN}====================================================${NC}"
echo -e "${CYAN}   WP Root Guard — Production Packaging Tool        ${NC}"
echo -e "${CYAN}====================================================${NC}"
info "Plugin Slug : ${PLUGIN_SLUG}"
info "Versi       : ${VERSION}"
info "Target Dir  : ${OUTPUT_DIR}"
info "File Output : ${ZIP_FILENAME}"

# 3. Lakukan linting PHP (opsional tapi sangat disarankan)
if [[ ${SKIP_LINT} -eq 0 ]] && command -v php >/dev/null 2>&1; then
    log "Memeriksa sintaks PHP (linting)..."
    PHP_FILES=$(find "${PLUGIN_ROOT}" \
        -path "${PLUGIN_ROOT}/.git" -prune -o \
        -path "${PLUGIN_ROOT}/dist" -prune -o \
        -name "*.php" -print)

    for php_file in ${PHP_FILES}; do
        LINT_OUTPUT=$(php -l "${php_file}" 2>&1)
        if [[ $? -ne 0 ]]; then
            echo -e "${RED}${LINT_OUTPUT}${NC}"
            die "Linting gagal pada berkas: ${php_file}"
        fi
    done
    log "Semua file PHP valid (0 sintaks error)."
fi

# 4. Siapkan direktori staging sementara
STAGE_BASE=$(mktemp -d -t wprg_build_XXXXXX)
STAGE_DIR="${STAGE_BASE}/${PLUGIN_SLUG}"

cleanup() {
    if [[ -d "${STAGE_BASE}" ]]; then
        rm -rf "${STAGE_BASE}"
    fi
}
trap cleanup EXIT

mkdir -p "${STAGE_DIR}"

log "Menyiapkan berkas produksi ke staging directory..."

# Salin berkas akar plugin yang diperlukan
cp "${PLUGIN_ROOT}/${PLUGIN_SLUG}.php" "${STAGE_DIR}/"
cp "${PLUGIN_ROOT}/uninstall.php" "${STAGE_DIR}/"

if [[ -f "${PLUGIN_ROOT}/readme.txt" ]]; then
    cp "${PLUGIN_ROOT}/readme.txt" "${STAGE_DIR}/"
fi
if [[ -f "${PLUGIN_ROOT}/README.md" ]]; then
    cp "${PLUGIN_ROOT}/README.md" "${STAGE_DIR}/"
fi
if [[ -f "${PLUGIN_ROOT}/LICENSE" ]]; then
    cp "${PLUGIN_ROOT}/LICENSE" "${STAGE_DIR}/"
fi

# Salin folder-folder modul
for dir in admin includes languages; do
    if [[ -d "${PLUGIN_ROOT}/${dir}" ]]; then
        cp -r "${PLUGIN_ROOT}/${dir}" "${STAGE_DIR}/"
    fi
done

# Bersihkan metadata/temporary file jika ada di dalam staging
find "${STAGE_DIR}" -name ".DS_Store" -delete 2>/dev/null || true
find "${STAGE_DIR}" -name "*.swp" -delete 2>/dev/null || true
find "${STAGE_DIR}" -name "*~" -delete 2>/dev/null || true

# 5. Buat direktori output jika belum ada
mkdir -p "${OUTPUT_DIR}"

TARGET_ZIP="${OUTPUT_DIR}/${ZIP_FILENAME}"
LATEST_ZIP="${OUTPUT_DIR}/${LATEST_ZIP_FILENAME}"

# Hapus file ZIP lama jika sudah ada
rm -f "${TARGET_ZIP}" "${LATEST_ZIP}"

log "Membuat arsip ZIP..."
(
    cd "${STAGE_BASE}"
    zip -r -q -9 "${TARGET_ZIP}" "${PLUGIN_SLUG}"
)

# Buat salinan dengan nama standar (wp-root-guard.zip) untuk memudahkan upload
cp "${TARGET_ZIP}" "${LATEST_ZIP}"

# 6. Verifikasi integritas ZIP
if command -v unzip >/dev/null 2>&1; then
    unzip -t "${TARGET_ZIP}" >/dev/null 2>&1 || die "Verifikasi ZIP gagal! File korup."
fi

# 7. Informasi Ringkasan
TOTAL_FILES=$(unzip -l "${TARGET_ZIP}" | tail -n 1 | awk '{print $2}')
FILE_SIZE=$(du -h "${TARGET_ZIP}" | cut -f1)

log "Packaging berhasil diselesaikan! 🎉"
cat <<EOF

Ringkasan Paket:
----------------------------------------------------
  Berkas Utama : ${TARGET_ZIP}
  Salinan Rilis: ${LATEST_ZIP}
  Total Berkas : ${TOTAL_FILES} file
  Ukuran Paket : ${FILE_SIZE}
  Struktur Root: ${PLUGIN_SLUG}/
----------------------------------------------------

File siap diunggah melalui:
WP Admin -> Plugins -> Add New -> Upload Plugin
EOF
