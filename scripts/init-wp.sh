#!/usr/bin/env bash
# =============================================================
# init-wp.sh — Auto-init WordPress lab untuk testing plugin
# =============================================================
set -euo pipefail

# ---------- Konfigurasi (boleh diubah) ----------
WP_PORT=50080
WP_URL="http://localhost:${WP_PORT}"

WP_TITLE="WP Plugin Lab"
WP_ADMIN_USER="admin"
WP_ADMIN_PASS="admin123!"
WP_ADMIN_EMAIL="admin@lab.local"

# Samakan dengan docker-compose.yml
DB_NAME="wordpress"
DB_USER="wpuser"
DB_PASS="wppass123!"

# Warna output
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[x]${NC} $*" >&2; exit 1; }

# ---------- Cek prasyarat ----------
command -v docker >/dev/null 2>&1 || die "Docker tidak terinstall."
docker-compose version >/dev/null 2>&1 || die "Docker Compose plugin tidak tersedia."
[[ -f docker-compose.yml ]] || die "docker-compose.yml tidak ditemukan di $(pwd)."

# ---------- 1. Start stack ----------
log "Menjalankan docker-compose..."
docker-compose up -d

# ---------- 2. Tunggu DB healthy ----------
log "Menunggu MariaDB siap..."
for i in {1..30}; do
  if docker-compose exec -T db mariadb -u"${DB_USER}" -p"${DB_PASS}" -e "SELECT 1" "${DB_NAME}" >/dev/null 2>&1; then
    log "Database siap."
    break
  fi
  sleep 2
  [[ $i -eq 30 ]] && die "Database tidak kunjung siap. Cek: docker-compose logs db"
done

# ---------- 3. Tunggu WordPress container up ----------
log "Menunggu WordPress container..."
for i in {1..30}; do
  if docker-compose exec -T wordpress test -f /var/www/html/wp-load.php 2>/dev/null; then
    break
  fi
  sleep 2
  [[ $i -eq 30 ]] && die "File WordPress tidak muncul. Cek: docker-compose logs wordpress"
done

# ---------- 4. Install WP-CLI di container (sekali saja) ----------
if ! docker-compose exec -T wordpress which wp >/dev/null 2>&1; then
  log "Menginstall WP-CLI di container..."
  docker-compose exec -T wordpress bash -c '
    curl -fsSL -o /usr/local/bin/wp \
      https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar \
      && chmod +x /usr/local/bin/wp
  ' || die "Gagal install WP-CLI (cek koneksi internet)."
fi

# ---------- 5. Cek apakah sudah terinstall ----------
if docker-compose exec -T wordpress wp core is-installed --allow-root >/dev/null 2>&1; then
  warn "WordPress sudah terinstall. Skip instalasi."
else
  log "Installing WordPress core..."
  docker-compose exec -T wordpress wp core install \
    --url="${WP_URL}" \
    --title="${WP_TITLE}" \
    --admin_user="${WP_ADMIN_USER}" \
    --admin_password="${WP_ADMIN_PASS}" \
    --admin_email="${WP_ADMIN_EMAIL}" \
    --skip-email \
    --allow-root

  log "Set permalink & timezone..."
  docker-compose exec -T wordpress wp rewrite structure '/%postname%/' --hard --allow-root || true
  docker-compose exec -T wordpress wp option update timezone_string 'Asia/Jakarta' --allow-root || true
  docker-compose exec -T wordpress wp option update blogdescription 'Lab testing plugin' --allow-root || true

  log "Hapus plugin & theme bawaan yang tidak perlu..."
  for plugin in akismet hello; do
    docker-compose exec -T wordpress wp plugin delete "$plugin" --allow-root 2>/dev/null || true
  done
  for theme in twentytwentythree twentytwentyfour; do
    docker-compose exec -T wordpress wp theme delete "$theme" --allow-root 2>/dev/null || true
  done
fi

# ---------- 6. Info akhir ----------
echo
log "Selesai! 🎉"
cat <<EOF

  ┌──────────────────────────────────────────────┐
  │  WordPress Admin                             │
  │  URL    : ${WP_URL}/wp-admin                 │
  │  User   : ${WP_ADMIN_USER}                   │
  │  Pass   : ${WP_ADMIN_PASS}                   │
  ├──────────────────────────────────────────────┤
  │  Folder plugin lokal : ./plugins             │
  │  Live log error      :                       │
  │    docker-compose exec wordpress \\           │
  │      tail -f /var/www/html/wp-content/debug.log
  └──────────────────────────────────────────────┘

EOF