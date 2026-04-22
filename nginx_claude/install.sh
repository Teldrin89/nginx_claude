#!/usr/bin/env bash
# ==============================================================================
# install.sh  –  Provision OpenResty + Gunicorn on Ubuntu 22.04 / 24.04
#
# Network topology:
#   Internet → Azure Application Gateway (HTTPS/443, TLS termination)
#           → this host (HTTP/80, private network only)
#           → Gunicorn (UNIX socket)
#
# Run as root or with sudo:
#   sudo bash install.sh
#
# What this script does:
#   1. Installs OpenResty and Lua OIDC libraries
#   2. Creates the appuser system account
#   3. Locks down port 80 to the Application Gateway subnet (ufw)
#   4. Deploys nginx config files
#   5. Sets up a Python virtualenv and installs app dependencies
#   6. Installs and enables both systemd services
# ==============================================================================

set -euo pipefail

# --- Configurable variables (override via environment) ---
APP_DIR="${APP_DIR:-/opt/app}"
APP_USER="${APP_USER:-appuser}"
NGINX_CONF_DIR="${NGINX_CONF_DIR:-/etc/nginx/conf.d}"
OPENRESTY_CONF="${OPENRESTY_CONF:-/usr/local/openresty/nginx/conf/nginx.conf}"
OPENRESTY_LUA="${OPENRESTY_LUA:-/usr/local/openresty/nginx/lua}"
PYTHON="${PYTHON:-python3}"
# CIDR of the Azure Application Gateway subnet – only this range may reach port 80
GATEWAY_CIDR="${GATEWAY_CIDR:-10.0.1.0/24}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log()  { echo "==> $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this script as root (sudo bash install.sh)"

# ------------------------------------------------------------------------------
# 1. Install OpenResty
# ------------------------------------------------------------------------------
log "Installing OpenResty..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    wget gnupg ca-certificates lsb-release

DISTRO=$(lsb_release -sc)
wget -qO - https://openresty.org/package/pubkey.gpg \
    | gpg --dearmor -o /usr/share/keyrings/openresty.gpg
echo "deb [signed-by=/usr/share/keyrings/openresty.gpg] \
http://openresty.org/package/ubuntu ${DISTRO} main" \
    > /etc/apt/sources.list.d/openresty.list

apt-get update -qq
apt-get install -y --no-install-recommends openresty

# Install OPM (OpenResty Package Manager)
apt-get install -y --no-install-recommends openresty-opm 2>/dev/null || \
    /usr/local/openresty/bin/opm --help &>/dev/null || \
    { log "OPM not found via apt, installing manually..."; true; }

# Install Lua OIDC dependencies
log "Installing lua-resty-openidc and lua-resty-session..."
/usr/local/openresty/bin/opm get zmartzone/lua-resty-openidc
/usr/local/openresty/bin/opm get bungle/lua-resty-session

# ------------------------------------------------------------------------------
# 2. Create system user
# ------------------------------------------------------------------------------
log "Creating system user: ${APP_USER}..."
if ! id "${APP_USER}" &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "Application service account" "${APP_USER}"
fi

# Add the OpenResty worker user (www-data) to the app group so it can
# read the UNIX socket created by Gunicorn (mode 0750, group appuser).
NGINX_WORKER_USER="www-data"
usermod -aG "${APP_USER}" "${NGINX_WORKER_USER}" || true
log "Added ${NGINX_WORKER_USER} to group ${APP_USER} for socket access"

# ------------------------------------------------------------------------------
# 3. Firewall – restrict port 80 to Application Gateway subnet only
# ------------------------------------------------------------------------------
log "Configuring ufw: allow port 80 from ${GATEWAY_CIDR} only..."
apt-get install -y --no-install-recommends ufw

# Reset any existing HTTP rules and apply a tight allow
ufw delete allow 80/tcp  2>/dev/null || true
ufw delete allow http    2>/dev/null || true
ufw allow from "${GATEWAY_CIDR}" to any port 80 proto tcp comment "App Gateway → nginx"
ufw --force enable

log "ufw rules applied. Verify with: sudo ufw status verbose"

# ------------------------------------------------------------------------------
# 4. Deploy OpenResty / nginx configuration
# ------------------------------------------------------------------------------
log "Deploying nginx configuration..."
install -m 644 "${REPO_DIR}/nginx.conf"          "${OPENRESTY_CONF}"
install -d -m 755                                 "${NGINX_CONF_DIR}"
install -m 644 "${REPO_DIR}/conf.d/oidc_entra.conf" "${NGINX_CONF_DIR}/"
install -m 644 "${REPO_DIR}/conf.d/app.conf"        "${NGINX_CONF_DIR}/"

install -d -m 755                                 "${OPENRESTY_LUA}"
install -m 644 "${REPO_DIR}/lua/oidc_authz.lua"  "${OPENRESTY_LUA}/"

# Note: no SSL certificates are needed on this host.
# TLS is terminated at the Azure Application Gateway.

# ------------------------------------------------------------------------------
# 5. Deploy application code and Python environment
# ------------------------------------------------------------------------------
log "Setting up application directory: ${APP_DIR}..."
install -d -m 755 "${APP_DIR}"
install -d -m 755 "${APP_DIR}/staticfiles"
install -d -m 755 "${APP_DIR}/media"

# Copy gunicorn config
install -d -m 755                                    "${APP_DIR}/gunicorn"
install -m 644 "${REPO_DIR}/gunicorn/gunicorn.conf.py" "${APP_DIR}/gunicorn/"

# Copy .env template if not already present
if [[ ! -f "${APP_DIR}/.env" ]]; then
    install -m 600 "${REPO_DIR}/.env.example" "${APP_DIR}/.env"
    log "Copied .env.example → ${APP_DIR}/.env  (fill in your secrets)"
fi

# Create Python virtualenv
log "Creating Python virtualenv..."
apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip libpq-dev build-essential

"${PYTHON}" -m venv "${APP_DIR}/.venv"
"${APP_DIR}/.venv/bin/pip" install --quiet --upgrade pip

if [[ -f "${APP_DIR}/requirements.txt" ]]; then
    log "Installing Python dependencies..."
    "${APP_DIR}/.venv/bin/pip" install --quiet -r "${APP_DIR}/requirements.txt"
else
    log "No requirements.txt found in ${APP_DIR} – installing gunicorn only"
    "${APP_DIR}/.venv/bin/pip" install --quiet gunicorn
fi

# Fix ownership
chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}"

# ------------------------------------------------------------------------------
# 6. Install systemd service units
# ------------------------------------------------------------------------------
log "Installing systemd service units..."
install -m 644 "${REPO_DIR}/gunicorn/gunicorn.service"   /etc/systemd/system/
install -m 644 "${REPO_DIR}/gunicorn/openresty.service"  /etc/systemd/system/

systemctl daemon-reload

log "Enabling and starting gunicorn..."
systemctl enable --now gunicorn

log "Testing OpenResty config..."
/usr/local/openresty/bin/openresty -t

log "Enabling and starting openresty..."
systemctl enable --now openresty

# ------------------------------------------------------------------------------
# Done
# ------------------------------------------------------------------------------
cat <<EOF

==========================================================================
 Installation complete!

 Next steps:
   1. Edit  ${APP_DIR}/.env  with your Entra ID credentials and app config
   2. Replace YOUR_APP_DOMAIN in:
        ${NGINX_CONF_DIR}/oidc_entra.conf
        ${NGINX_CONF_DIR}/app.conf
   3. Replace the Application Gateway subnet CIDR (10.0.1.0/24) in:
        ${NGINX_CONF_DIR}/app.conf  (geo block + set_real_ip_from)
      and re-run: sudo ufw allow from <YOUR_GATEWAY_CIDR> to any port 80 proto tcp
   4. Configure the Application Gateway backend pool to point at this
      host's private IP on port 80 (HTTP, no TLS).
   5. Deploy your application code to ${APP_DIR}/
   6. Reload both services:
        sudo systemctl reload gunicorn
        sudo openresty -t && sudo systemctl reload openresty

 Useful commands:
   sudo systemctl status  gunicorn openresty
   sudo journalctl -u gunicorn  -f
   sudo journalctl -u openresty -f
   sudo systemctl reload gunicorn        # zero-downtime worker restart
   sudo openresty -t                     # test nginx config
   sudo systemctl reload openresty       # reload nginx config
   sudo ufw status verbose               # verify firewall rules
==========================================================================
EOF
