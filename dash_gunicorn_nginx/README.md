# Dummy Dash App — Mock Entra ID Authentication

A **Dash + Gunicorn + nginx** web application secured with OIDC authentication and role-based authorization, using [Mock Entra ID](../mock-entra-id) as the identity provider.

This is the Dash port of the [flask-app](../flask-app) example — same auth logic, different UI framework.

```
Browser ──► nginx :8080 ──► Gunicorn ──► Dash (wraps Flask) ──► Mock Entra ID :3000
```

---

## Why this works: Dash sits on top of Flask

Dash apps are a Flask app underneath (`Dash(__name__, server=...)` either creates or wraps a Flask `Flask` instance, exposed as `app.server`). This example creates the Flask server explicitly first, attaches the OIDC routes (`/login`, `/callback`, `/logout`, `/api/me`, `/api/whoami`) as ordinary Flask view functions, then hands that server to `Dash(...)`. Dash's own page-rendering logic runs as **callbacks** reading `flask.session` — the exact same session used by the OIDC routes — so authentication state flows naturally between the two without any extra glue.

| Concern | Implementation |
|---|---|
| OIDC flow | Plain Flask routes on `server` (the Flask object) |
| Page routing | `dcc.Location` + a callback keyed on `pathname` (Dash's standard multi-page pattern, no `dash.pages` plugin needed) |
| Auth state | `flask.session`, read inside callbacks via `current_user()` |
| RBAC | Checked inside the routing callback — unauthorized pages render a Bootstrap `Alert` instead of the page content |
| WSGI entrypoint | Gunicorn must point at `main:server` (the Flask object), **not** `main:app` (the Dash object) |

---

## What's implemented

| Feature | Where |
|---|---|
| Authorization Code flow + PKCE (S256) | `/login`, `/callback` (Flask routes) |
| ID token signature verification | `verify_id_token()` — RS256 via JWKS |
| Session-based auth shared with Dash | `flask.session`, read by `current_user()` in callbacks |
| Role-based access control | `/admin` page checks `Admin` role inside the routing callback |
| Protected API route | `/api/me` (session-based) |
| Bearer token API auth | `/api/whoami` (stateless, for API clients) |
| Logout | `/logout` → redirects through Mock Entra ID's `end_session_endpoint` |
| Production WSGI server | Gunicorn, sync workers, pointed at `main:server` |
| Reverse proxy | nginx — TLS termination point, static file serving |
| UI components | `dash-bootstrap-components` (Navbar, Card, Table, Badge, Alert) |

---

## Quick start — Docker Compose (recommended)

```bash
cd dash-app
docker compose up --build
```

Open **http://localhost:8080** and click **Sign in**.

### Test accounts

| Username | Password | Roles |
|---|---|---|
| `alice@contoso.dev` | `Password1!` | Admin, User |
| `bob@contoso.dev` | `Password2!` | User |

Sign in as Alice to access `/admin`. Sign in as Bob and you'll see a "you don't have the required role" message instead of the page content (Dash pages don't return HTTP status codes the way Flask routes do — the routing callback renders an `Alert` in place of the gated content).

---

## Quick start — without Docker

```bash
# 1. Start Mock Entra ID (separate terminal)
cd ../mock-entra-id && node src/server.js

# 2. Install dependencies
cd dash-app/app
pip install -r requirements.txt

# 3. Run with Gunicorn — NOTE: main:server, not main:app
export OIDC_BASE_URL=http://localhost:3000
export OIDC_CLIENT_ID=my-dev-app
export OIDC_CLIENT_SECRET=dev-secret-change-me
export OIDC_REDIRECT_URI=http://localhost:8080/callback
export FLASK_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
gunicorn -c gunicorn.conf.py main:server

# 4. (optional) nginx in front
cd ../nginx
nginx -c $(pwd)/nginx.conf -p $(pwd)
```

---

## Running as systemd services on Ubuntu

This covers running both **Mock Entra ID** and the **Dash app** as persistent systemd services on Ubuntu (22.04 / 24.04), managed with `systemctl`, auto-starting on boot, and logging to `journald`.

Assumed layout on the server:

```
/opt/mock-entra-id/        ← Mock Entra ID project root
/opt/dash-app/             ← this project root
/opt/dash-app/app/         ← main.py, requirements.txt, gunicorn.conf.py
/opt/dash-app/venv/        ← Python virtual environment (created below)
/opt/dash-app/.env         ← environment variables (created below)
```

### 1. Create a dedicated service user

Running services as root is a bad habit even in dev. Create a locked-down user that owns both apps:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin appuser
sudo mkdir -p /opt/mock-entra-id /opt/dash-app
sudo chown -R appuser:appuser /opt/mock-entra-id /opt/dash-app
```

Copy your project files into place (from WSL or via scp):

```bash
sudo cp -r mock-entra-id/. /opt/mock-entra-id/
sudo cp -r dash-app/.      /opt/dash-app/
sudo chown -R appuser:appuser /opt/mock-entra-id /opt/dash-app
```

### 2. Install Node.js (for Mock Entra ID)

```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version   # should print v20.x
```

### 3. Create the Python virtual environment

```bash
sudo apt-get install -y python3 python3-venv python3-pip

sudo -u appuser python3 -m venv /opt/dash-app/venv
sudo -u appuser /opt/dash-app/venv/bin/pip install --upgrade pip
sudo -u appuser /opt/dash-app/venv/bin/pip install -r /opt/dash-app/app/requirements.txt
```

### 4. Write the environment file

Both services read their configuration from `/opt/dash-app/.env`. Keep secrets out of the unit files.

```bash
sudo tee /opt/dash-app/.env > /dev/null << 'EOF'
OIDC_BASE_URL=http://localhost:3000
# Must be reachable from the Gunicorn process — use 127.0.0.1
# rather than localhost to avoid connection refused on some systems
OIDC_INTERNAL_BASE_URL=http://127.0.0.1:3000
OIDC_TENANT_ID=mock-tenant-id
OIDC_CLIENT_ID=my-dev-app
OIDC_CLIENT_SECRET=dev-secret-change-me
OIDC_REDIRECT_URI=http://localhost:8080/callback
OIDC_SCOPE=openid profile email offline_access
OIDC_POST_LOGOUT_REDIRECT=http://localhost:8080/
# REQUIRED — must be identical across all Gunicorn workers.
# A random value per-worker causes state_mismatch errors at /callback.
FLASK_SECRET_KEY=change-me-to-a-long-random-string
GUNICORN_PORT=8080
GUNICORN_WORKERS=2
GUNICORN_LOG_LEVEL=info
PORT=3000
BASE_URL=http://localhost:3000
TENANT_ID=mock-tenant-id
EOF

sudo chown appuser:appuser /opt/dash-app/.env
sudo chmod 640 /opt/dash-app/.env
```

Generate a real Flask secret key and paste it in:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
sudo nano /opt/dash-app/.env   # replace FLASK_SECRET_KEY value
```

### 5. Pre-create the certs directory

The mock server auto-generates RSA keys on first start. The directory must exist and be writable **before** the service starts — otherwise `ProtectSystem=strict` blocks the write and the service starts but immediately fails to reach the token endpoint.

```bash
sudo mkdir -p /opt/mock-entra-id/certs
sudo chown appuser:appuser /opt/mock-entra-id/certs
```

### 6. Find the correct Node.js binary path

The path varies depending on how Node was installed. Verify it now — you will need the exact output in the next step:

```bash
which node
# common results:
#   /usr/bin/node          (apt / NodeSource)
#   /usr/local/bin/node    (nvm, manual install)
#   /home/<user>/.nvm/versions/node/v20.x.x/bin/node  (nvm per-user)
```

If `which node` returns nothing, Node.js is not in the system PATH for non-login shells. Either install it system-wide (`sudo apt-get install -y nodejs`) or use the full absolute path from `nvm`:

```bash
# nvm users — get the absolute path
nvm which current
```

### 7. Create the Mock Entra ID service unit

Replace `/usr/bin/node` below with the path from the previous step if it differs.

```bash
sudo tee /etc/systemd/system/mock-entra-id.service > /dev/null << 'EOF'
[Unit]
Description=Mock Entra ID — local OIDC identity provider
After=network.target

[Service]
Type=simple
User=appuser
Group=appuser
WorkingDirectory=/opt/mock-entra-id
EnvironmentFile=/opt/dash-app/.env

ExecStart=/usr/bin/node src/server.js
Restart=on-failure
RestartSec=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=mock-entra-id

# Hardening — certs/ must be pre-created (see step 5) before
# ProtectSystem=strict takes effect, otherwise key generation fails.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/mock-entra-id/certs

[Install]
WantedBy=multi-user.target
EOF
```

### 8. Create the Dash app service unit

```bash
sudo tee /etc/systemd/system/dash-app.service > /dev/null << 'EOF'
[Unit]
Description=Dash App — Gunicorn WSGI server
After=network.target mock-entra-id.service
# Wants= ensures mock-entra-id starts first but does NOT wait for it
# to be fully ready. The 5 s StartLimitBurst / RestartSec on the Dash
# service means a brief race is handled by automatic restart.
Wants=mock-entra-id.service

[Service]
Type=simple
User=appuser
Group=appuser
WorkingDirectory=/opt/dash-app/app
EnvironmentFile=/opt/dash-app/.env

ExecStart=/opt/dash-app/venv/bin/gunicorn     -c gunicorn.conf.py     main:server

Restart=on-failure
RestartSec=5

StandardOutput=journal
StandardError=journal
SyslogIdentifier=dash-app

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/dash-app

[Install]
WantedBy=multi-user.target
EOF
```

### 9. Enable and start both services

```bash
sudo systemctl daemon-reload

sudo systemctl enable mock-entra-id.service
sudo systemctl enable dash-app.service

sudo systemctl start mock-entra-id.service
sudo systemctl start dash-app.service
```

### 10. Verify and diagnose

Run these immediately after starting — they surface the most common failures:

```bash
# --- Are both services active? ---
sudo systemctl status mock-entra-id.service
sudo systemctl status dash-app.service
# Both must show:  Active: active (running)
# "activating" means it crashed and is retrying — check logs.

# --- Can the token endpoint be reached from the server? ---
curl http://127.0.0.1:3000/health
# Must return {"status":"ok",...}
# Connection refused means mock-entra-id.service is not running.
# Check: sudo journalctl -n 30 -u mock-entra-id.service

# --- HTTP smoke test ---
curl http://localhost:3000/health   # Mock Entra ID
curl http://localhost:8080/healthz  # Dash app

# --- Common failure: wrong Node.js path ---
# If mock-entra-id shows "failed" in status, check:
sudo journalctl -n 20 -u mock-entra-id.service
# "No such file or directory" on ExecStart means the node path is wrong.
# Fix it:
sudo nano /etc/systemd/system/mock-entra-id.service
# Change ExecStart=/usr/bin/node to the path from: which node
sudo systemctl daemon-reload && sudo systemctl restart mock-entra-id.service

# --- Common failure: certs directory not writable ---
# "ENOENT" or "EACCES" in mock-entra-id logs means certs/ is missing or
# owned by root. Fix it:
sudo mkdir -p /opt/mock-entra-id/certs
sudo chown appuser:appuser /opt/mock-entra-id/certs
sudo systemctl restart mock-entra-id.service

# --- Common failure: FLASK_SECRET_KEY not set ---
# Dash app exits immediately with RuntimeError. Check:
sudo journalctl -n 10 -u dash-app.service
# Set FLASK_SECRET_KEY in /opt/dash-app/.env and restart.

# --- Common failure: state_mismatch at /callback ---
# Means FLASK_SECRET_KEY differs between Gunicorn workers or changed
# after a restart. Ensure it is a fixed string in .env, not generated
# at runtime. Restart the service after fixing .env:
sudo systemctl restart dash-app.service

# --- Common failure: connection refused on token endpoint ---
# Means OIDC_INTERNAL_BASE_URL points to an address the Gunicorn process
# cannot reach. Verify mock-entra-id is running first, then check:
curl http://127.0.0.1:3000/health
# If that succeeds but the app still fails, ensure your .env contains:
#   OIDC_INTERNAL_BASE_URL=http://127.0.0.1:3000
```

### 11. View logs

```bash
# Live-follow both services together
sudo journalctl -f -u mock-entra-id.service -u dash-app.service

# Last 50 lines for a specific service
sudo journalctl -n 50 -u mock-entra-id.service
sudo journalctl -n 50 -u dash-app.service

# Since last boot
sudo journalctl -b -u dash-app.service
```

### 12. Restart / stop / disable

```bash
# Restart after editing .env or updating code
sudo systemctl restart mock-entra-id.service
sudo systemctl restart dash-app.service

# Stop both
sudo systemctl stop dash-app.service mock-entra-id.service

# Remove from auto-start
sudo systemctl disable dash-app.service mock-entra-id.service
```

### 13. Updating the application

After pulling new code into `/opt/dash-app/` or `/opt/mock-entra-id/`:

```bash
# Re-install Python deps if requirements.txt changed
sudo -u appuser /opt/dash-app/venv/bin/pip install -r /opt/dash-app/app/requirements.txt

# Restart to pick up changes
sudo systemctl restart mock-entra-id.service
sudo systemctl restart dash-app.service
```

### Service dependency overview

```
boot
 └─► mock-entra-id.service    (Node.js, port 3000)
      └─► dash-app.service    (Gunicorn, port 8080)
                                     │
                              nginx (port 80)        ← managed separately
                              or direct access
```

`dash-app.service` declares `Wants=mock-entra-id.service` so systemd starts the IdP first. If Mock Entra ID crashes and restarts, the Dash app reconnects automatically on the next OIDC request — JWKS keys are re-fetched lazily.

### nginx as a service (optional)

If you installed nginx via `apt`, it already runs as a systemd service. Drop the config in place and reload:

```bash
sudo apt-get install -y nginx
sudo cp /opt/dash-app/nginx/nginx.conf /etc/nginx/nginx.conf
sudo nginx -t                          # verify config syntax
sudo systemctl enable nginx
sudo systemctl restart nginx
```

nginx proxies `:80 → :8080` (Gunicorn), so users hit port 80 and never see Gunicorn directly.


---

## Project structure

```
dash-app/
├── app/
│   ├── main.py              # Flask server + OIDC routes + Dash app + layouts/callbacks
│   ├── gunicorn.conf.py     # Gunicorn worker/timeout config
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   ├── nginx.conf           # Reverse proxy config
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

Unlike the Flask version, there's no `templates/` directory — Dash layouts are built with Python (`dash_html_components`, `dash_bootstrap_components`) inside `main.py` rather than Jinja HTML files.

---

## How the auth flow works

Identical to the Flask version — the OIDC mechanics don't change, only how pages render afterward:

1. **`GET /login`** (Flask route) — generates a PKCE verifier/challenge pair and a `state`/`nonce`, stores them in `flask.session`, redirects to Mock Entra ID's `/authorize`.
2. **User authenticates** on Mock Entra ID's login page.
3. **`GET /callback?code=...&state=...`** (Flask route) — validates `state`, exchanges the code for tokens, verifies the `id_token`'s RS256 signature via JWKS, checks `nonce`, stores claims in `flask.session["user"]`, redirects to `/dashboard`.
4. **Dash takes over** — the browser loads the Dash single-page shell at `/dashboard`. Dash's client-side router fires the `render_page` callback with `pathname="/dashboard"`, which calls `current_user()` (reading the same `flask.session`) and renders the dashboard layout if authenticated.
5. **Role gating** — the same callback checks `"Admin" in user.get("roles", [])` for `/admin` and renders an `Alert` instead of the page if the check fails.
6. **`GET /logout`** (Flask route) clears `flask.session` and redirects through Mock Entra ID's `end_session_endpoint`.

---

## Bearer token auth (for API clients)

`/api/whoami` works identically to the Flask version — same Flask route, same logic:

```bash
TOKEN=$(curl -s -X POST http://localhost:3000/mock-tenant-id/oauth2/v2.0/token \
  -d "grant_type=client_credentials&client_id=my-dev-app&client_secret=dev-secret-change-me" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/whoami
```

---

## Configuration reference

Same environment variables as the Flask version — see `.env.example`.

| Variable | Description |
|---|---|
| `OIDC_BASE_URL` | Mock Entra ID base URL the **browser** can reach |
| `OIDC_TENANT_ID` | Must match Mock Entra ID's `TENANT_ID` |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | Must match a registered client in Mock Entra ID |
| `OIDC_REDIRECT_URI` | Must be in that client's `redirectUris` list |
| `FLASK_SECRET_KEY` | Signs the Flask session cookie underlying Dash's session |

---

## Adding more protected pages

Add a new branch to the `render_page` callback in `main.py`:

```python
def page_reports(user):
    return card(html.H2("Reports"), html.P("Reports content here"))

# inside render_page():
if pathname == "/reports":
    if not user:
        return page_login_required()
    if not set(user.get("roles", [])).intersection({"Admin", "Analyst"}):
        return page_forbidden()
    return page_reports(user)
```

And add the corresponding nav link in `navbar()` if it should appear in the menu.

---

## Gotchas specific to Dash

- **Gunicorn must target `main:server`**, not `main:app`. `app` is the `Dash` instance (not directly WSGI-callable in the way Gunicorn expects for this setup); `server` is the underlying Flask app.
- **Dash's internal endpoints** (`/_dash-layout`, `/_dash-dependencies`, `/_dash-update-component`) are plain Flask routes registered by the `Dash()` constructor — nginx proxies them transparently, no special config needed beyond a reasonable `client_max_body_size`.
- **No per-page HTTP status codes.** A Flask route can return `403`; a Dash "page" is really just a callback output, so unauthorized access renders an `Alert` component with `200 OK` rather than an actual `403` response. If you need real HTTP-level gating (e.g. for a load balancer health check or an API consumed by non-browser clients), keep that logic in a Flask route instead, the way `/api/me` does it.

---

## Security notes

Same as the Flask version:
- This is a **development/demo** app. Set a stable `FLASK_SECRET_KEY` or sessions won't survive a restart.
- Set `SESSION_COOKIE_SECURE=True` once behind HTTPS.
- Gunicorn binds with `forwarded_allow_ips = "*"` for convenience — restrict this to nginx's IP in any shared environment.
- Mock Entra ID has no rate limiting or audit logging — don't point this stack at real credentials.

---

## Switching to real Microsoft Entra ID

The application code implements standard OIDC Authorization Code + PKCE. Real Entra ID uses the same protocol, so switching is mostly a configuration change — no new libraries, no new auth logic.

### 1. Create an App Registration in Azure Portal

1. **Azure Portal → Microsoft Entra ID → App registrations → New registration**
   - Name: anything descriptive
   - Supported account types: *Accounts in this organizational directory only* (single-tenant)
   - Redirect URI: Web → `https://your-app.example.com/callback`

2. **Authentication tab**
   - Add `https://your-app.example.com/` as a post-logout redirect URI
   - Front-channel logout URL: `https://your-app.example.com/logout`

3. **Certificates & secrets → New client secret**
   - Copy the value immediately — Azure only shows it once

4. **Token configuration** (recommended)
   - Add optional claims on the ID token: `email`, `family_name`, `given_name`
   - Without this, `email` may be absent for some account types

5. **App roles** (if you use role-based access like the `/admin` page)
   - App roles → Create app role for each role (`Admin`, `User`, …)
   - Enterprise Applications → your app → Users and groups → assign users to roles

### 2. Update environment variables

```bash
# Real Entra ID — replace these values in your .env file

# Azure tenant ID — found in Entra ID → Overview
OIDC_BASE_URL=https://login.microsoftonline.com/your-tenant-id-here
OIDC_TENANT_ID=your-tenant-id-here

# Real Entra ID is a public endpoint — internal and external URL are the same.
# Set OIDC_INTERNAL_BASE_URL to the same value as OIDC_BASE_URL, or remove it
# (it defaults to OIDC_BASE_URL when not set).
OIDC_INTERNAL_BASE_URL=https://login.microsoftonline.com/your-tenant-id-here

# From App Registration → Overview
OIDC_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

# From App Registration → Certificates & secrets
OIDC_CLIENT_SECRET=your-client-secret-value

# Your app's public HTTPS URL — must match what you registered in step 1
OIDC_REDIRECT_URI=https://your-app.example.com/callback
OIDC_POST_LOGOUT_REDIRECT=https://your-app.example.com/

# These stay the same
OIDC_SCOPE=openid profile email offline_access
FLASK_SECRET_KEY=<your stable random key>
```

### 3. Two code changes in main.py

**Remove the WSL clock skew workaround** — the 150 s leeway and disabled `iat` check were needed because the WSL clock freezes on Windows sleep, causing a large skew between Node.js (Mock Entra ID) and Python. With real Entra ID served from Microsoft's infrastructure there is no such skew. Restore normal validation:

```python
# Before (WSL workaround):
options={"require": ["exp", "iat", "sub"], "verify_iat": False},
leeway=timedelta(seconds=150),

# After (real Entra ID):
options={"require": ["exp", "iat", "sub"]},
leeway=timedelta(seconds=10),   # small tolerance is still good practice
```

**Enable the secure session cookie** — uncomment the one line in the Flask config:

```python
server.config.update(
    SESSION_COOKIE_NAME="dash_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
    SESSION_COOKIE_SECURE=True,   # ← uncomment this
)
```

### 4. What stays identical

Everything else in the code works unchanged against real Entra ID:

| Component | Why it stays the same |
|---|---|
| OIDC discovery URL | Real Entra ID uses the same `/.well-known/openid-configuration` path |
| PKCE (S256) | Real Entra ID fully supports it, same parameters |
| Token exchange | Same POST to `/token`, same JSON response shape |
| JWKS verification | Real Entra ID serves RS256 keys at the same path pattern |
| `roles` and `groups` claims | Same claim names — populated from Azure instead of the mock user list |
| `/api/whoami` Bearer auth | Works identically |
| Session handling | No change |
| Gunicorn / nginx config | No change |

The `OIDC_BASE_URL` / `OIDC_INTERNAL_BASE_URL` split becomes irrelevant — `login.microsoftonline.com` is publicly reachable from both the browser and your Gunicorn process, so both variables hold the same value. The code still reads them separately, which does no harm.