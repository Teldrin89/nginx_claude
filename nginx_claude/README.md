# nginx + Microsoft Entra ID OIDC → Gunicorn WSGI

Protect any Python web application behind Microsoft Entra ID (formerly Azure AD)
single sign-on using **OpenResty** (nginx + LuaJIT), **lua-resty-openidc**, and
**Gunicorn** — running directly on Ubuntu 22.04 / 24.04.

TLS is terminated at an **Azure Application Gateway**. The connection between
the gateway and nginx is plain HTTP on a private network — no certificates are
needed on the nginx host.

---

## Architecture

```
                        ┌─────────────────────────────────────────────┐
                        │              Azure / Private VNet            │
                        │                                              │
Internet                │  App Gateway subnet       nginx host         │
   │                    │  ┌─────────────────┐    ┌──────────────────┐│
   │  HTTPS/443         │  │ Application     │    │  OpenResty       ││
   └───────────────────►│  │ Gateway         │    │  (HTTP/80 only)  ││
                        │  │                 │    │                  ││
                        │  │  TLS termination│    │  lua-resty-      ││
                        │  │  WAF rules      ├───►│  openidc         ││
                        │  │  Health probes  │    │  (OIDC / Entra)  ││
                        │  │                 │    │        │         ││
                        │  └─────────────────┘    │        ▼         ││
                        │    HTTP/80 (plain)       │  Gunicorn        ││
                        │    private subnet only   │  (UNIX socket)   ││
                        │                          │        │         ││
                        │                          │        ▼         ││
                        │                          │  Django / Flask  ││
                        │                          └──────────────────┘│
                        └─────────────────────────────────────────────┘
                                     │
                             Entra ID (OIDC)
                        login.microsoftonline.com
```

**Key points:**
- The Application Gateway owns the TLS certificate. nginx never sees a private key.
- Port 80 on the nginx host is restricted to the gateway subnet at both the NSG and ufw levels.
- nginx reconstructs the public `https://` origin from `X-Forwarded-Proto` / `X-Forwarded-Host` so OIDC redirect URIs and session cookies reference the correct public URL.
- Gunicorn is reached via a UNIX socket — no TCP port exposed.

---

## File layout

```
nginx-oidc/
├── install.sh                      # one-shot provisioning script
├── nginx.conf                      # OpenResty main config (Lua shared memory)
├── .env.example                    # secrets template → copy to /opt/app/.env
├── conf.d/
│   ├── oidc_entra.conf             # Entra ID endpoints & nginx map variables
│   └── app.conf                    # server block, gateway trust, upstream pool
├── lua/
│   └── oidc_authz.lua              # optional role / group enforcement helper
└── gunicorn/
    ├── gunicorn.conf.py            # Gunicorn settings (workers, socket, logs)
    ├── gunicorn.service            # systemd unit for Gunicorn
    ├── openresty.service           # systemd unit for OpenResty
    └── requirements.txt            # Python deps template
```

---

## 1 – Azure Application Gateway setup

### 1.1 Backend pool
- Add the nginx VM's **private IP** as the backend target.
- **Protocol: HTTP**, **Port: 80** — no TLS toward the backend.

### 1.2 Backend HTTP settings
| Setting | Value |
|---|---|
| Protocol | HTTP |
| Port | 80 |
| Cookie-based affinity | Disabled (sessions handled by Gunicorn/nginx) |
| Override with new host name | **Pick host name from backend target** (or set explicitly to your domain) |
| Custom probe | See 1.4 below |

### 1.3 Listener
- **Protocol: HTTPS**, **Port: 443**
- Attach your TLS certificate (Key Vault reference recommended).
- Enable **HTTP/2** if desired.

### 1.4 Health probe
Configure a custom HTTP probe against the nginx host:
- Protocol: HTTP
- Path: `/static/health.txt` (create a static file) or any publicly accessible path that returns 200.
- Port: 80

### 1.5 Routing rule
Wire the HTTPS listener → backend HTTP settings → backend pool.

### 1.6 Network Security Group (NSG)
On the **nginx VM's NIC or subnet NSG**, add an inbound rule:

| Priority | Source | Port | Protocol | Action |
|---|---|---|---|---|
| 100 | Application Gateway subnet CIDR | 80 | TCP | Allow |
| 200 | Any | 80 | TCP | Deny |

This ensures no traffic reaches port 80 except from the gateway, even if ufw is misconfigured.

### 1.7 Required headers from the gateway
Ensure the Application Gateway forwards these headers to the backend (they are sent by default in most configurations):

| Header | Purpose |
|---|---|
| `X-Forwarded-For` | Original client IP chain |
| `X-Forwarded-Proto` | Always `https` (gateway terminates TLS) |
| `X-Forwarded-Host` | Public hostname the client requested |

---

## 2 – Register an App in Microsoft Entra ID

1. Go to **Azure Portal → Entra ID → App registrations → New registration**.
2. Set **Redirect URI** (Web) to `https://YOUR_APP_DOMAIN/oidc/callback`.
   Note: this is the **public gateway URL** — always `https://`.
3. Under **Certificates & Secrets** → create a **Client secret** and copy it.
4. Copy the **Application (Client) ID** and **Directory (Tenant) ID** from the *Overview* page.
5. Under **API permissions**, confirm `openid`, `profile`, and `email` are granted.
6. *(Optional)* Define **App roles** under App roles; they appear in the `roles` claim.
7. *(Optional)* Set `"groupMembershipClaims": "SecurityGroup"` in the Manifest for group claims.

---

## 3 – Automated install (recommended)

```bash
# Set your Application Gateway subnet before running
export GATEWAY_CIDR="10.0.1.0/24"   # replace with your actual subnet

sudo -E bash install.sh
```

The script installs OpenResty and Lua OIDC libraries, creates the `appuser`
system account, locks down port 80 with ufw to `GATEWAY_CIDR`, deploys all
config files, sets up a Python virtualenv, and registers both systemd services.

---

## 4 – Manual install (step by step)

### 4.1 Install OpenResty

```bash
sudo apt-get install -y wget gnupg ca-certificates lsb-release

DISTRO=$(lsb_release -sc)
wget -qO - https://openresty.org/package/pubkey.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/openresty.gpg
echo "deb [signed-by=/usr/share/keyrings/openresty.gpg] \
http://openresty.org/package/ubuntu ${DISTRO} main" \
  | sudo tee /etc/apt/sources.list.d/openresty.list

sudo apt-get update
sudo apt-get install -y openresty openresty-opm
```

### 4.2 Install Lua OIDC libraries

```bash
sudo /usr/local/openresty/bin/opm get zmartzone/lua-resty-openidc
sudo /usr/local/openresty/bin/opm get bungle/lua-resty-session
```

### 4.3 Create the application user

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin appuser
sudo usermod -aG appuser www-data   # OpenResty worker reads the Gunicorn socket
```

### 4.4 Lock down port 80 to the gateway subnet

```bash
sudo apt-get install -y ufw

# Replace with your actual Application Gateway subnet
GATEWAY_CIDR="10.0.1.0/24"

sudo ufw allow from "${GATEWAY_CIDR}" to any port 80 proto tcp comment "App Gateway → nginx"
sudo ufw --force enable
sudo ufw status verbose
```

Also apply the NSG rule described in section 1.6 for defence-in-depth.

### 4.5 Deploy nginx / OpenResty config

```bash
sudo cp nginx.conf    /usr/local/openresty/nginx/conf/nginx.conf
sudo cp conf.d/*      /etc/nginx/conf.d/
sudo cp lua/*         /usr/local/openresty/nginx/lua/
```

### 4.6 Fill in your values

**`/etc/nginx/conf.d/oidc_entra.conf`** — set tenant ID, client ID, client secret, and app domain.

**`/etc/nginx/conf.d/app.conf`** — two places to update:
- `YOUR_APP_DOMAIN` in `server_name`
- `10.0.1.0/24` in the `geo` block and `set_real_ip_from` with your actual Application Gateway subnet CIDR

### 4.7 Deploy the Python application

```bash
sudo mkdir -p /opt/app
sudo chown appuser:appuser /opt/app

# Copy your application code to /opt/app/, then:
sudo -u appuser python3 -m venv /opt/app/.venv
sudo -u appuser /opt/app/.venv/bin/pip install -r /opt/app/requirements.txt

# Django only
sudo -u appuser /opt/app/.venv/bin/python manage.py collectstatic --noinput

sudo mkdir -p /opt/app/gunicorn
sudo cp gunicorn/gunicorn.conf.py /opt/app/gunicorn/gunicorn.conf.py
```

### 4.8 Configure environment variables

```bash
sudo cp .env.example /opt/app/.env
sudo chmod 600 /opt/app/.env
sudo nano /opt/app/.env
```

### 4.9 Install and start systemd services

```bash
sudo cp gunicorn/gunicorn.service  /etc/systemd/system/
sudo cp gunicorn/openresty.service /etc/systemd/system/
sudo systemctl daemon-reload

sudo systemctl enable --now gunicorn
sudo openresty -t
sudo systemctl enable --now openresty
```

---

## 5 – Application-level proxy trust (Django / Flask)

Because the Application Gateway prepends to `X-Forwarded-For` and sets
`X-Forwarded-Proto: https`, your application must trust these headers.

**Django** — add to `settings.py`:
```python
USE_X_FORWARDED_HOST  = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
# Trust only the nginx host (localhost) — nginx already validated the gateway
ALLOWED_HOSTS = ["YOUR_APP_DOMAIN", "127.0.0.1"]
```

**Flask** — use `werkzeug.middleware.proxy_fix`:
```python
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
```

---

## 6 – Day-to-day operations

| Task | Command |
|------|---------|
| Check service status | `sudo systemctl status gunicorn openresty` |
| Follow Gunicorn logs | `sudo journalctl -u gunicorn -f` |
| Follow OpenResty logs | `sudo journalctl -u openresty -f` |
| Zero-downtime worker reload | `sudo systemctl reload gunicorn` |
| Test nginx config | `sudo openresty -t` |
| Reload nginx config | `sudo systemctl reload openresty` |
| Restart after code deploy | `sudo systemctl restart gunicorn` |
| Check firewall rules | `sudo ufw status verbose` |

---

## 7 – Role-based access control (optional)

```nginx
location /admin {
    access_by_lua_block {
        local oidc  = require("resty.openidc")
        local authz = require("oidc_authz")
        oidc.authenticate({ --[[ same opts as in location / ]] })
        authz.require_role("MyApp.Admin")
    }
    proxy_pass http://gunicorn;
    -- same proxy_set_header directives as location /
}
```

---

## 8 – Identity headers forwarded to Gunicorn

| nginx header | Entra ID claim | Django / Flask access |
|---|---|---|
| `X-Auth-User` | `preferred_username` (UPN) | `request.META["HTTP_X_AUTH_USER"]` |
| `X-Auth-Name` | `name` | `request.META["HTTP_X_AUTH_NAME"]` |
| `X-Auth-Email` | `email` | `request.META["HTTP_X_AUTH_EMAIL"]` |
| `X-Auth-Roles` | `roles` (comma-separated) | `request.META["HTTP_X_AUTH_ROLES"]` |

Flask: `request.headers.get("X-Auth-User")` etc.

---

## 9 – Security notes

* **No TLS certificate on this host.** The private key lives only in the Application Gateway (ideally referencing Azure Key Vault). The nginx VM cannot be used to decrypt traffic.
* **Defence-in-depth:** port 80 is blocked at two layers — the Azure NSG and ufw. nginx also rejects requests not originating from the declared gateway CIDR via the `geo` block.
* **Never** commit `/opt/app/.env` to source control. Use Azure Key Vault references in the Application Gateway and inject secrets via environment at startup.
* `forwarded_allow_ips = "127.0.0.1"` in `gunicorn.conf.py` ensures Gunicorn only trusts `X-Forwarded-For` from the local OpenResty process.
* Rotate the Entra ID client secret on your policy schedule; update `/opt/app/.env` and run `sudo systemctl restart gunicorn`.
