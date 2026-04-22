# nginx + lua-resty-openidc + Entra ID — Setup Guide

## Architecture

```
Browser ──HTTPS──▶ OpenResty/nginx
                       │  lua-resty-openidc validates/initiates OIDC flow
                       │  Injects X-Auth-* headers
                       ▼
                   Gunicorn + Flask
                       │  Reads headers via flask_oidc_identity.py
                       ▼
                   Your application logic
```

---

## 1. Entra ID App Registration

In the [Azure Portal](https://portal.azure.com) → **Entra ID → App registrations → New registration**:

| Field | Value |
|---|---|
| Name | your-app-name |
| Supported account types | Single tenant (or multi) |
| Redirect URI – Platform | **Web** |
| Redirect URI – Value | `https://your.domain.example.com/oidc/callback` |

After creation:

1. **Certificates & secrets → New client secret** — copy the *Value* (shown once).
2. **Token configuration → Add optional claim → ID token** → add `email`, `preferred_username`.
3. *(Optional)* **Manifest → `groupMembershipClaims`** → set to `"SecurityGroup"` or `"All"` if you need group GUIDs in the token.
4. *(Optional)* **App roles** — define roles and assign users/groups; they appear as `roles` claim.

---

## 2. Environment Variables

```bash
cp .env.example .env
# Edit .env with your real Tenant ID, Client ID, and Client Secret
```

---

## 3. TLS Certificate

Place your certificate files in `./ssl/`:

```
ssl/
  server.crt   # full-chain PEM
  server.key   # private key PEM
```

For local development you can generate a self-signed cert:

```bash
mkdir -p ssl
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout ssl/server.key \
  -out ssl/server.crt \
  -subj "/CN=localhost"
```

---

## 4. Install Lua Dependencies (if not using Docker)

With **OpenResty** + **opm**:

```bash
opm get zmartzone/lua-resty-openidc
opm get bungle/lua-resty-session
opm get cdbattags/lua-resty-jwt
opm get ledgetech/lua-resty-http
```

Or with **LuaRocks**:

```bash
luarocks install lua-resty-openidc
luarocks install lua-resty-session
```

---

## 5. Start the Stack

```bash
docker compose up --build
```

---

## 6. File Layout

```
.
├── .env.example
├── docker-compose.yml
├── nginx/
│   ├── nginx.conf                  # Main nginx config
│   └── conf.d/
│       ├── oidc_config.lua         # Entra ID OIDC options
│       ├── oidc_access.lua         # access_by_lua_file handler
│       └── oidc_logout.lua         # /oidc/logout handler
├── app/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── wsgi.py                     # Gunicorn entry point
│   ├── flask_oidc_identity.py      # Identity header helper  ← copy here
│   └── ...your Flask app...
└── ssl/
    ├── server.crt
    └── server.key
```

---

## 7. Flask Integration

Copy `flask_oidc_identity.py` into your Flask project, then use:

```python
from flask_oidc_identity import current_user, require_auth, require_role

@app.route("/api/me")
@require_auth
def me():
    return {
        "sub":      current_user.sub,
        "username": current_user.username,
        "email":    current_user.email,
        "roles":    current_user.roles,
        "groups":   current_user.groups,
    }

@app.route("/admin")
@require_role("Admin")
def admin():
    return "Admin area"
```

---

## 8. Headers Injected by nginx

| Header | Source claim | Description |
|---|---|---|
| `X-Auth-Sub` | `sub` | Immutable Entra ID object ID |
| `X-Auth-User` | `preferred_username` | UPN / email login |
| `X-Auth-Email` | `email` | Email address |
| `X-Auth-Name` | `name` | Display name |
| `X-Auth-Roles` | `roles` | Comma-separated app roles |
| `X-Auth-Groups` | `groups` | Comma-separated group GUIDs |
| `X-Access-Token` | — | Raw access token (for MS Graph calls) |

---

## 9. Common Issues

**`discovery` endpoint 403 / SSL error**  
→ Ensure the nginx container can reach `login.microsoftonline.com` (check DNS and egress firewall rules).

**`redirect_uri_mismatch`**  
→ The URI in `oidc_config.lua` (`APP_BASE_URL + /oidc/callback`) must exactly match one registered in the Entra ID app under *Authentication → Redirect URIs*.

**Token doesn't include `groups` or `roles`**  
→ Enable `groupMembershipClaims` in the App Manifest, and/or create App Roles and assign users/groups in *Enterprise Applications → App → Users and groups*.

**Session cookie too large (> 4 KB)**  
→ Switch to server-side session storage (Redis) by configuring `lua-resty-session` with the `redis` storage adapter.
