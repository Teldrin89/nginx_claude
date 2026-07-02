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
