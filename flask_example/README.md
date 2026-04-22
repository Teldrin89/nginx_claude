# Calculator — Example Flask App with Entra ID Auth

A single-page calculator that demonstrates the full
**nginx → lua-resty-openidc → Gunicorn → Flask** authentication chain.

```
Browser ──HTTPS──▶ nginx (lua-resty-openidc)
                       │ injects X-Auth-* headers
                       ▼
                   Gunicorn
                       │
                       ▼
                   Flask (routes.py)
                       │ flask_oidc_identity.current_user
                       ▼
                   calculator.html  (Jinja2 + vanilla JS)
                       │ fetch POST /api/calculate
                       ▼
                   routes.py  →  Python math  →  JSON result
```

---

## Project layout

```
example-app/
├── wsgi.py                        # Gunicorn entry point
├── dev_server.py                  # Local dev runner (no nginx needed)
├── requirements.txt
├── app/
│   ├── __init__.py                # Flask factory
│   ├── routes.py                  # All routes + /api/calculate
│   ├── flask_oidc_identity.py     # current_user / @require_auth helpers
│   └── templates/
│       └── calculator.html        # Single-page calculator UI
```

---

## Local development (no nginx / Entra ID)

```bash
pip install -r requirements.txt
python dev_server.py
# → http://localhost:5000
```

`dev_server.py` injects fake `X-Auth-*` headers before every request so
`flask_oidc_identity` behaves exactly as in production.  Override the
fake identity with env vars:

```bash
DEV_NAME="Jane Smith" DEV_EMAIL="jane@corp.com" python dev_server.py
```

---

## Production (with nginx + Entra ID)

Place this app directory inside the stack from the parent folder and
run via Docker Compose:

```bash
cd ..
cp .env.example .env  # fill in Entra ID credentials
docker compose up --build
```

nginx handles authentication entirely; Flask **never** sees
unauthenticated requests.

---

## Identity in templates

The `user` object is passed to every template:

```jinja2
Hello, {{ user.name }}!          {# Display name #}
{{ user.email }}                 {# Email address #}
{{ user.sub }}                   {# Immutable Entra ID object ID #}
{% for role in user.roles %}...  {# App roles #}
```

## Identity in route handlers

```python
from app.flask_oidc_identity import current_user, require_auth, require_role

@app.route("/secret")
@require_auth
def secret():
    return f"Hello {current_user.name}"

@app.route("/admin")
@require_role("Admin")
def admin():
    return "Admin only"
```

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | ✅ required | Calculator UI |
| POST | `/api/calculate` | ✅ required | Evaluate expression |
| GET | `/api/whoami` | ✅ required | Return current user JSON |
| GET | `/health` | ❌ open | Health probe for nginx / k8s |
| GET | `/oidc/logout` | — | Handled by nginx lua |
