# Dash Calculator — Entra ID Auth via lua-resty-openidc

A single-page calculator built with **Plotly Dash**, demonstrating the complete
**nginx → lua-resty-openidc → Gunicorn → Dash** authentication chain.

---

## Architecture

```
Browser ──HTTPS──▶ nginx (OpenResty + lua-resty-openidc)
                       │
                       │  X-Auth-Sub, X-Auth-User, X-Auth-Email,
                       │  X-Auth-Name, X-Auth-Roles  (injected)
                       ▼
                   Gunicorn  (wsgi.py → dash_app.server)
                       │
                   Dash internal Flask server
                       ├── before_request auth guard
                       ├── serve_layout()  ← callable layout, reads identity at render
                       └── /_dash-update-component  ← callbacks (also in request context)
```

---

## How Dash differs from plain Flask

| Concern | Plain Flask | Dash |
|---|---|---|
| Serving HTML | `render_template()` | `app.layout` (Python component tree) |
| User identity in HTML | `render_template("x.html", user=user)` | Callable `app.layout = serve_layout` (called per page load inside a request context) |
| User identity in handlers | `@bp.route` + `current_user` | `@callback` + `get_current_user()` — same Flask request context |
| WSGI entry point | `app` (Flask) | `dash_app.server` (Dash's internal Flask) |
| Auth guard | `@app.before_request` | Same — attached to `dash_app.server` |

---

## Project layout

```
dash-example/
├── wsgi.py                    # Gunicorn entry point — binds to dash_app.server
├── dev_server.py              # Local dev runner (no nginx needed)
├── requirements.txt
├── assets/
│   └── styles.css             # Dash auto-serves everything in assets/
└── app/
    ├── __init__.py            # App factory: auth guard, layout, route registration
    ├── layout.py              # build_layout(name, email, sub) → html.Div tree
    ├── callbacks.py           # All @callback decorators; reads identity via get_current_user()
    └── flask_oidc_identity.py # current_user proxy + @require_auth / @require_role
```

---

## Local development

```bash
pip install -r requirements.txt
python dev_server.py
# → http://localhost:8050
```

Override the fake identity:

```bash
DEV_NAME="Alice Smith" DEV_EMAIL="alice@corp.com" DEV_ROLES="Admin" python dev_server.py
```

---

## Production deployment

Use the same `docker-compose.yml` and nginx files from the parent directory.
The only change vs the Flask example is `wsgi.py`:

```python
# Plain Flask example
from app import create_app
app = create_app()

# Dash example — Gunicorn must bind to dash_app.server (the inner Flask app)
from app import create_dash_app
dash_app = create_dash_app()
app = dash_app.server        # ← this is the WSGI callable
```

---

## Identity in Dash callbacks

```python
from app.flask_oidc_identity import get_current_user

@callback(Output("out", "children"), Input("btn", "n_clicks"))
def my_callback(n):
    user = get_current_user()          # safe inside any callback
    return f"Hello {user.name}"
```

`get_current_user()` reads the Flask request context that Dash maintains
for every `/_dash-update-component` POST, so it works the same as in any
plain Flask route.

---

## Identity at page load (before any callback)

```python
# app/__init__.py
def serve_layout():
    user = get_current_user()          # called once per page load
    return build_layout(user.display_name(), user.email, user.sub)

app.layout = serve_layout              # callable → fresh call per request
```

Assigning a **callable** to `app.layout` is the standard Dash pattern for
per-user layouts.  The callable runs inside a Flask request context, so
the OIDC headers are already available.

---

## Callback state machine

All calculator state lives in a `dcc.Store` component and is passed as
`State` to a single pattern-match callback that handles every button.
Keyboard input is routed through a clientside callback → hidden `dcc.Input`
→ server callback, keeping keyboard and mouse behaviour identical.
