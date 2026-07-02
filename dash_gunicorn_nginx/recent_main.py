"""
Dummy Dash application demonstrating OIDC authentication/authorization
against Mock Entra ID.

Architecture:
  - The OIDC flow (/login, /callback, /logout) is implemented as plain
    Flask routes on the underlying server Dash wraps (`app.server`).
  - Dash itself serves the UI as a single-page app at "/" and friends,
    with page content driven by dcc.Location + callbacks (Dash's
    standard multi-page pattern).
  - Every Dash page render checks the Flask session (via flask.session)
    for a valid identity before rendering protected content — this is
    the same Flask session used by the OIDC routes.

Flow:
  1. User hits "/" -> layout checks flask.session for "user"
  2. If absent, page shows a "Sign in" link -> /login
  3. /login redirects to Mock Entra ID with PKCE
  4. Mock Entra ID redirects back to /callback?code=...
  5. /callback exchanges the code, verifies the id_token via JWKS,
     stores claims in flask.session, redirects to /dashboard
  6. Dash callbacks read flask.session on every page navigation
"""

import base64
from datetime import timedelta
import hashlib
import json
import logging
import os
import secrets
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request

import jwt
from jwt import PyJWKClient
from flask import Flask, redirect, request, session, jsonify

from dash import Dash, dcc, html, Input, Output
import dash_bootstrap_components as dbc

# ──────────────────────────────────────────────────────────────
# Logging — goes to stdout → journald when running as a service
# ──────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("dash-app")

# ──────────────────────────────────────────────────────────────
# Configuration — all from environment, with dev-friendly defaults
#
# Two base URLs are needed because this app makes both browser-facing
# redirects and server-side back-channel HTTP calls to the IdP:
#
#   OIDC_BASE_URL          — what the BROWSER uses (authorize redirect,
#                            logout redirect). Typically localhost:3000
#                            or the public hostname.
#
#   OIDC_INTERNAL_BASE_URL — what THIS SERVER uses for back-channel calls
#                            (token exchange, JWKS fetch). Must be
#                            reachable from the Gunicorn process.
#                            Defaults to OIDC_BASE_URL when not set,
#                            which works when both run on the same machine.
#                            Set this explicitly when they differ:
#                              systemd:  OIDC_INTERNAL_BASE_URL=http://127.0.0.1:3000
#                              Docker:   OIDC_INTERNAL_BASE_URL=http://mock-entra:3000
# ──────────────────────────────────────────────────────────────
OIDC_BASE_URL      = os.environ.get("OIDC_BASE_URL",      "http://localhost:3000")
OIDC_TENANT_ID     = os.environ.get("OIDC_TENANT_ID",     "mock-tenant-id")
OIDC_CLIENT_ID     = os.environ.get("OIDC_CLIENT_ID",     "my-dev-app")
OIDC_CLIENT_SECRET = os.environ.get("OIDC_CLIENT_SECRET", "dev-secret-change-me")
OIDC_REDIRECT_URI  = os.environ.get("OIDC_REDIRECT_URI",  "http://127.0.0.1:8080/callback")
OIDC_SCOPE         = os.environ.get("OIDC_SCOPE",         "openid profile email offline_access")
OIDC_POST_LOGOUT_REDIRECT = os.environ.get("OIDC_POST_LOGOUT_REDIRECT", "http://127.0.0.1:8080/")

# Internal base URL for server-side back-channel calls.
# Falls back to OIDC_BASE_URL when not set.
_INTERNAL = os.environ.get("OIDC_INTERNAL_BASE_URL", OIDC_BASE_URL)
# _INTERNAL = os.environ.get("OIDC_INTERNAL_BASE_URL", "http://127.0.0.1:3000")

# Browser-facing URLs (embedded in redirects the browser follows)
OIDC_AUTHORIZE_URL = f"{OIDC_BASE_URL}/{OIDC_TENANT_ID}/oauth2/v2.0/authorize"
OIDC_LOGOUT_URL    = f"{OIDC_BASE_URL}/{OIDC_TENANT_ID}/oauth2/v2.0/logout"

# Server-side URLs (used by Gunicorn — never seen by the browser)
OIDC_TOKEN_URL = f"{_INTERNAL}/{OIDC_TENANT_ID}/oauth2/v2.0/token"
OIDC_JWKS_URL  = f"{_INTERNAL}/{OIDC_TENANT_ID}/discovery/v2.0/keys"

# Issuer must match what Mock Entra ID stamps in the token (its own BASE_URL)
OIDC_ISSUER = f"{OIDC_BASE_URL}/{OIDC_TENANT_ID}/v2.0"

# ──────────────────────────────────────────────────────────────
# Flask server (Dash wraps this) — auth routes live here
# ──────────────────────────────────────────────────────────────
server = Flask(__name__)

# ── FLASK_SECRET_KEY must be identical across all Gunicorn workers. ──────────
# Never let it default to a random value — each worker would generate a
# different key, sign session cookies independently, and reject each other's
# cookies, causing state_mismatch / missing PKCE verifier on /callback.
# _secret = os.environ.get("FLASK_SECRET_KEY")
_secret = "3d398c8ed6683e24ef88853bd845f6181db79f83b193dd71ab6a1c90778c7787"
if not _secret:
    raise RuntimeError(
        "FLASK_SECRET_KEY environment variable is not set. "
        "Generate one with: python3 -c \"import secrets; print(secrets.token_hex(32))\" "
        "and add it to your .env file. It must be the same value across all "
        "Gunicorn workers and survive service restarts."
    )
server.secret_key = _secret

# server.config.update(
#     SESSION_COOKIE_HTTPONLY=True,
#     SESSION_COOKIE_SAMESITE="Lax",
#     # SESSION_COOKIE_SECURE=True,  # enable behind HTTPS
# )

server.config.update(
    SESSION_COOKIE_NAME="dash_session",   # explicit name, never conflicts
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_PATH="/",
    # SESSION_COOKIE_SECURE=True,  # uncomment when running behind HTTPS
)

_jwks_client = PyJWKClient(OIDC_JWKS_URL)


# ──────────────────────────────────────────────────────────────
# PKCE + token helpers
# ──────────────────────────────────────────────────────────────
def generate_pkce_pair():
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def verify_id_token(id_token: str) -> dict:
    unverified_header = jwt.get_unverified_header(id_token)
    # signing_key = _jwks_client.get_signing_key_from_jwt(id_token)
    signing_key = _jwks_client.get_signing_key(unverified_header["kid"])
    log.info("Unverified header: %s", unverified_header)
    log.info("Sigining key: %s", signing_key.key)
    return jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=OIDC_CLIENT_ID,
        issuer=OIDC_ISSUER,
        options={"require": ["exp", "iat", "sub"]},
        leeway=timedelta(seconds=10),
    )


def exchange_code_for_tokens(code: str, code_verifier: str) -> dict:
    """
    POST to the token endpoint and return the parsed JSON response.
    Raises RuntimeError with the IdP's error body on 4xx/5xx so callers
    can log and surface the actual reason instead of a generic failure.
    """
    data = urllib.parse.urlencode({
        "grant_type":    "authorization_code",
        "client_id":     OIDC_CLIENT_ID,
        "client_secret": OIDC_CLIENT_SECRET,
        "redirect_uri":  OIDC_REDIRECT_URI,
        "code":          code,
        "code_verifier": code_verifier,
    }).encode()

    req = urllib.request.Request(
        OIDC_TOKEN_URL, data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        # Read the error body — this is the JSON from Mock Entra ID
        # (e.g. {"error":"invalid_grant","error_description":"..."})
        try:
            body = exc.read().decode()
        except Exception:
            body = "<unreadable>"
        raise RuntimeError(
            f"Token endpoint returned HTTP {exc.code}: {body}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"Could not reach token endpoint {OIDC_TOKEN_URL}: {exc.reason}"
        ) from exc


def current_user():
    """Returns the session user dict, or None if not authenticated / expired."""
    user = session.get("user")
    if not user:
        return None
    if session.get("expires_at", 0) < time.time():
        log.info("Session expired for %s", user.get("email"))
        session.clear()
        return None
    return user


def has_role(*roles):
    user = current_user()
    if not user:
        return False
    return bool(set(user.get("roles", [])).intersection(roles))


# ──────────────────────────────────────────────────────────────
# Flask routes — the OIDC dance + protected JSON API
# ──────────────────────────────────────────────────────────────
@server.route("/login")
def login():
    verifier, challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)

    session["pkce_verifier"] = verifier
    session["oauth_state"]   = state
    session["oauth_nonce"]   = nonce
    session["post_login_redirect"] = request.args.get("next", "/dashboard")

    log.info("Login initiated — state=%s redirect_uri=%s", state, OIDC_REDIRECT_URI)

    params = {
        "client_id":             OIDC_CLIENT_ID,
        "redirect_uri":          OIDC_REDIRECT_URI,
        "response_type":         "code",
        "scope":                 OIDC_SCOPE,
        "state":                 state,
        "nonce":                 nonce,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"{OIDC_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}")


@server.route("/callback")
def callback():
    # ── IdP-level error (e.g. user cancelled) ─────────────────
    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", "")
        log.warning("IdP returned error at callback: %s — %s", error, desc)
        return redirect(f"/?auth_error={urllib.parse.quote(f'{error}: {desc}')}")

    code  = request.args.get("code")
    state = request.args.get("state")

    # ── State / CSRF check ────────────────────────────────────
    expected_state   = session.get("oauth_state")
    verifier         = session.get("pkce_verifier")
    expected_nonce   = session.get("oauth_nonce")

    log.info(
        "Callback received — code=%s state=%s expected_state=%s verifier_present=%s",
        bool(code), state, expected_state, bool(verifier),
    )

    if not code:
        log.error("Callback missing code parameter")
        return redirect("/?auth_error=missing_code")

    if state != expected_state:
        log.error("State mismatch — got %s expected %s (session keys: %s)",
                  state, expected_state, list(session.keys()))
        return redirect("/?auth_error=state_mismatch")

    if not verifier:
        log.error("PKCE verifier missing from session (session keys: %s)",
                  list(session.keys()))
        return redirect("/?auth_error=missing_pkce_verifier")

    # Consume the one-use session values
    session.pop("pkce_verifier", None)
    session.pop("oauth_nonce",   None)
    session.pop("oauth_state",   None)

    # ── Token exchange ────────────────────────────────────────
    try:
        tokens = exchange_code_for_tokens(code, verifier)
        log.info("Token exchange succeeded — scopes: %s", tokens.get("scope"))
    except RuntimeError as exc:
        log.error("Token exchange failed: %s", exc)
        return redirect(f"/?auth_error={urllib.parse.quote(str(exc))}")
    except Exception as exc:
        log.error("Unexpected error during token exchange: %s\n%s",
                  exc, traceback.format_exc())
        return redirect(f"/?auth_error={urllib.parse.quote(f'token_exchange_error: {exc}')}")

    # ── ID token verification ─────────────────────────────────
    id_token = tokens.get("id_token")
    if not id_token:
        log.error("No id_token in token response: %s", list(tokens.keys()))
        return redirect("/?auth_error=no_id_token")

    try:
        claims = verify_id_token(id_token)
        log.info("ID token verified for sub=%s email=%s",
                 claims.get("sub"), claims.get("email"))
    except Exception as exc:
        log.error("ID token verification failed: %s\n%s", exc, traceback.format_exc())
        return redirect(f"/?auth_error={urllib.parse.quote(f'invalid_id_token: {exc}')}")

    # ── Nonce check (replay protection) ──────────────────────
    if claims.get("nonce") != expected_nonce:
        log.error("Nonce mismatch — token nonce=%s expected=%s",
                  claims.get("nonce"), expected_nonce)
        return redirect("/?auth_error=nonce_mismatch")

    # ── Store identity in session ─────────────────────────────
    session["user"] = {
        "sub":                claims.get("sub"),
        "name":               claims.get("name"),
        "email":              claims.get("email"),
        "preferred_username": claims.get("preferred_username"),
        "roles":              claims.get("roles", []),
        "groups":             claims.get("groups", []),
        "tid":                claims.get("tid"),
    }
    session["access_token"]  = tokens.get("access_token")
    session["refresh_token"] = tokens.get("refresh_token")
    session["expires_at"]    = time.time() + tokens.get("expires_in", 3600)

    dest = session.pop("post_login_redirect", "/dashboard")
    log.info("Login complete for %s — redirecting to %s", claims.get("email"), dest)
    return redirect(dest)


@server.route("/logout")
def logout():
    user = current_user()
    log.info("Logout for %s", user.get("email") if user else "anonymous")
    session.clear()
    params = urllib.parse.urlencode({"post_logout_redirect_uri": OIDC_POST_LOGOUT_REDIRECT})
    return redirect(f"{OIDC_LOGOUT_URL}?{params}")


# ── Debug endpoint — shows what's in the session right now ───
@server.route("/debug/session")
def debug_session():
    """
    Dumps non-sensitive session keys to help diagnose auth issues.
    Remove or gate behind a flag before exposing to a real network.
    """
    safe = {
        "keys":          list(session.keys()),
        "has_user":      "user" in session,
        "has_verifier":  "pkce_verifier" in session,
        "has_state":     "oauth_state" in session,
        "has_nonce":     "oauth_nonce" in session,
        "expires_at":    session.get("expires_at"),
        "user_email":    session.get("user", {}).get("email"),
        "user_roles":    session.get("user", {}).get("roles"),
    }
    return jsonify(safe)


@server.route("/api/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(user)


@server.route("/api/whoami")
def api_whoami():
    """Bearer-token auth for API clients (no session)."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing_bearer_token"}), 401
    token = auth_header.removeprefix("Bearer ")
    try:
        claims = verify_id_token(token)
    except Exception as exc:
        log.warning("Bearer token verification failed: %s", exc)
        return jsonify({"error": "invalid_token", "detail": str(exc)}), 401
    return jsonify({
        "sub":                claims.get("sub"),
        "preferred_username": claims.get("preferred_username"),
        "roles":              claims.get("roles", []),
    })


@server.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


# ──────────────────────────────────────────────────────────────
# Dash app — wraps the Flask server above
# ──────────────────────────────────────────────────────────────
app = Dash(
    __name__,
    server=server,
    external_stylesheets=[dbc.themes.BOOTSTRAP],
    suppress_callback_exceptions=True,
    title="Dummy Dash App",
)

MS_LOGO = html.Div(
    [
        html.Div(className="ms-squares", children=[
            html.Div(className="sq1"), html.Div(className="sq2"),
            html.Div(className="sq3"), html.Div(className="sq4"),
        ]),
        html.Span("Dummy App", style={"fontWeight": 600, "fontSize": "16px", "marginLeft": "10px"}),
    ],
    style={"display": "flex", "alignItems": "center"},
)


def navbar(user):
    links = [dbc.NavLink("Home", href="/", active="exact")]
    if user:
        links += [
            dbc.NavLink("Dashboard", href="/dashboard", active="exact"),
            dbc.NavLink("Profile",   href="/profile",   active="exact"),
        ]
        if "Admin" in user.get("roles", []):
            links.append(dbc.NavLink("Admin", href="/admin", active="exact"))

    right = (
        html.Div(
            [
                html.Div(
                    (user["name"][:2].upper() if user.get("name") else "??"),
                    className="avatar",
                ),
                html.Span(user.get("name", ""), style={"marginLeft": "8px", "marginRight": "12px"}),
                dbc.Button("Sign out", href="/logout", external_link=True, color="light", size="sm"),
            ],
            style={"display": "flex", "alignItems": "center"},
        )
        if user
        else dbc.Button("Sign in", href="/login", external_link=True, color="primary", size="sm")
    )

    return dbc.Navbar(
        dbc.Container(
            [
                dbc.NavbarBrand(MS_LOGO, href="/"),
                dbc.Nav(links, navbar=True, className="me-auto", style={"marginLeft": "24px"}),
                right,
            ],
            fluid=True,
        ),
        color="white",
        className="border-bottom",
        style={"height": "56px"},
    )


def claims_table(user):
    rows = [
        ("sub",                user.get("sub")),
        ("name",               user.get("name")),
        ("email",              user.get("email")),
        ("preferred_username", user.get("preferred_username")),
        ("tenant (tid)",       user.get("tid")),
    ]
    body = [html.Tr([html.Td(k), html.Td(v)]) for k, v in rows]
    body.append(html.Tr([
        html.Td("roles"),
        html.Td([dbc.Badge(r, color="info",      className="me-1") for r in user.get("roles",  [])]),
    ]))
    body.append(html.Tr([
        html.Td("groups"),
        html.Td([dbc.Badge(g, color="secondary", className="me-1") for g in user.get("groups", [])]),
    ]))
    return dbc.Table([html.Tbody(body)], bordered=False, hover=True, size="sm")


def card(*children, **kwargs):
    return dbc.Card(dbc.CardBody(list(children)), className="mb-4 shadow-sm", **kwargs)


# ── Page layouts ─────────────────────────────────────────────
def page_home(user, auth_error=None):
    content = []
    if auth_error:
        content.append(dbc.Alert(
            [html.Strong("Authentication error: "), auth_error],
            color="danger", className="mb-3",
        ))

    if user:
        content += [
            html.P(["Signed in as ", html.Strong(user.get("name")), f" ({user.get('email')})"]),
            html.Div([dbc.Badge(r, color="info", className="me-1") for r in user.get("roles", [])],
                     className="mb-3"),
            dbc.Button("Go to Dashboard →", href="/dashboard", color="primary"),
        ]
    else:
        content += [
            html.P("You are not signed in."),
            dbc.Button("Sign in with Mock Entra ID", href="/login", external_link=True, color="primary"),
        ]

    return html.Div([
        card(
            html.H2("Dummy Dash App"),
            html.P("Authentication & authorization powered by Mock Entra ID",
                   className="text-muted mb-3"),
            *content,
        ),
        card(
            html.H4("What this demonstrates"),
            dbc.Table([html.Tbody([
                html.Tr([html.Td("Authorization Code + PKCE (S256)"), html.Td("OAuth2 flow against Mock Entra ID")]),
                html.Tr([html.Td("ID token verification"),            html.Td("RS256 signature checked via JWKS endpoint")]),
                html.Tr([html.Td("Session-based auth"),               html.Td("Flask session shared with Dash callbacks")]),
                html.Tr([html.Td("Role-based access control"),        html.Td("Admin page requires the Admin role")]),
                html.Tr([html.Td("Bearer token API auth"),            html.Td(html.Code("/api/whoami"))]),
            ])], bordered=False, size="sm"),
        ),
    ])


def page_dashboard(user):
    return html.Div([
        card(
            html.H2("Dashboard"),
            html.P("Protected page — requires a valid session", className="text-muted mb-3"),
            claims_table(user),
        ),
        card(
            html.H4("Try the protected API"),
            html.P("This calls /api/me using your session cookie:"),
            html.Pre(id="api-result", children="Click the button below…",
                     style={"background": "#f3f2f1", "padding": "12px",
                            "borderRadius": "4px", "fontSize": "13px"}),
            dbc.Button("GET /api/me", id="call-api-btn", color="primary", className="mt-2"),
        ),
    ])


def page_profile(user):
    return card(
        html.H2("Profile"),
        html.P("Your identity as provided by Mock Entra ID", className="text-muted mb-3"),
        html.Div([
            html.Div(
                (user["name"][:2].upper() if user.get("name") else "??"),
                className="avatar",
                style={"width": "56px", "height": "56px", "fontSize": "20px"},
            ),
            html.Div([
                html.P(user.get("name"),  style={"fontSize": "18px", "fontWeight": 600, "margin": 0}),
                html.P(user.get("email"), className="text-muted", style={"fontSize": "13px", "margin": 0}),
            ], style={"marginLeft": "16px"}),
        ], style={"display": "flex", "alignItems": "center", "marginBottom": "20px"}),
        claims_table(user),
    )


def page_admin(user):
    return card(
        html.H2(["Admin Panel ", dbc.Badge("Admin role required", color="warning", className="ms-2")]),
        html.P([html.Code("@roles_required('Admin')"), " gate"], className="text-muted mb-3"),
        html.P("If you can see this, your roles claim from Mock Entra ID includes Admin."),
        html.Div([dbc.Badge(r, color="info", className="me-1") for r in user.get("roles", [])],
                 className="mt-2"),
    )


def page_forbidden():
    return dbc.Alert(
        ["You don't have the required role for this page. ", dcc.Link("Back to home", href="/")],
        color="danger",
    )


def page_login_required():
    return dbc.Alert(
        ["Please ", html.A("sign in", href="/login"), " to view this page."],
        color="warning",
    )


# ── App layout ───────────────────────────────────────────────
app.layout = html.Div([
    dcc.Location(id="url", refresh=False),
    html.Div(id="navbar-container"),
    dbc.Container(html.Div(id="page-content"), style={"maxWidth": "900px", "marginTop": "32px"}),
])


@app.callback(Output("navbar-container", "children"), Input("url", "pathname"))
def render_navbar(_pathname):
    return navbar(current_user())


@app.callback(Output("page-content", "children"), Input("url", "pathname"), Input("url", "search"))
def render_page(pathname, search):
    user = current_user()
    qs = urllib.parse.parse_qs((search or "").lstrip("?"))
    auth_error = qs.get("auth_error", [None])[0]

    if pathname in ("/", None):
        return page_home(user, auth_error)
    if pathname == "/dashboard":
        return page_dashboard(user) if user else page_login_required()
    if pathname == "/profile":
        return page_profile(user)  if user else page_login_required()
    if pathname == "/admin":
        if not user:
            return page_login_required()
        if "Admin" not in user.get("roles", []):
            return page_forbidden()
        return page_admin(user)

    return dbc.Alert("404 — page not found", color="secondary")


@app.callback(Output("api-result", "children"), Input("call-api-btn", "n_clicks"),
              prevent_initial_call=True)
def call_api(_n_clicks):
    user = current_user()
    if not user:
        return json.dumps({"error": "unauthorized"}, indent=2)
    return json.dumps(user, indent=2)


# ── Inline CSS ───────────────────────────────────────────────
app.index_string = """
<!DOCTYPE html>
<html>
<head>
{%metas%}
<title>{%title%}</title>
{%favicon%}
{%css%}
<style>
  body { background: #f3f2f1; font-family: 'Segoe UI', system-ui, sans-serif; }
  .ms-squares { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; width: 16px; height: 16px; }
  .sq1 { background: #f25022; } .sq2 { background: #7fba00; }
  .sq3 { background: #00a4ef; } .sq4 { background: #ffb900; }
  .avatar { width: 28px; height: 28px; border-radius: 50%; background: #0078d4; color: #fff;
            display: flex; align-items: center; justify-content: center;
            font-size: 11px; font-weight: 600; }
  .card { border: 1px solid #e1dfdd !important; }
</style>
</head>
<body>
{%app_entry%}
<footer>
{%config%}
{%scripts%}
{%renderer%}
</footer>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
