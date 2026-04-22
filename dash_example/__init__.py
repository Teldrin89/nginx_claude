"""app/__init__.py

Dash application factory.

Key integration points with lua-resty-openidc / Entra ID
──────────────────────────────────────────────────────────
1.  before_request guard on the Flask server
    Dash uses an internal Flask app (dash_app.server).  We attach a
    before_request hook that aborts unauthenticated requests with 401.
    nginx will never let such a request through in production, but the
    guard protects the app if nginx is misconfigured or bypassed.

2.  index_string override
    Dash renders a full HTML shell around the React bundle.  We hook
    into _read_request_user() inside the index_string to stamp the
    authenticated user's name and sub into the page at first load,
    before any callback fires.  This is the only way to get server-side
    identity into the initial HTML without a separate REST call.

3.  /api/whoami route on the Flask server
    A plain Flask route (not a Dash callback) that returns the current
    identity as JSON — useful for debugging and for custom JS.
"""
import os

import dash
from dash import html
from flask import request, abort, jsonify, redirect

from .flask_oidc_identity import get_current_user, OIDCUser


# ── Dash app factory ─────────────────────────────────────────────────────────

def create_dash_app() -> dash.Dash:
    """Create and configure the Dash application."""

    app = dash.Dash(
        __name__,
        # assets_folder is relative to this file; Dash auto-serves assets/
        assets_folder="../assets",
        # suppress_callback_exceptions allows pattern-matching callbacks
        suppress_callback_exceptions=True,
        # meta_tags for viewport
        meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}],
        title="ARITHMOS",
    )

    # ── Auth gate on the underlying Flask server ──────────────────────────────
    _attach_auth_guard(app)

    # ── Extra Flask routes (whoami, health, logout stub) ──────────────────────
    _attach_flask_routes(app)

    # ── Layout (built lazily so each request gets the right identity) ─────────
    _attach_layout(app)

    # ── Register all callbacks ────────────────────────────────────────────────
    from . import callbacks  # noqa: F401  — importing registers @callback decorators

    return app


# ── Auth guard ────────────────────────────────────────────────────────────────

def _attach_auth_guard(app: dash.Dash) -> None:
    """
    Abort 401 for any request that lacks a valid OIDC identity.

    In production nginx never lets unauthenticated traffic through;
    this is a defence-in-depth measure.
    """
    server = app.server  # the underlying Flask app

    # Paths that must remain open (Dash/_dash-* internals + health probe)
    _OPEN_PREFIXES = ("/health", "/_dash-component-suites", "/_dash-layout",
                      "/assets")
    # Note: /_dash-update-component (callbacks) IS protected — they run
    # inside a request context that already carries the OIDC headers.

    @server.before_request
    def require_oidc():
        # Let open paths through
        for prefix in _OPEN_PREFIXES:
            if request.path.startswith(prefix):
                return

        user = get_current_user()
        if not user.is_authenticated:
            # In production this should never fire; return a JSON error
            # so Dash's XHR callbacks get something parseable.
            if request.headers.get("X-Requested-With") == "XMLHttpRequest" or \
               request.content_type == "application/json":
                return jsonify({"error": "Not authenticated"}), 401
            abort(401)


# ── Extra Flask routes ────────────────────────────────────────────────────────

def _attach_flask_routes(app: dash.Dash) -> None:
    server = app.server

    @server.route("/health")
    def health():
        return "ok", 200

    @server.route("/api/whoami")
    def whoami():
        user = get_current_user()
        if not user.is_authenticated:
            return jsonify({"error": "Not authenticated"}), 401
        return jsonify(user.to_dict())

    # In production /oidc/logout is handled entirely by nginx lua.
    # This stub is only reached in local dev (via dev_server.py).
    @server.route("/oidc/logout")
    def dev_logout():
        return (
            "<html><body style='font-family:monospace;background:#0d1a1c;"
            "color:#f2ead8;display:flex;align-items:center;justify-content:"
            "center;height:100vh;margin:0'>"
            "<div><p style='color:#c8973a;letter-spacing:.2em'>SIGNED OUT</p>"
            "<p style='margin-top:12px;font-size:12px'>(dev mock) "
            "<a href='/' style='color:#1a7a80'>return</a></p></div></body></html>",
            200,
        )


# ── Layout injection ──────────────────────────────────────────────────────────

def _attach_layout(app: dash.Dash) -> None:
    """
    Dash layout can be a callable — it is called fresh for every page load,
    within a Flask request context.  This lets us read the authenticated
    user and inject identity into the initial render without a callback round-trip.
    """
    from .layout import build_layout

    def serve_layout():
        try:
            user: OIDCUser = get_current_user()
            name  = user.display_name()
            email = user.email
            sub   = user.sub or "00000000"
        except RuntimeError:
            # No request context (e.g. Dash building the layout spec at import time)
            name  = "—"
            email = ""
            sub   = "00000000"

        return build_layout(name, email, sub)

    app.layout = serve_layout
