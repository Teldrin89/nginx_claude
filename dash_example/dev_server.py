"""dev_server.py

Local development entry point — no nginx or Entra ID required.

Attaches a before_request hook to Dash's internal Flask server that
injects fake X-Auth-* headers into every request's environ, so
flask_oidc_identity.get_current_user() works identically to production.

Run with:
    python dev_server.py

Override identity:
    DEV_NAME="Alice Smith" DEV_EMAIL="alice@corp.com" python dev_server.py
"""
import os
from app import create_dash_app

DEV_USER = {
    "X-Auth-Sub":    os.getenv("DEV_SUB",      "00000000-dead-beef-cafe-000000000001"),
    "X-Auth-User":   os.getenv("DEV_USERNAME", "dev.user@example.com"),
    "X-Auth-Email":  os.getenv("DEV_EMAIL",    "dev.user@example.com"),
    "X-Auth-Name":   os.getenv("DEV_NAME",     "Dev User"),
    "X-Auth-Roles":  os.getenv("DEV_ROLES",    "User,Admin"),
    "X-Auth-Groups": os.getenv("DEV_GROUPS",   ""),
}


def _environ_key(header: str) -> str:
    """Convert an HTTP header name to a WSGI environ key."""
    return "HTTP_" + header.upper().replace("-", "_")


if __name__ == "__main__":
    dash_app = create_dash_app()
    server   = dash_app.server  # underlying Flask app

    @server.before_request
    def inject_dev_identity():
        from flask import request
        for header, value in DEV_USER.items():
            request.environ.setdefault(_environ_key(header), value)

    print()
    print("  ┌──────────────────────────────────────────────────┐")
    print("  │  DEV MODE — Entra ID OIDC headers are mocked     │")
    print(f"  │  User  : {DEV_USER['X-Auth-Name']:<40}│")
    print(f"  │  Email : {DEV_USER['X-Auth-Email']:<40}│")
    print(f"  │  Roles : {DEV_USER['X-Auth-Roles']:<40}│")
    print("  │  http://localhost:8050                            │")
    print("  └──────────────────────────────────────────────────┘")
    print()

    dash_app.run(debug=True, port=8050)
