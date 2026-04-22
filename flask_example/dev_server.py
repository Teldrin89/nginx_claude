"""dev_server.py

Local development entry point — no nginx or Entra ID required.

Wraps every request with fake X-Auth-* headers so flask_oidc_identity
behaves as if nginx already authenticated the user.

Run with:
    python dev_server.py
"""
import os
from app import create_app

# ── Fake identity injected into every request ──────────────────────────────
DEV_USER = {
    "X-Auth-Sub":   "00000000-0000-0000-0000-000000000001",
    "X-Auth-User":  os.getenv("DEV_USERNAME",  "dev.user@example.com"),
    "X-Auth-Email": os.getenv("DEV_EMAIL",     "dev.user@example.com"),
    "X-Auth-Name":  os.getenv("DEV_NAME",      "Dev User"),
    "X-Auth-Roles": os.getenv("DEV_ROLES",     "User,Admin"),
    "X-Auth-Groups": "",
}


def create_dev_app():
    app = create_app()

    @app.before_request
    def inject_dev_headers():
        """Inject fake headers before each request so the app behaves as
        if nginx already authenticated the user."""
        from flask import request
        for key, value in DEV_USER.items():
            # Werkzeug stores headers as environ entries prefixed with
            # HTTP_ and uppercased with dashes replaced by underscores.
            environ_key = "HTTP_" + key.upper().replace("-", "_")
            request.environ[environ_key] = value

    # Mock /oidc/logout for local dev
    @app.route("/oidc/logout")
    def dev_logout():
        return "<p>Logged out (dev mock). <a href='/'>Back</a></p>"

    return app


if __name__ == "__main__":
    dev_app = create_dev_app()
    print("\n  ┌─────────────────────────────────────────────┐")
    print("  │  DEV MODE — OIDC headers are mocked         │")
    print(f"  │  User : {DEV_USER['X-Auth-Name']:<36}│")
    print(f"  │  Email: {DEV_USER['X-Auth-Email']:<36}│")
    print("  │  http://localhost:5000                       │")
    print("  └─────────────────────────────────────────────┘\n")
    dev_app.run(debug=True, port=5000)
