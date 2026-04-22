"""wsgi.py — Gunicorn entry point.

Dash wraps its own Flask server internally.
We expose that server as `app` so Gunicorn can bind to it.
"""
from app import create_dash_app

# Dash exposes the underlying Flask server via .server
dash_app = create_dash_app()
app = dash_app.server          # ← this is what Gunicorn binds to
