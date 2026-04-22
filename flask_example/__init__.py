"""app/__init__.py — Flask application factory."""
from flask import Flask


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "dev-only-change-in-production"  # only needed for flash/session

    from .routes import bp
    app.register_blueprint(bp)

    return app
