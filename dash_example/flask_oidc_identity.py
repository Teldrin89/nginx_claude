"""app/flask_oidc_identity.py

Reads the trusted X-Auth-* headers that nginx / lua-resty-openidc injects
after a successful Entra ID authentication.

Works identically in plain Flask and inside Dash's internal Flask server
because Dash callbacks ultimately run within a Flask request context.
"""
from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import List, Optional

from flask import request, abort, g


@dataclass
class OIDCUser:
    sub: str
    username: str
    email: str
    name: str
    roles: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    access_token: Optional[str] = None

    @property
    def is_authenticated(self) -> bool:
        return bool(self.sub)

    def display_name(self) -> str:
        return self.name or self.username or "Unknown"

    def to_dict(self) -> dict:
        return {
            "sub": self.sub,
            "username": self.username,
            "email": self.email,
            "name": self.name,
            "roles": self.roles,
            "groups": self.groups,
        }


def _load_user() -> OIDCUser:
    """Parse nginx-injected headers into an OIDCUser; cached on Flask `g`."""
    if "oidc_user" not in g:
        h = request.headers
        raw_roles  = h.get("X-Auth-Roles",  "")
        raw_groups = h.get("X-Auth-Groups", "")
        g.oidc_user = OIDCUser(
            sub=h.get("X-Auth-Sub", ""),
            username=h.get("X-Auth-User", "anonymous"),
            email=h.get("X-Auth-Email", ""),
            name=h.get("X-Auth-Name", ""),
            roles=[r.strip() for r in raw_roles.split(",")  if r.strip()],
            groups=[g_.strip() for g_ in raw_groups.split(",") if g_.strip()],
            access_token=h.get("X-Access-Token"),
        )
    return g.oidc_user


class _CurrentUserProxy:
    """Per-request proxy — safe to use as a module-level singleton."""
    def __getattr__(self, name):
        return getattr(_load_user(), name)
    def __repr__(self):
        return repr(_load_user())


#: Use like: current_user.email, current_user.name, current_user.roles
current_user: OIDCUser = _CurrentUserProxy()  # type: ignore[assignment]


def get_current_user() -> OIDCUser:
    """Explicit getter — preferred inside Dash callbacks."""
    return _load_user()


def require_auth(f):
    """Decorator: abort 401 when the OIDC sub claim is absent."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not _load_user().is_authenticated:
            abort(401)
        return f(*args, **kwargs)
    return decorated


def require_role(*required_roles: str):
    """Decorator: abort 403 when the user lacks all of the required roles."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = _load_user()
            if not user.is_authenticated:
                abort(401)
            if not any(r in user.roles for r in required_roles):
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator
