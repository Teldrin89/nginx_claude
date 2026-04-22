# flask_oidc_identity.py
#
# Drop this file into your Flask project.
# It provides a lightweight `current_user` proxy that reads the trusted
# identity headers injected by nginx / lua-resty-openidc.
#
# Usage:
#   from flask_oidc_identity import current_user, require_auth
#
#   @app.route("/api/me")
#   @require_auth
#   def me():
#       return jsonify(current_user.__dict__)

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import List, Optional

from flask import request, abort, g


# ---------------------------------------------------------------------------
# Identity dataclass
# ---------------------------------------------------------------------------

@dataclass
class OIDCUser:
    """Parsed identity forwarded by nginx lua-resty-openidc headers."""

    sub: str                        # Immutable Entra ID object ID (oid claim)
    username: str                   # preferred_username / UPN
    email: str
    name: str
    roles: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    access_token: Optional[str] = None

    @property
    def is_authenticated(self) -> bool:
        return bool(self.sub)


# ---------------------------------------------------------------------------
# Flask `g`-backed proxy
# ---------------------------------------------------------------------------

def _load_user() -> OIDCUser:
    """Parse nginx-injected headers into an OIDCUser, cache on `g`."""
    if "oidc_user" not in g:
        h = request.headers

        # nginx strips/clears these if not set by lua — safe to trust
        sub      = h.get("X-Auth-Sub", "")
        username = h.get("X-Auth-User", "")
        email    = h.get("X-Auth-Email", "")
        name     = h.get("X-Auth-Name", "")

        raw_roles  = h.get("X-Auth-Roles",  "")
        raw_groups = h.get("X-Auth-Groups", "")
        token      = h.get("X-Access-Token")

        roles  = [r.strip() for r in raw_roles.split(",")  if r.strip()] if raw_roles  else []
        groups = [g_.strip() for g_ in raw_groups.split(",") if g_.strip()] if raw_groups else []

        g.oidc_user = OIDCUser(
            sub=sub,
            username=username,
            email=email,
            name=name,
            roles=roles,
            groups=groups,
            access_token=token,
        )

    return g.oidc_user


class _CurrentUserProxy:
    """Proxy that delegates attribute access to the per-request OIDCUser."""

    def __getattr__(self, name):
        return getattr(_load_user(), name)

    def __repr__(self):
        return repr(_load_user())


#: Use like `current_user.email`, `current_user.roles`, etc.
current_user: OIDCUser = _CurrentUserProxy()  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_auth(f):
    """Abort 401 if the request carries no OIDC identity (X-Auth-Sub empty)."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not _load_user().is_authenticated:
            abort(401)
        return f(*args, **kwargs)
    return decorated


def require_role(*required_roles: str):
    """Abort 403 if the user does not have at least one of the required roles."""
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


def require_group(*required_groups: str):
    """Abort 403 if the user does not belong to at least one of the required groups."""
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            user = _load_user()
            if not user.is_authenticated:
                abort(401)
            if not any(gr in user.groups for gr in required_groups):
                abort(403)
            return f(*args, **kwargs)
        return decorated
    return decorator
