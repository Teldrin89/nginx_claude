"""app/flask_oidc_identity.py

Reads the trusted X-Auth-* headers that nginx / lua-resty-openidc
injects after a successful Entra ID authentication.

Usage:
    from app.flask_oidc_identity import current_user, require_auth
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
    def __getattr__(self, name):
        return getattr(_load_user(), name)
    def __repr__(self):
        return repr(_load_user())


current_user: OIDCUser = _CurrentUserProxy()  # type: ignore[assignment]


def require_auth(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not _load_user().is_authenticated:
            abort(401)
        return f(*args, **kwargs)
    return decorated


def require_role(*required_roles: str):
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
