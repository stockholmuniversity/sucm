"""
Role-based dynamic views: parses the Shibboleth `X-Remote-MemberOf` header
into an application role set, and provides a decorator to enforce roles
in-app (defense-in-depth on top of Apache's Shibboleth-level gating).

See TODO-role-based-views.md for the full design.
"""

from functools import wraps

from flask import abort, session

from .sucm_globals import ROLE_GROUPS
from .sucm_settings import app_logger

# NOTE: mod_shib's documented default delimiter for multi-valued headers is
# ";" but this has NOT been empirically confirmed against a real multi-group
# request/log for this deployment (attribute-map.xml/shibboleth2.xml were
# not found in any locally-cloned salt-states repo - see Step 0 in
# TODO-role-based-views.md). Confirm before relying on this in production.
MEMBEROF_DELIMITER = ";"


def parse_member_of(raw_header):
    """Split the raw X-Remote-MemberOf header into a clean list of group names."""
    if not raw_header:
        return []
    return [g.strip() for g in raw_header.split(MEMBEROF_DELIMITER) if g.strip()]


def roles_for_groups(groups):
    """
    Additive role resolution: union of every role whose backing group set
    intersects the user's memberOf groups. Each role maps to a set of groups
    (logical OR - any one match grants the role), so the mapping mirrors the
    Apache-side `Require shib-attr memberOf` lines directly.
    """
    group_set = set(groups)
    return {
        role
        for role, backing_groups in ROLE_GROUPS.items()
        if group_set & backing_groups
    }


def require_role(*allowed_roles):
    """Route decorator: 403s if the current session has none of the allowed roles.

    This is defense-in-depth on top of Apache - Apache is still the primary
    gate, but every route should also assert its own requirement in-app so
    that (a) the UI can reason about roles consistently with routing, and
    (b) a future Apache config mistake doesn't silently grant broader access
    than intended.
    """

    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            have = set(session.get("roles", []))
            if not have & set(allowed_roles):
                # Log the resolved-vs-required roles so a 403 is
                # self-diagnosing (e.g. a memberOf parse mismatch).
                app_logger.warning(
                    "AUTH-DEBUG 403 user=%s required=%s resolved=%s",
                    session.get("username"),
                    sorted(allowed_roles),
                    sorted(have),
                )
                abort(403)
            return view_func(*args, **kwargs)

        return wrapped

    return decorator
