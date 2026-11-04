state = {"LAST_RUN": None}

CERT_TYPES = ["Automatic", "Manual"]

# Certs provisioned through the ACME front-end. Not selectable in the normal
# add/edit cert GUI (kept out of CERT_TYPES) - only ever set by the ACME
# account admin panel / ACME order-finalize bridge. Excluded from automatic
# renewal since the ACME client (e.g. certbot) drives its own renewal.
ACME_CERT_TYPE = "ACME"

# Maps an application role to the set of backing Shibboleth `memberOf`
# groups that grant it. A role is granted if ANY of its groups is present
# (logical OR), so this mirrors the Apache-side `Require shib-attr memberOf`
# lines one-to-one. Roles are additive: a user's effective roles are the
# union of every role whose group set intersects their memberOf list
# (see sucm_roles.py).
ROLE_GROUPS = {
    "cert_manager": {"it-staff"},
    # Deliberately it-produktion-infra-imdb ONLY: the ACME account admin
    # panel excludes it-staff by design, matching the Apache block. Do not
    # add other groups here without also changing the access boundary.
    "acme_admin": {"it-produktion-infra-imdb"},
    # Both groups may request an ACME account, matching the two `Require
    # shib-attr memberOf` lines in the /acme-accounts/(request|created)
    # Apache block. "su-lokal-it-ansvarig" (local IT managers) is the real
    # "org but not it-staff" requester group; keep this in lockstep with the
    # Apache-side block in su-salt-states-services-cert's sucm-apache.conf.
    "acme_requester": {"su-lokal-it-ansvarig", "it-staff"},
}
