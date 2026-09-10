state = {"LAST_RUN": None}
CERT_TYPES = ["Automatic", "Manual"]

# Certs provisioned through the ACME front-end. Not selectable in the normal
# add/edit cert GUI (kept out of CERT_TYPES) - only ever set by the ACME
# account admin panel / ACME order-finalize bridge. Excluded from automatic
# renewal since the ACME client (e.g. certbot) drives its own renewal.
ACME_CERT_TYPE = "ACME"
