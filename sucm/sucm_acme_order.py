"""
ACME order/authorization model (RFC 8555 sections 7.1.3/7.1.4/7.5) and the
bridge into SUCM's existing certificate-issuance pipeline.

Design note - "trust-based" issuance: this ACME server does not perform
real domain-control validation (no HTTP-01/DNS-01 challenge is ever
actually fetched from the client). Instead, at order-creation time every
requested identifier is checked against the account's admin-managed
domain allow-list (see SucmAcmeAccount.is_domain_allowed). If all
identifiers pass, the corresponding authorizations - and their single
challenge each - are created already in "valid" status, so RFC 8555
clients (certbot et al.) see nothing to solve and proceed straight to
"finalize". This was an explicit, accepted design decision for this
internal-only tool; it is not appropriate for anything facing untrusted
clients.
"""

import json
import secrets
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .sucm_acme_account import SucmAcmeAccount
from .sucm_certificate import SucmCertificate
from .sucm_common import sucm_db
from .sucm_globals import ACME_CERT_TYPE
from .sucm_settings import cfg, audit_logger

ORDER_TTL_DAYS = 7
AUTHZ_TTL_DAYS = 7

# POC-hardcoded ACME issuance settings (not user-selectable, unlike the
# manual "add cert" form - an ACME client has no UI to pick these). Move
# these into sucm_conf.ini's [ACME] section later if they need to vary
# per-environment.
ACME_CA_PLUGIN_NAME = "Harica_EAB"
ACME_SECRET_PATH = "SUCMTEST/test/ssl/"
ACME_NOTIFY_GROUP_ID = None


class SucmAcmeOrderError(Exception):
    """Raised for any order/finalize condition that should be surfaced to
    the ACME client as a problem document. `acme_type` is the short RFC
    8555 problem type suffix (e.g. "rejectedIdentifier")."""

    def __init__(self, message, acme_type="malformed", status_code=400):
        super().__init__(message)
        self.acme_type = acme_type
        self.status_code = status_code


class SucmAcmeOrder:
    @staticmethod
    def _order_row_to_dict(row):
        return {
            "order_id": row[0],
            "account_id": row[1],
            "status": row[2],
            "identifiers": json.loads(row[3]) if row[3] else [],
            "cert_id": row[4],
            "expires": row[5],
            "create_date": row[6],
            "error": row[7],
        }

    @staticmethod
    def _authz_row_to_dict(row):
        return {
            "authz_id": row[0],
            "order_id": row[1],
            "identifier_type": row[2],
            "identifier_value": row[3],
            "status": row[4],
            "challenge_token": row[5],
            "challenge_status": row[6],
            "expires": row[7],
        }

    def get_next_order_id(self):
        return sucm_db.get_next_available_id("AcmeOrder")

    def get_next_authz_id(self):
        return sucm_db.get_next_available_id("AcmeAuthorization")

    def get_orders_for_cert(self, cert_id):
        rows = sucm_db.execute_select_query(
            "SELECT * FROM AcmeOrder WHERE Cert_Id = %s", (cert_id,)
        )
        if not rows:
            return []
        return [self._order_row_to_dict(row) for row in rows]

    def get_order(self, order_id):
        rows = sucm_db.execute_select_query(
            "SELECT * FROM AcmeOrder WHERE Order_Id = %s", (order_id,)
        )
        if not rows:
            return {}
        return self._order_row_to_dict(rows[0])

    def get_authorization(self, authz_id):
        rows = sucm_db.execute_select_query(
            "SELECT * FROM AcmeAuthorization WHERE Authz_Id = %s", (authz_id,)
        )
        if not rows:
            return {}
        return self._authz_row_to_dict(rows[0])

    def get_authorizations_for_order(self, order_id):
        rows = sucm_db.execute_select_query(
            "SELECT * FROM AcmeAuthorization WHERE Order_Id = %s", (order_id,)
        )
        if not rows:
            return []
        return [self._authz_row_to_dict(row) for row in rows]

    def create_order(self, account_id, identifiers):
        """
        identifiers: list of {"type": "dns", "value": "..."} dicts, as
        received in the ACME newOrder payload.

        Raises SucmAcmeOrderError if any identifier is not "dns" or is not
        on the account's allow-list. Otherwise creates the order plus one
        pre-valid authorization (and one pre-valid challenge) per
        identifier, and returns the order dict.
        """
        if not identifiers:
            raise SucmAcmeOrderError("Order must contain at least one identifier")

        account_model = SucmAcmeAccount()
        for identifier in identifiers:
            if identifier.get("type") != "dns":
                raise SucmAcmeOrderError(
                    f"Unsupported identifier type: {identifier.get('type')}",
                    acme_type="unsupportedIdentifier",
                )
            value = identifier.get("value", "")
            if not account_model.is_domain_allowed(account_id, value):
                raise SucmAcmeOrderError(
                    f"{value} is not on this account's allowed domain list",
                    acme_type="rejectedIdentifier",
                    status_code=403,
                )

        order_id = self.get_next_order_id()
        expires = datetime.now() + timedelta(days=ORDER_TTL_DAYS)
        order_data = {
            "Order_Id": order_id,
            "Account_Id": account_id,
            "Status": "ready",
            "Identifiers": json.dumps(identifiers),
            "Expires": expires,
            "Create_Date": datetime.now(),
        }
        sucm_db.add_update_record("AcmeOrder", order_data)

        for identifier in identifiers:
            authz_id = self.get_next_authz_id()
            authz_data = {
                "Authz_Id": authz_id,
                "Order_Id": order_id,
                "Identifier_Type": identifier["type"],
                "Identifier_Value": identifier["value"],
                "Status": "valid",
                "Challenge_Token": secrets.token_urlsafe(24),
                "Challenge_Status": "valid",
                "Expires": expires,
            }
            sucm_db.add_update_record("AcmeAuthorization", authz_data)

        audit_logger.info(
            "ACME order %s created for account %s, identifiers: %s",
            order_id,
            account_id,
            ", ".join(i["value"] for i in identifiers),
        )
        return self.get_order(order_id)

    @staticmethod
    def _csr_identifiers(csr):
        """Extracts the CN and all dNSName SANs from a parsed CSR."""
        names = set()
        cn_attrs = csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        common_name = cn_attrs[0].value if cn_attrs else None
        if common_name:
            names.add(common_name.lower())
        try:
            san_ext = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            names.update(name.lower() for name in san_ext.value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            pass
        return common_name, names

    @staticmethod
    def _resolve_ca_id(plugin_name):
        for row in SucmCertificate().get_all_certificate_authority():
            if f"{row[1]}_{row[2]}" == plugin_name:
                return row[0]
        raise SucmAcmeOrderError(
            f"No '{plugin_name}' entry found in the CertificateAuthority table",
            acme_type="serverInternal",
            status_code=500,
        )

    def finalize_order(self, order_id, csr_der):
        """
        csr_der: raw DER bytes of the CSR from the ACME finalize payload.

        Validates the CSR's identifier set against the order's authorized
        identifiers, then drives the existing SucmCertificate pipeline
        (submit_manual_csr + renew_cert_with_csr) to actually get a cert
        issued via the configured CA and stashed in Vault, exactly as a
        manually-submitted CSR would be. Returns the updated order dict.
        """
        order = self.get_order(order_id)
        if not order:
            raise SucmAcmeOrderError("No such order", acme_type="malformed", status_code=404)
        if order["status"] != "ready":
            raise SucmAcmeOrderError(
                f"Order is not ready to be finalized (status: {order['status']})",
                acme_type="orderNotReady",
                status_code=403,
            )

        try:
            csr = x509.load_der_x509_csr(csr_der, default_backend())
        except ValueError as exc:
            raise SucmAcmeOrderError(f"Could not parse CSR: {exc}") from exc

        if not csr.is_signature_valid:
            raise SucmAcmeOrderError("CSR signature does not verify against its own public key")

        common_name, csr_names = self._csr_identifiers(csr)
        order_names = {i["value"].lower() for i in order["identifiers"]}

        if not csr_names:
            raise SucmAcmeOrderError("CSR contains no identifiers")
        if not csr_names.issubset(order_names):
            raise SucmAcmeOrderError(
                "CSR identifiers are not a subset of the order's authorized identifiers",
                acme_type="badCSR",
            )
        if common_name is None:
            # Certbot's CSRs put the first name in both CN and SAN; fall
            # back to an arbitrary authorized name if a client omits CN.
            common_name = sorted(csr_names)[0]

        existing = SucmCertificate().get_common_name(common_name)
        if existing and existing.get("cert_type") != ACME_CERT_TYPE:
            raise SucmAcmeOrderError(
                f"{common_name} already exists as a non-ACME certificate in SUCM; "
                "an administrator must resolve this before it can be issued via ACME",
                acme_type="rejectedIdentifier",
                status_code=409,
            )

        cert_id = existing["cert_id"] if existing else SucmCertificate().get_next_cert_id()
        subject_alt = ", ".join(sorted(csr_names))

        cert_conf = {
            "common_name": common_name,
            "certificate_authority_id": self._resolve_ca_id(ACME_CA_PLUGIN_NAME),
            "country": cfg.get("cert_defaults", "country_name"),
            "state": cfg.get("cert_defaults", "state_or_province_name"),
            "city": cfg.get("cert_defaults", "locality_name"),
            "organisation": cfg.get("cert_defaults", "organization_name"),
            "subject_alt": subject_alt,
            "cert_type": ACME_CERT_TYPE,
            "notify_group": ACME_NOTIFY_GROUP_ID,
            "status": None,
            "secret_path": ACME_SECRET_PATH,
        }

        sucm_db.execute_modify_query(
            "UPDATE AcmeOrder SET Status = %s, Cert_Id = %s WHERE Order_Id = %s",
            ("processing", cert_id, order_id),
        )

        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        try:
            cert = SucmCertificate(cert_id=cert_id, cert_conf=cert_conf)
            cert.submit_manual_csr(csr_pem)
            cert.renew_cert_with_csr()
        except Exception as exc:
            sucm_db.execute_modify_query(
                "UPDATE AcmeOrder SET Status = %s, Error = %s WHERE Order_Id = %s",
                ("invalid", str(exc), order_id),
            )
            audit_logger.error(
                "ACME order %s finalize failed for %s: %s", order_id, common_name, exc
            )
            raise SucmAcmeOrderError(
                f"Certificate issuance failed: {exc}", acme_type="serverInternal", status_code=500
            ) from exc

        sucm_db.execute_modify_query(
            "UPDATE AcmeOrder SET Status = %s WHERE Order_Id = %s",
            ("valid", order_id),
        )
        audit_logger.info(
            "ACME order %s finalized: cert_id=%s common_name=%s", order_id, cert_id, common_name
        )
        return self.get_order(order_id)
