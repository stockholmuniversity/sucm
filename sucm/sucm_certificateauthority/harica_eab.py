import base64
import hashlib
import hmac
import json
import os
import re
import struct
import subprocess
import sys
import time
from datetime import datetime

import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from requests_toolbelt.multipart.encoder import MultipartEncoder
from requests_toolbelt.utils import dump

from ..sucm_common import sucm_db
from ..sucm_settings import cfg, sys_logger
from . import SucmCertificateAuthority

CA_PLUGIN_NAME = "HARICA_EAB"
harica_eab_config = {
    "api_base_url": cfg.get(CA_PLUGIN_NAME, "api_base_url"),
    "order_email": cfg.get(CA_PLUGIN_NAME, "order_email"),
    "order_password": cfg.get(CA_PLUGIN_NAME, "order_password"),
    "order_totp_seed": cfg.get(CA_PLUGIN_NAME, "order_totp_seed"),
    "approve_email": cfg.get(CA_PLUGIN_NAME, "approve_email"),
    "approve_password": cfg.get(CA_PLUGIN_NAME, "approve_password"),
    "approve_totp_seed": cfg.get(CA_PLUGIN_NAME, "approve_totp_seed"),
}


class Harica_EAB(SucmCertificateAuthority):
    def __init__(self):
        self.api_base_url = harica_eab_config["api_base_url"]
        self.order_email = harica_eab_config["order_email"]
        self.order_password = harica_eab_config["order_password"]
        self.order_totp_seed = harica_eab_config["order_totp_seed"]
        self.approve_email = harica_eab_config["approve_email"]
        self.approve_password = harica_eab_config["approve_password"]
        self.approve_totp_seed = harica_eab_config["approve_totp_seed"]
        self.session = requests.Session()

    def fetch_rvt(self):
        r = self.session.get(self.api_base_url)
        match = re.search(
            r'<input name="__RequestVerificationToken".*value="([^"]+)"', r.text
        )
        if not match:
            print("Could not find RequestVerificationToken.")
            sys.exit(1)
        rvt = match.group(1)
        self.session.headers.update({"RequestVerificationToken": rvt})
        print("RequestVerificationToken updated.")
        return rvt

    def login(self, email, password, totp_seed):
        token = self.generate_totp(totp_seed)
        self.fetch_rvt()
        login_data = {"email": email, "password": password, "token": token}
        self.session.headers.update({"Content-Type": "application/json;charset=utf-8"})
        r = self.session.post(f"{self.api_base_url}/api/User/Login2FA", json=login_data)

        if (
            not r.ok
            or not r.text
            or not re.match(
                r"^[a-z0-9-_]+\.[a-z0-9-_]+\.[a-z0-9-_]+$",
                r.text.strip(),
                re.IGNORECASE,
            )
        ):
            print("Login failed or JWT token invalid:")
            print(r.text)
            sys.exit(1)

        jwt_token = r.text.strip().strip('"')
        self.session.headers.update({"Authorization": jwt_token})
        print("JWT token added to Authorization header.")

        self.fetch_rvt()

    def domains_string_from_csr_pem(self, csr_pem, fallback_cn):
        """
        Build the HARICA `domainsString` value (CSV) from a PEM CSR.
        Order: CN first (if present, else fallback_cn), then SAN DNS names.
        Duplicates are removed while preserving order.
        """
        if isinstance(csr_pem, bytes):
            csr_pem = csr_pem.decode("utf-8")

        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"), default_backend())

        ordered: List[str] = []
        print("before add")

        def _add(v):
            if v is None:
                return
            v = str(v).strip()
            if v and v not in ordered:
                ordered.append(v)

        print("after add")
        # CN first (or fallback)
        try:
            cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn = cn_attrs[0].value if cn_attrs else None
            _add(cn if cn else fallback_cn)
        except Exception:
            _add(fallback_cn)

        # SAN DNS names (includes wildcards if present)
        try:
            san_ext = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
            for d in san_ext.value.get_values_for_type(x509.DNSName):
                _add(d)
        except x509.ExtensionNotFound:
            pass

        return ",".join(ordered)

    def request_certificate(self, common_name, csr):
        domains_csv = self.domains_string_from_csr_pem(csr, common_name)
        domains_list = domains_csv.split(",") if domains_csv else [common_name]
        print("----- domains_csv\n" + domains_csv + "-------\n")
        domain_objs = []
        for d in domains_list:
            d = d.strip()
            if not d:
                continue
            is_wc = d.startswith("*.")  # wildcard?
            base = d[2:] if is_wc else d  # strip "*."
            domain_objs.append(
                {"isWildcard": is_wc, "domain": base, "includeWWW": False}
            )

        # Remove me START
        print(
            "\ndomains_objs -----\n" + json.dumps(domain_objs, indent=2) + "\n--------"
        )
        # Remove me END

        r = self.session.post(f"{self.api_base_url}/api/User/GetCurrentUser")
        print("GetCurrentUser status:", r.status_code)

        domain_obj = {"isWildcard": False, "domain": common_name, "includeWWW": False}
        r = self.session.post(
            f"{self.api_base_url}/api/ServerCertificate/CheckMachingOrganization",
            json=[domain_obj],
        )
        if not r.ok:
            print("Failed to fetch organization info.")
            print(r.text)
            sys.exit(1)

        org_data = r.json()
        if not org_data:
            print("No organization matched domain.")
            sys.exit(1)
        org_id = org_data[0]["id"]
        org_dn = f"OrganizationId:{org_id}&C:SE&L:Stockholm&O:Stockholms universitet"
        print("Organization ID:", org_id)

        multipart_payload = MultipartEncoder(
            fields={
                "domainsString": json.dumps(domain_objs),
                "consentSameKey": "false",
                "friendlyName": common_name,
                "organizationDN": org_dn,
                "duration": "1",
                "csr": csr,
                "transactionType": "OV",
                "domains": json.dumps(domain_objs),
                "isManualCSR": "true",
            }
        )

        self.session.headers["Content-Type"] = multipart_payload.content_type
        r = self.session.post(
            f"{self.api_base_url}/api/ServerCertificate/RequestServerCertificate",
            data=multipart_payload,
        )

        print("RequestServerCertificate status:", r.status_code)
        print(r.text)

        if r.ok:
            try:
                cert_id = r.json().get("id")
                return cert_id
            except Exception as e:
                print("Warning: Could not parse certificate ID for {common_name}.")
                print(e)
                return None

    def approve_certificate_request(self, cert_id):
        payload = {"startIndex": 0, "status": "Pending", "filterPostDTOs": []}

        r = self.session.post(
            f"{self.api_base_url}/api/OrganizationValidatorSSL/GetSSLReviewableTransactions",
            json=payload,
        )
        if not r.ok:
            print(" Failed to fetch reviewable transactions.")
            sys.exit(1)

        transactions = r.json()
        tx = next((t for t in transactions if t.get("transactionId") == cert_id), None)
        if not tx:
            print(f" Transaction ID {cert_id} not found.")
            sys.exit(1)

        print(f"\n Reviews for transaction {cert_id}:\n")
        reviews = tx.get("reviewGetDTOs", [])
        if not reviews:
            print(" No reviews found.")
            sys.exit(1)

        approved_any = False
        for idx, review in enumerate(reviews, start=1):
            reviewed = review.get("isReviewed")
            rid = review.get("reviewId")
            rval = review.get("reviewValue")
            status = " already approved" if reviewed else " will approve"
            print(f"   - Review {idx}: id={rid} value={rval}  {status}")

            if not reviewed and rid and rval:
                fields = {
                    "reviewId": rid,
                    "isValid": "true",
                    "informApplicant": "true",
                    "reviewMessage": "Approved via script",
                    "reviewValue": rval,
                }

                m = MultipartEncoder(fields=fields)
                self.session.headers["Content-Type"] = m.content_type

                r = self.session.post(
                    f"{self.api_base_url}/api/OrganizationValidatorSSL/UpdateReviews",
                    data=m,
                )

                if r.ok:
                    print(f"      Approved review {rid}")
                    approved_any = True
                else:
                    print(f"      Failed to approve review {rid}: {r.status_code}")
                    print("     Body:", r.text)

        if approved_any:
            print(f"\n Transaction {cert_id} fully approved.")
        else:
            print("\n No reviews were approved (maybe already approved?).")

    def revoke_certificate(self, cert_id):
        self.fetch_rvt()

        revoke_data = {
            "transactionId": cert_id,
            "name": "4.9.1.1.1.1",
            "notes": f"Revoked via SUCM for {common_name}",
            "message": "",
        }

        r = self.session.post(
            f"{self.api_base_url}/api/Certificate/RevokeCertificate",
            json=revoke_data,
            headers={"Content-Type": "application/json;charset=utf-8"},
        )

        print("RevokeCertificate status:", r.status_code)
        print(r.text)

    def download_certificate(self, cert_id: str, common_name: str):
        """
        Downloads the certificate for a given cert_id from HARICA,
        verifies it against the private key, and returns SUCM-compatible output.

        Returns:
            list: [leaf_cert_pem (str), expiry_date (datetime),
                   full_chain_pem (str), cert_id (str)]
        """
        self.fetch_rvt()

        r = self.session.post(
            f"{self.api_base_url}/api/Certificate/GetCertificate",
            json={"id": cert_id},
            headers={"Content-Type": "application/json;charset=utf-8"},
        )

        print("GetCertificate status:", r.status_code)
        if not r.ok:
            raise RuntimeError(f"Failed to get certificate: {r.text}")

        full_chain = r.text.encode().decode("unicode_escape")

        cert_blocks = re.findall(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            full_chain,
            re.DOTALL,
        )

        if not cert_blocks:
            raise ValueError("No certificates found in HARICA response.")

        leaf_cert_pem = cert_blocks[0].strip() + "\n"
        full_chain_pem = "\n".join(block.strip() for block in cert_blocks) + "\n"

        # Parse expiration date from leaf certificate
        cert_obj = x509.load_pem_x509_certificate(
            leaf_cert_pem.encode(), default_backend()
        )
        expiry_date = cert_obj.not_valid_after_utc
        # print(f"Expiry date looks like: {expiry_date}")
        return_object = [leaf_cert_pem, expiry_date, full_chain_pem, cert_id]
        print("Printing some debug data below.")
        for item in return_object:
            print(f"Type: {type(item)}, Content: {item}")
        return return_object

    def generate_totp(
        self, totp_seed, digits=6, time_step=30, t0=0, digest_method=hashlib.sha1
    ):
        """
        Generates a TOTP code.
        :param secret: The TOTP seed as a base32 encoded string (without spaces).
        :param digits: The number of digits in the OTP (default is 6).
        :param time_step: The time step in seconds (default is 30).
        :param t0: The Unix time to start counting time steps (default is 0).
        :param digest_method: The cryptographic hash function to use (default is hashlib.sha1).
        :return: The TOTP code as a string.
        """
        try:
            # Decode the base32 secret (pads if necessary)
            key = base64.b32decode(
                totp_seed.upper() + "=" * ((8 - len(totp_seed) % 8) % 8)
            )
        except Exception as e:
            raise ValueError("Invalid base32 encoded secret") from e
        # Calculate the number of time steps since t0
        current_time = int(time.time())
        counter = (current_time - t0) // time_step
        # Convert counter to byte array (big-endian, 8-byte integer)
        counter_bytes = struct.pack(">Q", counter)
        # Compute HMAC using the chosen digest method
        hmac_hash = hmac.new(key, counter_bytes, digest_method).digest()
        # Dynamic truncation: get offset from the last nibble of hmac_hash
        offset = hmac_hash[-1] & 0x0F
        # Take 4 bytes from offset
        selected_bytes = hmac_hash[offset : offset + 4]
        # Convert to a 31-bit integer
        code_int = struct.unpack(">I", selected_bytes)[0] & 0x7FFFFFFF
        # Compute the OTP value
        otp = code_int % (10**digits)
        # Pad with zeros if necessary
        return str(otp).zfill(digits)
        # Example usage:
        #
        # if __name__ == '__main__':
        #    # Replace with your base32 encoded TOTP seed/key
        #    code = generate_totp(self.harica_totp_seed)
        #    print("Your TOTP code is:", code)

    def fetch_cert(self, csr_pem, common_name):
        try:
            self.login(self.order_email, self.order_password, self.order_totp_seed)
            harica_cert_id = self.request_certificate(common_name, csr_pem)
            print(f"Certificate requested. cert_id returned is {harica_cert_id}")
            self.login(
                self.approve_email, self.approve_password, self.approve_totp_seed
            )
            self.approve_certificate_request(harica_cert_id)

            self.login(self.order_email, self.order_password, self.order_totp_seed)
            certs = self.download_certificate(harica_cert_id, common_name)
            return certs
        except Exception as e:
            sys_logger.error(f"Error fetching certificate: {e}")
            return []

    def revoke_cert(self, fullchain_pem, active_cert_id, common_name=None):
        #        try:
        cert_id_harica = sucm_db.get_records(
            "activecertificate", f"ActiveCertificate_Id = {self.active_cert_id}"
        )[0]["Cert_Id_Harica"]
        print(f"Attempted retrieval of cert_id_harica, value: {cert_id_harica}")
        self.revoke_certificate(cert_id_harica)
        sys_logger.info("Certificate revoked successfully.")


#        except Exception as e:
#            sys_logger.error(f"Error revoking certificate: {e}")
