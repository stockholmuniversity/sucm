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

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

from ..sucm_settings import cfg, sys_logger
from . import SucmCertificateAuthority

CA_PLUGIN_NAME = "HARICA_EAB"
harica_eab_config = {
    "harica_username": cfg.get(CA_PLUGIN_NAME, "harica_username"),
    "harica_password": cfg.get(CA_PLUGIN_NAME, "harica_password"),
    "harica_totp_seed": cfg.get(CA_PLUGIN_NAME, "harica_totp_seed"),
    "harica_base_url": cfg.get(CA_PLUGIN_NAME, "harica_base_url"),
}


class Harica_EAB(SucmCertificateAuthority):
    def __init__(self):
        self.api_base_url = harica_eab_config["api_base_url"]
        self.harica_email = harica_eab_config["harica_email"]
        self.harica_password = harica_eab_config["harica_password"]
        self.harica_totp_seed = harica_eab_config["harica_totp_seed"]
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

    def login(self):
        token = self.generate_totp()
        self.fetch_rvt()
        login_data = {"email": self.harica_email, "password": self.harica_password, "token": token}
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

    def request_certificate(self, common_name, csr):
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

#        key_path = key_file_template.format(common_name)
#        csr_path = csr_file_template.format(common_name)
#
#        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
#        subprocess.run(
#            [
#                "openssl",
#                "req",
#                "-new",
#                "-key",
#                key_path,
#                "-subj",
#                f"/CN={common_name}",
#                "-out",
#                csr_path,
#            ],
#            check=True,
#        )

#        with open(csr_path, "r") as f:
#            csr = f.read()

        multipart_payload = MultipartEncoder(
            fields={
                "domainsString": json.dumps([domain_obj]),
                "consentSameKey": "false",
                "friendlyName": common_name,
                "organizationDN": org_dn,
                "duration": "1",
                "csr": csr,
                "transactionType": "OV",
                "domains": json.dumps([domain_obj]),
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

    def revoke_certificate(self, common_name):
        if not os.path.exists(local_cert_db):
            print(f"No certificates.json found. Cannot revoke.")
            sys.exit(1)

        with open(local_cert_db, "r") as f:
            certs = json.load(f)

        cert_id = next((c["id"] for c in certs if c.get("domain") == common_name), None)

        if not cert_id:
            print(f"No certificate ID found for domain {common_name} in certificates.json")
            sys.exit(1)

        print(f"Found cert ID {cert_id} for domain {common_name}")
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

    def download_certificate(self, common_name):
        if not os.path.exists(local_cert_db):
            print(f"No certificates.json found.")
            sys.exit(1)

        with open(local_cert_db, "r") as f:
            certs = json.load(f)

        cert_id = next((c["id"] for c in certs if c.get("domain") == common_name), None)

        if not cert_id:
            print(f"No certificate ID found for domain {common_name} in certificates.json")
            sys.exit(1)

        print(f"Found cert ID {cert_id} for domain {common_name}")
        self.fetch_rvt()

        r = self.session.post(
            f"{self.api_base_url}/api/Certificate/GetCertificate",
            json={"id": cert_id},
            headers={"Content-Type": "application/json;charset=utf-8"},
        )

        print("GetCertificate status:", r.status_code)
        if not r.ok:
            print("Failed to get certificate:")
            print(r.text)
            sys.exit(1)

        full_chain = r.text.encode().decode("unicode_escape")  # <-- unescape \n

        cert_blocks = re.findall(
            r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
            full_chain,
            re.DOTALL,
        )

        if not cert_blocks:
            print("No certificates found in response.")
            sys.exit(1)

#        pem_file = f"{common_name}.pem"
#        crt_file = f"{common_name}.crt"
#        key_file = key_file_template.format(common_name)
#
#        with open(pem_file, "w") as f:
#            f.write(cert_blocks[0].strip() + "\n")
#
#        with open(crt_file, "w") as f:
#            f.write("\n".join(block.strip() for block in cert_blocks) + "\n")
#
#        print(f"Saved leaf certificate to {pem_file}")
#        print(f"Saved full chain to {crt_file}")
#
#        if os.path.exists(key_file):
#            print(f"Private key exists: {key_file}")
#            #check_key_match(pem_file, key_file)
#        else:
#            print(f"Warning: Private key file {key_file} not found.")
#
#    def check_key_match(self, cert_path, key_path):
#        try:
#            mod_cert = subprocess.check_output(
#                ["openssl", "x509", "-noout", "-modulus", "-in", cert_path]
#            )
#            mod_key = subprocess.check_output(
#                ["openssl", "rsa", "-noout", "-modulus", "-in", key_path]
#            )
#            if mod_cert.strip() == mod_key.strip():
#                print("Certificate and private key match.")
#            else:
#                print("Certificate and private key do NOT match!")
#        except subprocess.CalledProcessError as e:
#            print("Error checking modulus match:", e)

    def save_certificate_mapping(self, common_name, cert_id):
        certs = []
        if os.path.exists(local_cert_db):
            with open(local_cert_db, "r") as f:
                try:
                    certs = json.load(f)
                except json.JSONDecodeError:
                    pass

        certs.append({"domain": common_name, "id": cert_id})

        with open(local_cert_db, "w") as f:
            json.dump(certs, f, indent=2)
    def generate_totp(self, digits=6, time_step=30, t0=0, digest_method=hashlib.sha1):
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
            key = base64.b32decode(self.harica_totp_seed.upper() + '=' * ((8 -
                len(self.harica_totp_seed) % 8) % 8))
        except Exception as e:
            raise ValueError("Invalid base32 encoded secret") from e
        # Calculate the number of time steps since t0
        current_time = int(time.time())
        counter = (current_time - t0) // time_step
        # Convert counter to byte array (big-endian, 8-byte integer)
        counter_bytes = struct.pack('>Q', counter)
        # Compute HMAC using the chosen digest method
        hmac_hash = hmac.new(key, counter_bytes, digest_method).digest()
        # Dynamic truncation: get offset from the last nibble of hmac_hash
        offset = hmac_hash[-1] & 0x0F
        # Take 4 bytes from offset
        selected_bytes = hmac_hash[offset:offset + 4]
        # Convert to a 31-bit integer
        code_int = struct.unpack('>I', selected_bytes)[0] & 0x7FFFFFFF
        # Compute the OTP value
        otp = code_int % (10 ** digits)
        # Pad with zeros if necessary
        return str(otp).zfill(digits)
        # Example usage:
        #
        #if __name__ == '__main__':
        #    # Replace with your base32 encoded TOTP seed/key
        #    code = generate_totp(self.harica_totp_seed)
        #    print("Your TOTP code is:", code)

    def validate_certificate_request(self, cert_id):
        pass

    def fetch_cert(self, csr_pem, common_name):
        try:
            self.login()
            cert_id_harica = self.request_certificate(common_name, csr_pem)
            self.validate_certificate_request(cert_id)
            #save_certificate_mapping(common_name, cert_id)
            pass
            return [cert_pem, expiry_date, fullchain_pem, cert_id_harica]
        except Exception as e:
            sys_logger.error(f"Error fetching certificate: {e}")
            return []

    def revoke_cert(self, fullchain_pem, common_name):
        try:
            pass
            sys_logger.info("Certificate revoked successfully.")
        except Exception as e:
            sys_logger.error(f"Error revoking certificate: {e}")

