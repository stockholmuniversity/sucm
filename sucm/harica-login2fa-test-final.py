import json
import os
import re
import subprocess
import sys

import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

if len(sys.argv) < 4:
    print("Usage:")
    print("  python3 harica-login2fa-test-final.py req <TOTP-token> <domain>")
    print("  python3 harica-login2fa-test-final.py revoke <TOTP-token> <domain>")
    print("  python3 harica-login2fa-test-final.py download <TOTP-token> <domain>")
    sys.exit(1)

command = sys.argv[1]
token = sys.argv[2]
target = sys.argv[3]

# Configuration
email = "jan.qvarnstrom@su.se"
password = "your password"
url_base = "https://cm.harica.gr"
local_cert_db = "certificates.json"
key_file_template = "{}.key"
csr_file_template = "{}.csr"

session = requests.Session()

def fetch_rvt():
    r = session.get(url_base)
    match = re.search(r'<input name="__RequestVerificationToken".*value="([^"]+)"', r.text)
    if not match:
        print("Could not find RequestVerificationToken.")
        sys.exit(1)
    rvt = match.group(1)
    session.headers.update({"RequestVerificationToken": rvt})
    print("RequestVerificationToken updated.")
    return rvt

def login(token):
    fetch_rvt()
    login_data = {
        "email": email,
        "password": password,
        "token": token
    }
    session.headers.update({"Content-Type": "application/json;charset=utf-8"})
    r = session.post(f"{url_base}/api/User/Login2FA", json=login_data)

    if not r.ok or not r.text or not re.match(r'^[a-z0-9-_]+\.[a-z0-9-_]+\.[a-z0-9-_]+$', r.text.strip(), re.IGNORECASE):
        print("Login failed or JWT token invalid:")
        print(r.text)
        sys.exit(1)

    jwt_token = r.text.strip().strip('"')
    session.headers.update({"Authorization": jwt_token})
    print("JWT token added to Authorization header.")

    fetch_rvt()

def request_certificate(domain):
    r = session.post(f"{url_base}/api/User/GetCurrentUser")
    print("GetCurrentUser status:", r.status_code)

    domain_obj = {"isWildcard": False, "domain": domain, "includeWWW": False}
    r = session.post(f"{url_base}/api/ServerCertificate/CheckMachingOrganization", json=[domain_obj])
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

    key_path = key_file_template.format(domain)
    csr_path = csr_file_template.format(domain)

    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)
    subprocess.run(["openssl", "req", "-new", "-key", key_path, "-subj", f"/CN={domain}", "-out", csr_path], check=True)

    with open(csr_path, "r") as f:
        csr = f.read()

    multipart_payload = MultipartEncoder(
        fields={
            "domainsString": json.dumps([domain_obj]),
            "consentSameKey": "false",
            "friendlyName": domain,
            "organizationDN": org_dn,
            "duration": "1",
            "csr": csr,
            "transactionType": "OV",
            "domains": json.dumps([domain_obj]),
            "isManualCSR": "true"
        }
    )

    session.headers["Content-Type"] = multipart_payload.content_type
    r = session.post(f"{url_base}/api/ServerCertificate/RequestServerCertificate", data=multipart_payload)

    print("RequestServerCertificate status:", r.status_code)
    print(r.text)

    if r.ok:
        try:
            cert_id = r.json().get("id")
            if cert_id:
                save_certificate_mapping(domain, cert_id)
                print(f"Saved {domain} with cert ID {cert_id} to certificates.json.")
            else:
                print("Warning: Certificate ID not found in response.")
        except Exception as e:
            print("Warning: Could not parse certificate ID.")
            print(e)

def revoke_certificate(domain):
    if not os.path.exists(local_cert_db):
        print(f"No certificates.json found. Cannot revoke.")
        sys.exit(1)

    with open(local_cert_db, "r") as f:
        certs = json.load(f)

    cert_id = next((c["id"] for c in certs if c.get("domain") == domain), None)

    if not cert_id:
        print(f"No certificate ID found for domain {domain} in certificates.json")
        sys.exit(1)

    print(f"Found cert ID {cert_id} for domain {domain}")
    fetch_rvt()

    revoke_data = {
        "transactionId": cert_id,
        "name": "4.9.1.1.1.1",
        "notes": f"Revoked via SUCM for {domain}",
        "message": "",
    }

    r = session.post(
        f"{url_base}/api/Certificate/RevokeCertificate",
        json=revoke_data,
        headers={"Content-Type": "application/json;charset=utf-8"}
    )

    print("RevokeCertificate status:", r.status_code)
    print(r.text)

def download_certificate(domain):
    if not os.path.exists(local_cert_db):
        print(f"No certificates.json found.")
        sys.exit(1)

    with open(local_cert_db, "r") as f:
        certs = json.load(f)

    cert_id = next((c["id"] for c in certs if c.get("domain") == domain), None)

    if not cert_id:
        print(f"No certificate ID found for domain {domain} in certificates.json")
        sys.exit(1)

    print(f"Found cert ID {cert_id} for domain {domain}")
    fetch_rvt()

    r = session.post(
        f"{url_base}/api/Certificate/GetCertificate",
        json={"id": cert_id},
        headers={"Content-Type": "application/json;charset=utf-8"}
    )

    print("GetCertificate status:", r.status_code)
    if not r.ok:
        print("Failed to get certificate:")
        print(r.text)
        sys.exit(1)

    full_chain = r.text.encode().decode('unicode_escape')  # <-- unescape \n

    cert_blocks = re.findall(
        r"(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)",
        full_chain,
        re.DOTALL
    )

    if not cert_blocks:
        print("No certificates found in response.")
        sys.exit(1)

    pem_file = f"{domain}.pem"
    crt_file = f"{domain}.crt"
    key_file = key_file_template.format(domain)

    with open(pem_file, "w") as f:
        f.write(cert_blocks[0].strip() + "\n")

    with open(crt_file, "w") as f:
        f.write("\n".join(block.strip() for block in cert_blocks) + "\n")

    print(f"Saved leaf certificate to {pem_file}")
    print(f"Saved full chain to {crt_file}")

    if os.path.exists(key_file):
        print(f"Private key exists: {key_file}")
        check_key_match(pem_file, key_file)
    else:
        print(f"❗ Warning: Private key file {key_file} not found.")

def check_key_match(cert_path, key_path):
    try:
        mod_cert = subprocess.check_output(
            ["openssl", "x509", "-noout", "-modulus", "-in", cert_path]
        )
        mod_key = subprocess.check_output(
            ["openssl", "rsa", "-noout", "-modulus", "-in", key_path]
        )
        if mod_cert.strip() == mod_key.strip():
            print("✅ Certificate and private key match.")
        else:
            print("❌ Certificate and private key do NOT match!")
    except subprocess.CalledProcessError as e:
        print("Error checking modulus match:", e)

def save_certificate_mapping(domain, cert_id):
    certs = []
    if os.path.exists(local_cert_db):
        with open(local_cert_db, "r") as f:
            try:
                certs = json.load(f)
            except json.JSONDecodeError:
                pass

    certs.append({"domain": domain, "id": cert_id})

    with open(local_cert_db, "w") as f:
        json.dump(certs, f, indent=2)

# Main execution
login(token)

if command == "req":
    request_certificate(target)
elif command == "revoke":
    revoke_certificate(target)
elif command == "download":
    download_certificate(target)
else:
    print(f"Unknown command: {command}")
    sys.exit(1)

