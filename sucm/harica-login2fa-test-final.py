import requests
import sys
import re
import subprocess
import tempfile
import os
import json
from requests_toolbelt.multipart.encoder import MultipartEncoder

if len(sys.argv) < 4:
    print("Usage:")
    print("  python3 harica-login2fa-test-final-with-revoke.py req <TOTP-token> <domain>")
    print("  python3 harica-login2fa-test-final-with-revoke.py revoke <TOTP-token> <domain>")
    sys.exit(1)

command = sys.argv[1]
token = sys.argv[2]
target = sys.argv[3]

# Configuration
email = "jan.qvarnstrom@su.se"
password = "your password"
url_base = "https://cm.harica.gr"
local_cert_db = "certificates.json"

session = requests.Session()

def fetch_rvt():
    """Fetch and update the RequestVerificationToken."""
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
    """Login with email, password, and TOTP token."""
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
    """Request a new certificate and save its ID locally."""
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

    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, f"key-{domain}.pem")
        csr_path = os.path.join(tmpdir, f"csr-{domain}.pem")

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
    """Revoke an existing certificate based on domain."""
    if not os.path.exists(local_cert_db):
        print(f"No certificates.json found. Cannot revoke.")
        sys.exit(1)

    with open(local_cert_db, "r") as f:
        certs = json.load(f)

    cert_id = None
    for cert in certs:
        if cert.get("domain") == domain:
            cert_id = cert.get("id")
            break

    if not cert_id:
        print(f"No certificate ID found for domain {domain} in certificates.json")
        sys.exit(1)

    print(f"Found cert ID {cert_id} for domain {domain}")

    fetch_rvt()  # Refresh RVT before revoking

    revoke_data = {
        "transactionId": cert_id,
        "name": "4.9.1.1.1.1",  # Correct name field now
        "notes": f"Revoked via script by {email}",
        "message": ""
    }

    r = session.post(
        f"{url_base}/api/Certificate/RevokeCertificate",
        json=revoke_data,
        headers={"Content-Type": "application/json;charset=utf-8"}
    )

    print("RevokeCertificate status:", r.status_code)
    print(r.text)

def save_certificate_mapping(domain, cert_id):
    """Save domain and cert ID to local JSON file."""
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
else:
    print(f"Unknown command: {command}")
    sys.exit(1)

