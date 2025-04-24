import requests
import sys
import re
import subprocess
import tempfile
import os
import json
from requests_toolbelt.multipart.encoder import MultipartEncoder

if len(sys.argv) != 3:
    print("Usage: python3 harica-request-multipart.py <TOTP-token> <domain>")
    sys.exit(1)

token = sys.argv[1]
domain = sys.argv[2]

# Configuration
email = "jan.qvarnstrom@su.se"
password = "pastw your password here"
url_base = "https://cm.harica.gr"

session = requests.Session()


def fetch_rvt():
    """Fetches and updates the RequestVerificationToken from homepage."""
    r = session.get(url_base)
    match = re.search(
        r'<input name="__RequestVerificationToken".*value="([^"]+)"', r.text
    )
    if not match:
        print("Could not find RequestVerificationToken.")
        sys.exit(1)
    rvt = match.group(1)
    session.headers.update({"RequestVerificationToken": rvt})
    print("RequestVerificationToken updated.")
    return rvt


# Step 1: Initial RVToken
fetch_rvt()

# Step 2: Login
login_data = {"email": email, "password": password, "token": token}
session.headers.update({"Content-Type": "application/json;charset=utf-8"})
r = session.post(f"{url_base}/api/User/Login2FA", json=login_data)

if (
    not r.ok
    or not r.text
    or not re.match(
        r"^[a-z0-9-_]+\.[a-z0-9-_]+\.[a-z0-9-_]+$", r.text.strip(), re.IGNORECASE
    )
):
    print("Login failed or JWT token invalid:")
    print(r.text)
    sys.exit(1)

jwt_token = r.text.strip().strip('"')
session.headers.update({"Authorization": jwt_token})
print("JWT token added to Authorization header.")

# Step 3: Refresh RVToken after login
fetch_rvt()

# Step 4: Confirm user
r = session.post(f"{url_base}/api/User/GetCurrentUser")
print("GetCurrentUser status:", r.status_code)
print(r.text)

# Step 5: Get Organization ID
domain_obj = {"isWildcard": False, "domain": domain, "includeWWW": False}
r = session.post(
    f"{url_base}/api/ServerCertificate/CheckMachingOrganization", json=[domain_obj]
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

# Step 6: Generate private key and CSR
with tempfile.TemporaryDirectory() as tmpdir:
    key_path = os.path.join(tmpdir, f"key-{domain}.pem")
    csr_path = os.path.join(tmpdir, f"csr-{domain}.pem")

    subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True)

    subprocess.run(
        [
            "openssl",
            "req",
            "-new",
            "-key",
            key_path,
            "-subj",
            f"/CN={domain}",
            "-out",
            csr_path,
        ],
        check=True,
    )

    with open(csr_path, "r") as f:
        csr = f.read()

# Step 7: Submit certificate request using multipart/form-data
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
        "isManualCSR": "true",
    }
)

session.headers["Content-Type"] = multipart_payload.content_type

r = session.post(
    f"{url_base}/api/ServerCertificate/RequestServerCertificate", data=multipart_payload
)

print("RequestServerCertificate status:", r.status_code)
print(r.text)
