import requests
import json
import getpass
import base64
import time
import hashlib
import hmac
import re

def get_rvt(session, base_url):
    res = session.get(base_url)
    if res.status_code != 200:
        raise Exception("Failed to get RVT")
    m = re.search(r'<input name="__RequestVerificationToken".*value="([^"]+)"', res.text)
    rvt=m.group(1)
    return rvt

def totp_token(secret):
    key = base64.b32decode(secret.upper() + '=' * ((8 - len(secret) % 8) % 8))
    msg = int(time.time() / 30).to_bytes(8, 'big')
    h = hmac.new(key, msg, hashlib.sha1).digest()
    o = h[19] & 15
    code = (int.from_bytes(h[o:o+4], 'big') & 0x7fffffff) % 1000000
    return f"{code:06d}"

def login(session, base_url, email, password, totp_secret):
    rvt = get_rvt(session, base_url)
    session.headers.update({
        'RequestVerificationToken': rvt,
        'Content-Type': 'application/json;charset=utf-8',
        'Accept': 'application/json, text/plain, */*'
    })

    token = totp_token(totp_secret)
    print(f"Generated TOTP: {token}")

    payload = {
        'email': email,
        'password': password,
        'token': token
    }
    res = session.post(f"{base_url}/api/User/Login2FA", data=json.dumps(payload))
    if not res.ok:
        raise Exception(f"Login failed: {res.text}")
    jwt = res.text.strip()
    session.headers['Authorization'] = jwt

    # Refresh RVT again after login
    rvt = get_rvt(session, base_url)
    session.headers['RequestVerificationToken'] = rvt
    print("Logged in successfully with 2FA.")

def get_matching_org(session, base_url, domains):
    payload = [
        {
            "isWildcard": False,
            "domain": domain,
            "includeWWW": False
        } for domain in domains
    ]
    r = session.get(base_url + "/api/ServerCertificate/CheckMachingOrganization", json=payload)
    #res = session.post(f"{base_url}/api/ServerCertificate/CheckMachingOrganization", json=payload)
    orgs = r.json()
    if not orgs:
        raise Exception("No matching organizations found.")
    print(f"Using organization: {orgs[0]['organizationName']} ({orgs[0]['id']})")
    return orgs[0]

def request_certificate(session, base_url, org, csr, domain):
    #orgDN = f"OrganizationId:{org['id']}&C:{org['country']}&ST:{org['state']}&L:{org['locality']}&O:{org['organizationName']}"
    org_info = session.post(base_url + "/api/ServerCertificate/CheckMachingOrganization", [ {"domain": "su.se" } ])
    org_id = org_info.json()[0]["id"]
    payload = {
        'friendlyName': domain,
        'transactionType': 'OV',
        'consentSameKey': 'true',
        'isManualCSR': 'true',
        'duration': 1,
        'csr': csr,
        'organizationDN': org_id,
        'domains': json.dumps([{ "domain": domain, "isWildcard": False, "includeWWW": False }]),
        'domainsString': json.dumps([{ "domain": domain, "isWildcard": False, "includeWWW": False }])
    }
    res = session.post(f"{base_url}/api/ServerCertificate/RequestServerCertificate", files=payload)
    if not res.ok:
        raise Exception(f"Request failed: {res.text}")
    print("Certificate requested:", res.text)
    return res.json()['id']

def download_certificate(session, base_url, cert_id):
    res = session.post(f"{base_url}/api/Certificate/GetCertificate", json={"id": cert_id})
    if not res.ok:
        raise Exception(f"Download failed: {res.text}")
    cert_data = res.json()
    print(f"Downloaded certificate for {cert_data['friendlyName']}:")
    print(cert_data['certificate'])

def main():
    base_url = 'https://cm.harica.gr'
    email = "claes.johansson@su.se"
    password = getpass.getpass("Password: ")
    totp_secret = input("TOTP Secret (base32): ")
    domain = input("Domain: ")
    csr_file = input("CSR file path: ")

    with open(csr_file, 'r') as f:
        csr = f.read()

    session = requests.Session()

    login(session, base_url, email, password, totp_secret)
    org = get_matching_org(session, base_url, [domain])
    cert_id = request_certificate(session, base_url, org, csr, domain)

    # Also try downloading the cert (can use the fixed ID for testing)
    download_certificate(session, base_url, "6b69fff2-9f4c-4b66-ad03-bae3675059b8")

if __name__ == '__main__':
    main()
