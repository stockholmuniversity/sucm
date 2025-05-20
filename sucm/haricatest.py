#!/usr/bin/python3

# from getpass import getpass
# from pprint import pprint
import json
import os
import re

import requests

tfa = ""
class HaricaAPI:
    def __init__(self):
        # For this demonstration, take email and password from environment variables
        secrets = {}
        with open("harica.json", "r") as harica:
            secrets = json.load(harica)
        self.url_base = os.environ.get("HARICA_URL_BASE", "https://cm.harica.gr")
        #self.email = os.environ["HARICA_EMAIL"]
        #self.password = os.environ["HARICA_PASSWORD"]
        self.email = secrets["email"]
        self.password = secrets["password"]
        tfa = secrets["2fa"]
        # We use a session to get cookies stored automatically, and to be able to set
        # headers for subsequent calls
        self.session = requests.Session()

        # These do not seem to be needed?
        # self.session.headers.update({"Content-Type": "multipart/form-data"})
        # self.session.headers.update({"Accept": "application/json, text/plain, */*"})

    def _update_rvt(self):
        """Update the RequestVerificationToken.

        Needs to be done before login. Also needs to be done again after login as the
        value changes."""

        r = self.session.get(self.url_base)
        m = re.search(
            r'<input name="__RequestVerificationToken".*value="([^"]+)"', r.text
            )
        rvt = m.group(1)
        self.session.headers.update({"RequestVerificationToken": rvt})
        print("Token from _update_rvt: " + rvt)

    def post(self, path, data=None):
        """Abstract the POST handling a bit so we do not have to repeat it everuwhere."""

        self._update_rvt()
        if data is None:
            data = {}
        r = self.session.post(self.url_base + path, json=data)
#        print(r.text)
        r.raise_for_status()
        print("Headers in request: " + h.session.headers.get("RequestVerificationToken"))
        return r

    def post_with_formdata(self, path, data=None):
        """Abstract the POST handling a bit so we do not have to repeat it everuwhere."""

        self._update_rvt()
        if data is None:
            data = {}
        r = self.session.post(self.url_base + path, data=data)
#        print(r.text)
        r.raise_for_status()
        print("Headers in request: " + h.session.headers.get("RequestVerificationToken"))
        return r

    def login(self):
        """Login for user without 2FA."""

        self._update_rvt()
        login_data = {"email": self.email, "password": self.password}
        r = self.post("/api/User/Login", login_data)
        self.session.headers.update({"Authorization": r.text})
        self._update_rvt()

    def login_2fa(self, token):
        """Login for user with 2FA."""

        self._update_rvt()
        login_data = {"email": self.email, "password": self.password, "token": token}
        r = self.post("/api/User/Login2FA", login_data)
        self.session.headers.update({"Authorization": r.text})
        self._update_rvt()


h = HaricaAPI()

# Login for user without 2FA
# h.login()

# Login for user with 2FA
# token = getpass("Token: ")
token = os.popen("oathtool -b --totp '{}'".format(os.environ["HARICA_2FA"])).read().strip()
#print(token)
h.login_2fa(token)

# Demonstrate some simple API calls

#r = h.post("/api/User/GetCurrentUser")
#pprint(r.json())

#r = h.post("/api/ServerCertificate/CheckMachingOrganization", [{"domain": "liu.se"}])
#pprint(r.json())
# Test /api/User/GetCurrentUser. This seems to be working as of 2025-04-23.
#print("Start /api/User/GetCurrentUser")
#getCurrentUserResponse = h.post("/api/User/GetCurrentUser")
#print(getCurrentUserResponse.text)
#print("End /api/User/GetCurrentUser")
# Order new cert
print("\n\n")
csr_string = ""
fqdn=input("FQDN?")
with open("{}.csr".format(fqdn), "r") as csr:
    csr_string = csr.read()
org_info = h.post("/api/ServerCertificate/CheckMachingOrganization", [ {"domain": "su.se" } ])
org_id = org_info.json()[0]["id"]
print("org_id: {}".format(org_id))
order_data = {
        "friendlyName": "testcert-container-lab",
        "domains": '[{"isWildcard":false,"domain":"container-lab.it.su.se","includeWWW":false}]',
        "domainsString": '[{"isWildcard":false,"domain":"container-lab.it.su.se","includeWWW":false}',
        "duration":1,
        "csr": csr_string,
        "consentSameKey": True,
        "isManualCSR": True,
        "transactionType": "OV",
        "organizationDN": org_id
        }
print("\n\n")
print("Data in outgoing request:\n")
print(json.dumps(order_data, indent=4))
response = h.post_with_formdata("/api/ServerCertificate/RequestServerCertificate", order_data)
print("Result:\n\n")
print(response)
#get_my_transactions = h.post("/api/ServerCertificate/GetMyTransactions")
#print(get_my_transactions.text)
