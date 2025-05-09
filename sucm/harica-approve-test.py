import requests
import sys
import re
from requests_toolbelt.multipart.encoder import MultipartEncoder

# Configuration
email = "cert@it.su.se"
password = "your password"
url_base = "https://cm.harica.gr"

session = requests.Session()

def fetch_rvt():
    r = session.get(url_base)
    match = re.search(r'<input name="__RequestVerificationToken".*value="([^"]+)"', r.text)
    if not match:
        print("❌ Could not find RequestVerificationToken.")
        sys.exit(1)
    rvt = match.group(1)
    session.headers.update({"RequestVerificationToken": rvt})
    return rvt

def login(totp):
    fetch_rvt()
    login_data = {
        "email": email,
        "password": password,
        "token": totp
    }
    session.headers.update({"Content-Type": "application/json;charset=utf-8"})
    r = session.post(f"{url_base}/api/User/Login2FA", json=login_data)
    if not r.ok:
        print("❌ Login failed:", r.text)
        sys.exit(1)

    jwt_token = r.text.strip().strip('"')
    session.headers.update({"Authorization": jwt_token})
    fetch_rvt()
    print("✅ Login successful")

def list_pending_transactions():
    payload = {
        "startIndex": 0,
        "status": "Pending",
        "filterPostDTOs": []
    }

    r = session.post(f"{url_base}/api/OrganizationValidatorSSL/GetSSLReviewableTransactions", json=payload)
    if not r.ok:
        print("❌ Failed to get transactions:", r.status_code)
        print(r.text)
        sys.exit(1)

    data = r.json()
    if not data:
        print("✅ No pending transactions found.")
        return

    print(f"🔎 Found {len(data)} pending transaction(s):\n")
    for tx in data:
        txid = tx.get("transactionId")
        print(f"➡️ transactionId: {txid}")
        reviews = tx.get("reviewGetDTOs", [])
        for idx, rev in enumerate(reviews, start=1):
            status = "✅ reviewed" if rev.get("isReviewed") else "⏳ pending"
            print(f"   - Review {idx}: id={rev.get('reviewId')} value={rev.get('reviewValue')} → {status}")
        print("")

def approve_transaction(transaction_id):
    payload = {
        "startIndex": 0,
        "status": "Pending",
        "filterPostDTOs": []
    }

    r = session.post(f"{url_base}/api/OrganizationValidatorSSL/GetSSLReviewableTransactions", json=payload)
    if not r.ok:
        print("❌ Failed to fetch reviewable transactions.")
        sys.exit(1)

    transactions = r.json()
    tx = next((t for t in transactions if t.get("transactionId") == transaction_id), None)
    if not tx:
        print(f"❌ Transaction ID {transaction_id} not found.")
        sys.exit(1)

    print(f"\n🔎 Reviews for transaction {transaction_id}:\n")
    reviews = tx.get("reviewGetDTOs", [])
    if not reviews:
        print("❌ No reviews found.")
        sys.exit(1)

    approved_any = False
    for idx, review in enumerate(reviews, start=1):
        reviewed = review.get("isReviewed")
        rid = review.get("reviewId")
        rval = review.get("reviewValue")
        status = "✅ already approved" if reviewed else "⏳ will approve"
        print(f"   - Review {idx}: id={rid} value={rval} → {status}")

        if not reviewed and rid and rval:
            fields = {
                "reviewId": rid,
                "isValid": "true",
                "informApplicant": "true",
                "reviewMessage": "Approved via script",
                "reviewValue": rval
            }

            m = MultipartEncoder(fields=fields)
            session.headers["Content-Type"] = m.content_type

            r = session.post(
                f"{url_base}/api/OrganizationValidatorSSL/UpdateReviews",
                data=m
            )

            if r.ok:
                print(f"     ✅ Approved review {rid}")
                approved_any = True
            else:
                print(f"     ❌ Failed to approve review {rid}: {r.status_code}")
                print("     Body:", r.text)

    if approved_any:
        print(f"\n✅ Transaction {transaction_id} fully approved.")
    else:
        print("\n⚠️ No reviews were approved (maybe already approved?).")

# ---------- Main ----------
if len(sys.argv) < 3:
    print("Usage:")
    print("  python3 harica-approve-test.py list <TOTP>")
    print("  python3 harica-approve-test.py approve <TOTP> <transactionId>")
    sys.exit(1)

mode = sys.argv[1]
totp = sys.argv[2]

login(totp)

if mode == "list":
    list_pending_transactions()
elif mode == "approve":
    if len(sys.argv) != 4:
        print("Missing <transactionId>")
        sys.exit(1)
    transaction_id = sys.argv[3]
    approve_transaction(transaction_id)
else:
    print(f"Unknown mode: {mode}")
