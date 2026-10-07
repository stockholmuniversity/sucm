import re

from .sucm_common import sucm_db

# Pragmatic single-address shape check - deliberately stricter than full RFC
# 5322 (no display names, no quoted local parts, no comments). The point is to
# guarantee the stored CSV can never smuggle CR/LF or a second header into the
# To:/Subject headers when send_email() later splits and interpolates it.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def validate_email_csv(email_csv):
    """
    Validate a comma-separated notification recipient list.

    Returns the normalized CSV (single spaces stripped, lowercased) on success.
    Raises ValueError listing the offending entry if any address is empty or
    malformed - callers should surface this to the user and refuse to save.
    This is the injection guard for the mail headers, not just tidiness.
    """
    if email_csv is None:
        raise ValueError("email list is required")
    cleaned = []
    for entry in email_csv.split(","):
        addr = entry.strip()
        if not addr:
            raise ValueError("empty address in list")
        if not _EMAIL_RE.match(addr):
            raise ValueError(f"invalid email address: {addr!r}")
        cleaned.append(addr)
    if not cleaned:
        raise ValueError("email list is empty")
    return ",".join(cleaned)


class SucmNotifyGroup:
    def __init__(self, group_id=None, group_name=None, email_csv=None):
        self.group_id = group_id
        self.group_name = group_name
        self.email_csv = email_csv

    def get_next_notifygroup_id(self):
        return sucm_db.claim_next_id("NotifyGroup")

    def get_all_notifygroups(self):
        return sucm_db.get_records("NotifyGroup")

    def get_notifygroup_detail(self, group_id=None):
        if group_id is None:
            group_id = self.group_id
        return sucm_db.get_records("NotifyGroup", "Group_Id", group_id)[0]

    def add_update_notifygroup(self):
        group_data = {
            "Group_Id": self.group_id,
            "Group_Name": self.group_name,
            "Email_CSV": self.email_csv,
        }
        sucm_db.add_update_record("NotifyGroup", group_data)

    def delete_notifygroup(self, group_id=None):
        if group_id is None:
            group_id = self.group_id
        sucm_db.remove_record("NotifyGroup", "Group_Id", group_id)

    def get_all_certs_for_group_id(self, group_id=None):
        if group_id is None:
            group_id = self.group_id
        if group_id != 1000:
            result = sucm_db.get_records("Certificate", "Notify_Group_Id", group_id)
            used_in = [sublist[2] for sublist in result]
            return used_in
        return ["The rest.."]
