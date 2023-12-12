from .sucm_common import sucm_db

class SucmNotifyGroup:
    def __init__(self, group_id=None, group_name=None, email_csv=None):
        self.group_id = group_id
        self.group_name = group_name
        self.email_csv = email_csv

    def get_next_notifygroup_id(self):
        return sucm_db.get_next_available_id("NotifyGroup")

    def get_all_notifygroups(self):
        return sucm_db.get_records("NotifyGroup")

    def get_notifygroup_detail(self, group_id=None):
        if group_id is None:
            group_id = self.group_id
        return sucm_db.get_records("NotifyGroup", f"Group_Id = {group_id}")[0]

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
        sucm_db.remove_record("NotifyGroup", f"Group_Id = {group_id}")

    def get_all_certs_for_group_id(self, group_id=None):
        if group_id is None:
            group_id = self.group_id
        if group_id != 1000:
            result = sucm_db.get_records("Certificate", f"Notify_Group_Id = {group_id}")
            used_in = [sublist[2] for sublist in result]
            return used_in
        return ["The rest.."]
