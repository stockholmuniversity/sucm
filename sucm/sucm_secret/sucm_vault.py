import hvac

from . import SucmSecret
from ..sucm_settings import cfg, sys_logger

vault_config = {
    "vault_addr": cfg.get("hvac", "vault_addr"),
    "mount_point": cfg.get("hvac", "mount_point"),
    "role_id": cfg.get("hvac", "role_id"),
    "secret_id": cfg.get("hvac", "secret_id"),
}


class SuVault(SucmSecret):
    def __init__(self, secret_path="SUCMTEST/test/ssl/"):
        self.secret_path = secret_path
        self.mount_point = vault_config["mount_point"]
        self.vault_addr = vault_config["vault_addr"]
        self.vault_token = None

    def init_vault(self):
        try:
            self.client = hvac.Client(url=self.vault_addr, token=self.vault_token)
            if not self.vault_token:
                self.login = self.client.auth.approle.login(
                    role_id=vault_config["role_id"], secret_id=vault_config["secret_id"]
                )
                self.vault_token = self.login["auth"]["client_token"]

            sys_logger.info("SucmVault instance successfully initialized.")
        except Exception as e:
            sys_logger.error("Failed to initialize SucmVault: %s", e)

    def get_all_paths(self):
        try:
            self.init_vault()
            servicepaths = self.client.adapter.request(
                "GET", "v1/secret/vaulttoolsecrets?list=true"
            )["data"]["keys"]
            allpaths = []
            environments = ["prod", "test", "dev", "edu", "lab", "ci"]
            for servicepath in servicepaths:
                for env in environments:
                    allpaths.append(f"secret/vaulttoolsecrets/{servicepath}{env}/ssl/")

            editable_paths = self.list_modifiable_paths(allpaths)
            usable_paths = [
                path.replace("secret/vaulttoolsecrets/", "", 1)
                for path in editable_paths
            ]
            return usable_paths
        except Exception as e:
            sys_logger.error("Error in get_all_paths: %s", e)
            return []

    def list_modifiable_paths(self, paths):
        modifiable_paths = []
        try:
            for path in paths:
                data = {"path": path}
                response = self.client.adapter.post(
                    "/v1/sys/capabilities-self", json=data
                )

                if "update" in response["data"]["capabilities"]:
                    modifiable_paths.append(path)

            return modifiable_paths
        except Exception as e:
            sys_logger.error("Error in list_modifiable_paths: %s", e)
            return []

    def read_secret(self, file_name):
        try:
            self.init_vault()
            secret = self.client.secrets.kv.v1.read_secret(
                path=self.secret_path + file_name, mount_point=self.mount_point
            )
            b = secret["data"]["binaryData"]
            secret_string = bytearray(b).decode("utf8")
            return secret_string
        except Exception as e:
            sys_logger.error("Error reading secret from vault: %s", e)
            return None

    def modify_or_create_secret(self, file_name, file_data):
        try:
            self.init_vault()
            file_content = {"pwd": "", "userName": ""}
            bytestream = bytearray(file_data.encode("utf-8"))
            b = [int(x) for x in bytestream]
            file_content["binaryData"] = b
            file_content["key"] = self.secret_path + file_name

            self.client.secrets.kv.v1.create_or_update_secret(
                path=self.secret_path + file_name,
                mount_point=self.mount_point,
                secret=file_content,
            )
            sys_logger.info("Secret %s modified or created in Vault.", file_name)
        except Exception as e:
            sys_logger.error("Error in modify_or_create_secret: %s", e)

    def remove_secret(self, file_name):
        try:
            self.init_vault()
            self.client.secrets.kv.v1.delete_secret(
                path=self.secret_path + file_name, mount_point=self.mount_point
            )
            sys_logger.info("Secret for file %s removed successfully.", file_name)
        except Exception as e:
            sys_logger.error("Failed to remove secret for file %s: %s", file_name, e)
