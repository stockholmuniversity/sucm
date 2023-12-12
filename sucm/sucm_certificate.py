import importlib
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import NoEncryption
from cryptography.x509.oid import NameOID

from .sucm_certificateauthority import SucmCertificateAuthority
from .sucm_common import send_email, sucm_db, sucm_secret
from .sucm_notifygroup import SucmNotifyGroup


class SucmCertificate:
    def __init__(self, cert_id=None, cert_conf=None):
        if cert_conf is None:
            cert_conf = {
                "common_name": None,
                "certificate_authority_id": None,
                "country": None,
                "state": None,
                "city": None,
                "organisation": None,
                "subject_alt": None,
                "cert_type": None,
                "notify_group": None,
                "status": None,
                "secret_path": None,
            }

        self.cert_id = cert_id
        self.certificate_authority_id = cert_conf["certificate_authority_id"]
        self.common_name = cert_conf["common_name"]
        self.country = cert_conf["country"]
        self.state = cert_conf["state"]
        self.city = cert_conf["city"]
        self.organisation = cert_conf["organisation"]
        self.subject_alt = cert_conf["subject_alt"]
        self.cert_type = cert_conf["cert_type"]
        self.notify_group = cert_conf["notify_group"]
        self.status = cert_conf["status"]
        self.secret_path = cert_conf["secret_path"]

        # Certificate Authority
        self.cert_authority = None

        # Need to run create or fetch method to populate these.
        self.key = None, None
        self.csr = None
        self.crt = None
        self.cachain = None
        self.fullchain = None

        # Need to run get method on existing cert to populate these.
        self.create_date = None
        self.expiry_date = None

        self.cert_operation = "add"
        cert_details = self.get_certificate_detail()

        if cert_details:
            self.cert_operation = "edit"
            self.set_current_class_values_from_db()

        if self.common_name:
            # Vault
            self.key_filename = self.common_name + ".key"
            self.csr_filename = self.common_name + ".csr"
            self.crt_filename = self.common_name + ".pem"
            self.cachain_filename = self.common_name + "-cachain.crt"
            self.fullchain_filename = self.common_name + ".fullchain"

    def set_current_class_values_from_db(self):
        cert_data = sucm_db.get_records("Certificate", f"Cert_Id = {self.cert_id}")[0]
        attrs = {
            "certificate_authority_id": 1,
            "common_name": 2,
            "subject_alt": 3,
            "country": 4,
            "state": 5,
            "city": 6,
            "organisation": 7,
            "status": 8,
            "cert_type": 9,
            "secret_path": 10,
            "notify_group": 11,
            "create_date": 12,
            "expiry_date": 13,
        }

        for attr, index in attrs.items():
            if getattr(self, attr) is None:
                setattr(self, attr, cert_data[index])

    def _load_certificate_authority(self):
        # Get the plugin class name from the database
        ca_detail = self.get_certificate_authority_detail(self.certificate_authority_id)
        plugin_class_name = f"{ca_detail[1]}_{ca_detail[2]}"

        # Import the plugin module (filename is lowercase)
        plugin_module_name = plugin_class_name.lower()
        plugin_module = importlib.import_module(
            f"lib.sucm.plugins.{plugin_module_name}"
        )

        # Fetch the class from the module (class name is in its original case)
        plugin_class = getattr(plugin_module, plugin_class_name)

        # Check if the class is a subclass of SucmCertificateAuthority
        if not issubclass(plugin_class, SucmCertificateAuthority):
            raise TypeError(
                f"{plugin_class_name} is not a valid certificate authority plugin"
            )

        self.cert_authority = plugin_class()

    @staticmethod
    def _create_active_cert_dict(data):
        details = {
            "active_cert_id": data[0],
            "cert_id": data[1],
            "common_name": data[2],
            "cert_pem": data[3],
            "create_date": data[4],
            "expiry_date": data[5],
        }
        return details

    @staticmethod
    def _create_cert_dict(data):
        details = {
            "cert_id": data[0],
            "certificate_authority_id": data[1],
            "common_name": data[2],
            "subject_alt": data[3],
            "country": data[4],
            "state": data[5],
            "city": data[6],
            "organisation": data[7],
            "status": data[8],
            "cert_type": data[9],
            "secret_path": data[10],
            "notify_group": data[11],
            "create_date": data[12],
            "expiry_date": data[13],
        }
        return details

    def get_all_active_certs(self, cert_id=None):
        if cert_id is None:
            all_data = sucm_db.get_records("ActiveCertificate")
        else:
            all_data = sucm_db.get_records("ActiveCertificate", f"Cert_Id = {cert_id}")
        data_list = []
        for data in all_data:
            details = self._create_active_cert_dict(data)
            data_list.append(details)
        return data_list

    def delete_active_cert(self, active_cert_id):
        sucm_db.remove_record(
            "ActiveCertificate", f"ActiveCertificate_Id = {active_cert_id}"
        )

    def get_active_cert_detail(self, active_cert_id):
        data = sucm_db.get_records(
            "ActiveCertificate", f"ActiveCertificate_Id = {active_cert_id}"
        )[0]
        details = self._create_active_cert_dict(data)
        return details

    def get_active_cert_ssl_data(self, active_cert_id):
        pem_data = self.get_active_cert_detail(active_cert_id)["cert_pem"]
        cert = x509.load_pem_x509_certificate(pem_data.encode(), default_backend())

        # Parse details from certificate
        details = {
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "serial_number": cert.serial_number,
            "not_valid_before": cert.not_valid_before,
            "not_valid_after": cert.not_valid_after,
            "public_key": cert.public_key()
            .public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode(),
            "key_size": cert.public_key().key_size,
        }
        return details

    def get_all_certificate(self):
        all_data = sucm_db.get_records("Certificate")
        data_list = []
        for data in all_data:
            details = self._create_cert_dict(data)
            data_list.append(details)
        return data_list

    def get_certificate_detail(self, cert_id=None):
        if cert_id is None:
            cert_id = self.cert_id
        data = sucm_db.get_records("Certificate", f"Cert_Id = {cert_id}")[0]
        details = self._create_cert_dict(data)
        return details

    def get_common_name(self, common_name):
        common_name = f'"{common_name}"'
        data = sucm_db.get_records("Certificate", f"Common_Name = {common_name}")
        details = self._create_cert_dict(data)
        return details

    def get_renewable_certs(self, days_until_expiry="30"):
        all_data = sucm_db.get_records(
            "Certificate",
            f"DATE(Expiry_Date) < (NOW() + INTERVAL {days_until_expiry} DAY)",
        )
        data_list = []
        for data in all_data:
            details = self._create_cert_dict(data)
            data_list.append(details)
        return data_list

    def get_expired_certs(self):
        all_data = sucm_db.get_records(
            "ActiveCertificate", "DATE(Expiry_Date) < CURDATE()"
        )
        data_list = []
        for data in all_data:
            details = self._create_cert_dict(data)
            data_list.append(details)
        return data_list

    def get_next_cert_id(self):
        return sucm_db.get_next_available_id("Certificate")

    def delete_cert(self, cert_id=None):
        if cert_id is None:
            cert_id = self.cert_id
        sucm_db.remove_record("Certificate", f"Cert_Id = {cert_id}")

    def _fetch_csr(self):
        secret_backend = sucm_secret
        secret_backend.secret_path = self.secret_path
        self.csr = secret_backend.read_secret(self.csr_filename)

    def commit_changes_to_db(self):
        if self.status is None:
            self.status = "New"
        cert_data = {
            "Cert_Id": self.cert_id,
            "CA_Id": self.certificate_authority_id,
            "Common_Name": self.common_name,
            "Subject_alt": self.subject_alt,
            "Country": self.country,
            "State": self.state,
            "City": self.city,
            "Org": self.organisation,
            "Status": self.status,
            "Type": self.cert_type,
            "Secret_Path": self.secret_path,
            "Notify_Group_Id": self.notify_group,
            "Create_Date": self.create_date,
            "Expiry_Date": self.expiry_date,
        }
        sucm_db.add_update_record("Certificate", cert_data)

    def commit_fullchain_to_db(self):
        active_cert_id = sucm_db.get_next_available_id("ActiveCertificate")
        active_cert_data = {
            "ActiveCertificate_Id": active_cert_id,
            "Cert_Id": self.cert_id,
            "Common_Name": self.common_name,
            "Cert_PEM": self.fullchain,
            "Create_Date": self.create_date,
            "Expiry_Date": self.expiry_date,
        }
        sucm_db.add_update_record("ActiveCertificate", active_cert_data)

    def commit_changes_to_vault(self):
        secret_backend = sucm_secret
        secret_backend.secret_path = self.secret_path

        if self.key is not None and self.key != (None, None):
            secret_backend.modify_or_create_secret(self.key_filename, self.key)
        if self.csr is not None:
            secret_backend.modify_or_create_secret(self.csr_filename, self.csr)
        if self.crt is not None:
            secret_backend.modify_or_create_secret(self.crt_filename, self.crt)
        if self.cachain is not None:
            secret_backend.modify_or_create_secret(self.cachain_filename, self.cachain)

    def create_new_key_and_csr(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        key_text = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=NoEncryption(),
        )
        self.key = key_text.decode("utf-8")

        if self.subject_alt:
            san_list = [
                x509.DNSName(f"{san.replace(' ', '')}")
                for san in self.subject_alt.split(",")
            ]

            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name(
                        [
                            x509.NameAttribute(NameOID.COUNTRY_NAME, f"{self.country}"),
                            x509.NameAttribute(
                                NameOID.STATE_OR_PROVINCE_NAME, f"{self.state}"
                            ),
                            x509.NameAttribute(NameOID.LOCALITY_NAME, f"{self.city}"),
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, f"{self.organisation}"
                            ),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, f"{self.common_name}"
                            ),
                        ]
                    )
                )
                .add_extension(
                    x509.SubjectAlternativeName(san_list),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )
        else:
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(
                    x509.Name(
                        [
                            x509.NameAttribute(NameOID.COUNTRY_NAME, f"{self.country}"),
                            x509.NameAttribute(
                                NameOID.STATE_OR_PROVINCE_NAME, f"{self.state}"
                            ),
                            x509.NameAttribute(NameOID.LOCALITY_NAME, f"{self.city}"),
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, f"{self.organisation}"
                            ),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, f"{self.common_name}"
                            ),
                        ]
                    )
                )
                .sign(key, hashes.SHA256())
            )
        self.csr = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        self.status = "New CSR"
        self.commit_changes_to_vault()
        self.commit_changes_to_db()

    def submit_manual_csr(self, csr=None):
        if csr is None:
            csr = self.csr
        self.csr = csr
        self.status = "New CSR"
        self.commit_changes_to_vault()
        self.commit_changes_to_db()

    def revoke_cert(self, active_cert_id):
        fullchain = self.get_active_cert_detail(active_cert_id)[3]
        self._load_certificate_authority()
        self.cert_authority.revoke_cert(fullchain)
        self.delete_active_cert(active_cert_id)

    @staticmethod
    def _split_pem_chain(pem_chain):
        """
        Splits a PEM chain into individual PEM certificates.
        """
        pem_certificates = []
        current_cert = []
        for line in pem_chain.splitlines():
            if line.startswith("-----BEGIN CERTIFICATE-----"):
                current_cert = [line]
            elif line.startswith("-----END CERTIFICATE-----"):
                current_cert.append(line)
                pem_certificates.append("\n".join(current_cert))
                current_cert = []
            else:
                current_cert.append(line)
        return pem_certificates

    def renew_cert_with_csr(self):
        if self.status == "New CSR":
            self._fetch_csr()

            self._load_certificate_authority()
            cert_data = self.cert_authority.fetch_cert(self.csr)

            self.crt = cert_data[0]
            self.expiry_date = cert_data[1]
            self.fullchain = cert_data[2]

            # create a cachain from the fullchain
            fullchain_certs = self._split_pem_chain(self.fullchain)
            #            cachain_split = fullchain_certs[1:]
            #            cachain_bytes = b"\n".join(c.encode() for c in cachain_split)
            #            self.cachain = cachain_bytes.decode("utf-8")
            self.cachain = fullchain_certs[1] if fullchain_certs else None

            self.create_date = datetime.today()
            self.status = "Renewed CRT"
            self.commit_changes_to_vault()
            self.commit_changes_to_db()
            self.commit_fullchain_to_db()
            secret_backend = sucm_secret
            secret_backend.secret_path = self.secret_path
            secret_backend.remove_secret(self.csr_filename)
            if self.cert_type == "Manual":
                email_addresses = SucmNotifyGroup().get_notifygroup_detail(
                    group_id=self.notify_group
                )[2]
                for email in email_addresses.replace(" ", "").split(","):
                    try:
                        send_email(
                            f"Renewed cert for {self.common_name}",
                            f"Cert for {self.common_name} has been renewed in SUCM and stored in secrets.",
                            email,
                        )
                    except Exception as e:
                        print(f"Failed to send email to {email}: {str(e)}")

    def get_certificate_authority_detail(self, certificate_authority_id=None):
        return sucm_db.get_records(
            "CertificateAuthority", f"CA_Id = {certificate_authority_id}"
        )[0]

    def get_all_certificate_authority(self):
        return sucm_db.get_records("CertificateAuthority")
