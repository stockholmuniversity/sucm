import josepy as jose
import OpenSSL
from acme import client, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from ..sucm_settings import cfg, sys_logger
from . import SucmCertificateAuthority

CA_PLUGIN_NAME = "HARICA_EAB"
harica_eab_config = {
    "eab_directory": cfg.get(CA_PLUGIN_NAME, "directory"),
    "eab_kid": cfg.get(CA_PLUGIN_NAME, "kid"),
    "eab_hmac": cfg.get(CA_PLUGIN_NAME, "hmac"),
    "eab_user_agent": cfg.get(CA_PLUGIN_NAME, "user_agent"),
    "eab_email": cfg.get(CA_PLUGIN_NAME, "email"),
    "eab_account_pw": cfg.get(CA_PLUGIN_NAME, "account_key_pw"),
}


class Harica_EAB(SucmCertificateAuthority):
    def __init__(self):
        self.eab_directory = harica_eab_config["eab_directory"]
        self.eab_kid = harica_eab_config["eab_kid"]
        self.eab_hmac = harica_eab_config["eab_hmac"]
        self.eab_user_agent = harica_eab_config["eab_user_agent"]
        self.eab_email = harica_eab_config["eab_email"]
        self.eab_account_pw = harica_eab_config["eab_account_pw"]

        with open("/local/cert-app/HARICA_EAB_account_key.pem", "rb") as key_file:
            acc_key_rsa = serialization.load_pem_private_key(
                key_file.read(),
                password=self.eab_account_pw.encode("utf-8"),
            )

        acc_key = jose.JWKRSA(key=acc_key_rsa)
        net = client.ClientNetwork(acc_key, user_agent=self.eab_user_agent)
        directory = messages.Directory.from_json(net.get(self.eab_directory).json())
        eab = messages.ExternalAccountBinding.from_data(
            account_public_key=acc_key,
            kid=self.eab_kid,
            hmac_key=self.eab_hmac,
            directory=directory,
        )

        self.client_acme = client.ClientV2(directory, net)

        try:
            regr = self.client_acme.new_account(
                messages.NewRegistration.from_data(
                    email=self.eab_email,
                    external_account_binding=eab,
                    terms_of_service_agreed=True,
                ),
            )
        except:
            regr = messages.RegistrationResource(
                body=messages.Registration(
                    contact=self.eab_email,
                    agreement=True,
                    external_account_binding=eab,
                )
            )

            self.client_acme.net.account = regr
            regr = self.client_acme.query_registration(regr)

    def fetch_cert(self, csr_pem):
        try:
            orderr = self.client_acme.new_order(csr_pem)
            response = self.client_acme.poll_and_finalize(orderr)
            expiry_date = response["body"]["expires"]
            fullchain_pem = response["fullchain_pem"]
            certs = x509.load_pem_x509_certificates(str.encode(fullchain_pem))
            cert = certs[0].public_bytes(encoding=serialization.Encoding.PEM)
            cert_pem = cert.decode("utf-8")
            sys_logger.info("Certificate fetched successfully.")
            return [cert_pem, expiry_date, fullchain_pem]
        except Exception as e:
            sys_logger.error(f"Error fetching certificate: {e}")
            return []

    def revoke_cert(self, fullchain_pem):
        try:
            fullchain_com = jose.ComparableX509(
                OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_PEM,
                    fullchain_pem,
                )
            )
            self.client_acme.revoke(fullchain_com, 0)
            sys_logger.info("Certificate revoked successfully.")
        except Exception as e:
            sys_logger.error(f"Error revoking certificate: {e}")
