from abc import ABC, abstractmethod


class SucmCertificateAuthority(ABC):
    @abstractmethod
    def fetch_cert(self, csr_pem):
        """
        Returns a cert file in bytecode from the cert provider, expiry date, cert_chain
            cert_data = self.cert_authority.fetch_cert(self.csr)
            self.crt = cert_data[0]
            self.expiry_date = cert_data[1]
            self.fullchain = cert_data[2]
        """
        pass

    def revoke_cert(self, fullchain_pem):
        """
        Revokes the cert on the cert provider, it takes the fullchain_pem as input.
        """
        pass
