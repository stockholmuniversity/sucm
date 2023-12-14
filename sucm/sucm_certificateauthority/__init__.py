from abc import ABC, abstractmethod


class SucmCertificateAuthority(ABC):
    @abstractmethod
    def fetch_cert(self, csr_pem):
        """
        Returns a cert file in bytecode from the cert provider
        """
        pass

    def revoke_cert(self, fullchain_pem):
        """
        Revokes the cert on the cert provider
        """
        pass
