from abc import ABC, abstractmethod


class SucmCertificateAuthority(ABC):
    @abstractmethod
    def fetch_cert(self, csr_pem):
        pass

    def revoke_cert(self, fullchain_pem):
        pass
