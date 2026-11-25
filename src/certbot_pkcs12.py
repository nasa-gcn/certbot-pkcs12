"""Certbot PKCS#12 installer plugin."""

from certbot._internal.plugins.null import Installer as NullInstaller
from certbot.display import util as display_util
from certbot.interfaces import RenewDeployer
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    NoEncryption,
    load_pem_private_key,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates,
)
from cryptography.x509 import load_pem_x509_certificate


def _load_bytes(path):
    with open(path, "rb") as f:
        return f.read()


def _load_key(path):
    return load_pem_private_key(_load_bytes(path), password=None)


def _load_cert(path):
    return load_pem_x509_certificate(_load_bytes(path))


def _load_certs(path):
    delimiter = b"-----BEGIN CERTIFICATE-----\n"
    for section in _load_bytes(path).split(delimiter):
        section = section.strip()
        if section:
            yield load_pem_x509_certificate(delimiter + section)


class Installer(NullInstaller, RenewDeployer):
    """PKCS#12 installer."""

    description = "PKCS#12 installer plugin."

    @classmethod
    def add_parser_arguments(cls, add):
        add("location", help="Location of PKCS#12 archive.")
        add("passphrase", help="PKCS#12 archive passphrase.")

    def more_info(self):
        return "Install the key and certificate in a PKCS#12 archive."

    def deploy_cert(self, domain, cert_path, key_path, chain_path, fullchain_path):
        self._write_pkcs12(cert_path, key_path, chain_path)

    def renew_deploy(self, lineage, *args, **kwargs):
        self._write_pkcs12(lineage.cert_path, lineage.key_path, lineage.chain_path)

    def _write_pkcs12(self, cert_path, key_path, chain_path):
        passphrase = self.conf("passphrase")
        if passphrase is not None:
            passphrase = passphrase.encode()

        private_key = _load_key(key_path)
        certificate = _load_cert(cert_path)
        ca_certificates = _load_certs(chain_path)

        pkcs12_data = serialize_key_and_certificates(
            name=None,
            key=private_key,
            cert=certificate,
            cas=ca_certificates,
            encryption_algorithm=NoEncryption()
            if passphrase is None
            else BestAvailableEncryption(passphrase),
        )

        location = self.conf("location")
        with open(location, "wb") as f:
            f.write(pkcs12_data)
        display_util.notify(f"The PKCS#12 archive is stored at {location}.")
