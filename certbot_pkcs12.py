"""Certbot PKCS#12 installer plugin."""
from certbot import interfaces
from certbot.display import util as display_util
from certbot.plugins import common
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    serialize_key_and_certificates)
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, load_pem_private_key, NoEncryption)


def _load_bytes(path):
    with open(path, 'rb') as f:
        return f.read()


def _load_key(path):
    return load_pem_private_key(_load_bytes(path), password=None)


def _load_certs(path):
    delimiter = b'-----BEGIN CERTIFICATE-----\n'
    for section in _load_bytes(path).split(delimiter):
        section = section.strip()
        if section:
            yield load_pem_x509_certificate(delimiter + section)


class Installer(common.Plugin, interfaces.Installer):
    """PKCS#12 installer."""

    description = "PKCS#12 installer plugin."

    @classmethod
    def add_parser_arguments(cls, add):
        add("location", help="Location of PKCS#12 archive.")
        add("password", help="PKCS#12 archive password.")

    def prepare(self):
        pass

    def more_info(self):
        return 'Install the key and certificate in a PKCS#12 archive.'

    def get_all_names(self):
        return []

    def deploy_cert(self, domain, cert_path, key_path,
                    chain_path, fullchain_path):
        key = _load_key(key_path)
        cert, = _load_certs(cert_path)
        chain = _load_certs(chain_path)
        password = self.conf('password')

        if password is None:
            encryption = NoEncryption()
        else:
            encryption = BestAvailableEncryption(password.encode())

        out_bytes = serialize_key_and_certificates(
            domain.encode(), key, cert, chain, encryption)

        location = self.conf('location')
        with open(location, 'wb') as f:
            f.write(out_bytes)
        display_util.notify(f'The PKCS#12 archive is stored at {location}.')

    def enhance(self, domain, enhancement, options=None):
        pass

    def supported_enhancements(self):
        return []

    def save(self, title=None, temporary=False):
        pass

    def rollback_checkpoints(self, rollback=1):
        pass

    def recovery_routine(self):
        pass

    def config_test(self):
        pass

    def restart(self):
        pass
