"""Certbot PKCS#12 installer plugin."""
from certbot import interfaces
from certbot.display import util as display_util
from certbot.plugins import common
from OpenSSL import crypto


def _load_bytes(path):
    with open(path, 'rb') as f:
        return f.read()


def _load_key(path):
    return crypto.load_privatekey(crypto.FILETYPE_PEM, _load_bytes(path))


def _load_cert(path):
    return crypto.load_certificate(crypto.FILETYPE_PEM, _load_bytes(path))


def _load_certs(path):
    delimiter = b'-----BEGIN CERTIFICATE-----\n'
    for section in _load_bytes(path).split(delimiter):
        section = section.strip()
        if section:
            yield crypto.load_certificate(
                crypto.FILETYPE_PEM, delimiter + section)


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
        password = self.conf('password')
        if password is not None:
            password = password.encode()

        pkcs12 = crypto.PKCS12()
        pkcs12.set_key(_load_key(key_path))
        pkcs12.set_certificate(_load_cert(cert_path))
        pkcs12.set_ca_certificates(_load_certs(chain_path))
        out_bytes = pkcs12.export(password=password)

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
