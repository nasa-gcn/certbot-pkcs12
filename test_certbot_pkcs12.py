import os
from unittest import mock

import certbot.tests.util as test_util
import pytest
from certbot._internal import storage, updater
from certbot.main import main
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)
from cryptography.x509 import load_pem_x509_certificate

from certbot_pkcs12 import Installer


class Pkcs12Test(test_util.ConfigTestCase):
    passphrase = None

    def setUp(self):
        super().setUp()
        self.config.pkcs12_passphrase = self.passphrase
        self.config.pkcs12_location = os.path.join(
            self.config.config_dir, "keystore.p12"
        )
        renewal_conf = test_util.make_lineage(
            self.config.config_dir, "sample-renewal.conf", ec=False
        )
        self.lineage = storage.RenewableCert(renewal_conf, self.config)
        self.installer = Installer(self.config, "pkcs12")

    def _assert_archive_written(self, mock_notify):
        with open(self.config.pkcs12_location, "rb") as f:
            key, cert, chain = load_key_and_certificates(
                f.read(),
                password=None if self.passphrase is None else self.passphrase.encode(),
            )
        with open(self.lineage.cert_path, "rb") as f:
            self.assertEqual(cert, load_pem_x509_certificate(f.read()))
        self.assertIsNotNone(key)
        self.assertTrue(chain)
        mock_notify.assert_called_once_with(
            f"The PKCS#12 archive is stored at {self.config.pkcs12_location}."
        )

    @mock.patch("certbot_pkcs12.display_util.notify")
    def test_install(self, mock_notify):
        assert (
            "Install the key and certificate in a PKCS#12 archive"
            in self.installer.more_info()
        )

        self.installer.deploy_cert(
            None,
            self.lineage.cert_path,
            self.lineage.key_path,
            self.lineage.chain_path,
            self.lineage.fullchain_path,
        )

        self._assert_archive_written(mock_notify)

    @mock.patch("certbot_pkcs12.display_util.notify")
    def test_renew_replaces_existing_archive(self, mock_notify):
        self.config.dry_run = False
        self.config.disable_renew_updates = False
        with open(self.config.pkcs12_location, "wb") as f:
            f.write(b"old archive")

        updater.run_renewal_deployer(self.config, self.lineage, self.installer)

        self._assert_archive_written(mock_notify)


class Pkcs12PassphraseTest(Pkcs12Test):
    passphrase = "snakeoil"


def test_help(capsys):
    with pytest.raises(SystemExit):
        main(["--help", "pkcs12"])
    captured = capsys.readouterr().out
    for arg in ["location", "passphrase"]:
        assert f"--pkcs12-{arg}" in captured
