import os
from unittest import mock

import certbot.tests.util as test_util
import pytest
from certbot._internal import constants, storage, updater
from certbot.main import main
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)
from cryptography.x509 import load_pem_x509_certificate

from certbot_pkcs12 import Installer


class Pkcs12Test(test_util.ConfigTestCase):
    passphrase = None

    @mock.patch("certbot_pkcs12.display_util.notify")
    def test_install(self, mock_notify):
        self.config.pkcs12_passphrase = self.passphrase
        self.config.pkcs12_location = os.path.join(
            self.config.config_dir, "keystore.p12"
        )
        testfile = "sample-renewal.conf"
        lineage_name = testfile[: -len(".conf")]
        test_util.make_lineage(self.config.config_dir, testfile, ec=False)
        live_path = os.path.join(
            self.config.config_dir, constants.LIVE_DIR, lineage_name
        )
        installer = Installer(self.config, "pkcs12")

        assert (
            "Install the key and certificate in a PKCS#12 archive"
            in installer.more_info()
        )

        installer.deploy_cert(
            None,
            os.path.join(live_path, "cert.pem"),
            os.path.join(live_path, "privkey.pem"),
            os.path.join(live_path, "chain.pem"),
            os.path.join(live_path, "fullchain.pem"),
        )
        mock_notify.assert_called_once_with(
            f"The PKCS#12 archive is stored at {self.config.pkcs12_location}."
        )

        with open(self.config.pkcs12_location, "rb") as f:
            load_key_and_certificates(
                f.read(),
                password=None if self.passphrase is None else self.passphrase.encode(),
            )

    @mock.patch("certbot_pkcs12.display_util.notify")
    def test_renew_replaces_existing_archive(self, mock_notify):
        self.config.pkcs12_passphrase = self.passphrase
        self.config.pkcs12_location = os.path.join(
            self.config.config_dir, "keystore.p12"
        )
        self.config.dry_run = False
        self.config.disable_renew_updates = False
        renewal_conf = test_util.make_lineage(
            self.config.config_dir, "sample-renewal.conf", ec=False
        )
        lineage = storage.RenewableCert(renewal_conf, self.config)
        with open(self.config.pkcs12_location, "wb") as f:
            f.write(b"old archive")

        installer = Installer(self.config, "pkcs12")
        updater.run_renewal_deployer(self.config, lineage, installer)

        with open(self.config.pkcs12_location, "rb") as f:
            key, cert, chain = load_key_and_certificates(
                f.read(),
                password=None if self.passphrase is None else self.passphrase.encode(),
            )
        with open(lineage.cert_path, "rb") as f:
            self.assertEqual(cert, load_pem_x509_certificate(f.read()))
        self.assertIsNotNone(key)
        self.assertTrue(chain)
        mock_notify.assert_called_once_with(
            f"The PKCS#12 archive is stored at {self.config.pkcs12_location}."
        )


class Pkcs12PassphraseTest(Pkcs12Test):
    passphrase = "snakeoil"


def test_help(capsys):
    with pytest.raises(SystemExit):
        main(["--help", "pkcs12"])
    captured = capsys.readouterr().out
    for arg in ["location", "passphrase"]:
        assert f"--pkcs12-{arg}" in captured
