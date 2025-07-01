import os
from unittest import mock

import certbot.tests.util as test_util
import pytest
from certbot._internal import constants
from certbot.main import main
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
)

from certbot_pkcs12 import Installer


class Pkcs12Test(test_util.ConfigTestCase):
    @mock.patch("certbot_pkcs12.display_util.notify")
    def test_install(self, mock_notify):
        self.config.pkcs12_passphrase = None
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
            load_key_and_certificates(f.read(), password=None)


def test_help(capsys):
    with pytest.raises(SystemExit):
        main(["--help", "pkcs12"])
    captured = capsys.readouterr().out
    for arg in ["location", "passphrase"]:
        assert f"--pkcs12-{arg}" in captured
