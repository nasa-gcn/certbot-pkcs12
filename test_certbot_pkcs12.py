import os
from unittest import mock

import certbot.tests.util as test_util
from certbot._internal import constants
from certbot_pkcs12 import Installer
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

class Pkcs12Test(test_util.ConfigTestCase):

    @mock.patch("certbot_pkcs12.display_util.notify")
    def test_install(self, mock_notify):
        self.config.pkcs12_passphrase = None
        self.config.pkcs12_location = os.path.join(self.config.config_dir, "keystore.p12")
        testfile = 'sample-renewal.conf'
        lineage_name = testfile[:-len('.conf')]
        test_util.make_lineage(self.config.config_dir, testfile, ec=False)
        live_path = os.path.join(self.config.config_dir, constants.LIVE_DIR, lineage_name)
        Installer(self.config, 'pkcs12').deploy_cert(None, os.path.join(live_path, 'cert.pem'), os.path.join(live_path, 'privkey.pem'), os.path.join(live_path, 'chain.pem'), os.path.join(live_path, 'fullchain.pem'))
        mock_notify.assert_called_once_with(f'The PKCS#12 archive is stored at {self.config.pkcs12_location}.')

        with open(self.config.pkcs12_location, 'rb') as f:
            load_key_and_certificates(f.read(), password=None)
