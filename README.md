[![PyPI](https://img.shields.io/pypi/v/certbot-pkcs12)](https://pypi.org/project/certbot-pkcs12/)
[![codecov](https://codecov.io/gh/nasa-gcn/certbot-pkcs12/graph/badge.svg?token=13rI9YvWym)](https://codecov.io/gh/nasa-gcn/certbot-pkcs12)

# Certbot PKCS#12 plugin

This is an installer plugin for [certbot](https://certbot.eff.org). Whenever
you generate a certificate with Let's Encrypt, it will save the certificate
in a [PKCS#12](https://en.wikipedia.org/wiki/PKCS_12) archive.

## Usage

To use this plugin, first follow the
[instructions to install certbot](https://eff-certbot.readthedocs.io/en/stable/install.html#installation)
as well as this plugin and any other plugins that you need. For example, if you
are installing certbot with [pip](https://pip.pypa.io/), then run the following
command:

    pip install certbot certbot-dns-route53 certbot-pkcs12

Then, configure certbot by populating the configuration file
`/etc/letsencrypt/cli.ini`. Here is an example configuration for verifying
certificates using the [certbot plugin](https://certbot-dns-route53.readthedocs.io/)
for [AWS Route53](https://aws.amazon.com/route53/):

    # Example settings for cert verification using Route53
    dns-route53 = true
    domains = example.com
    email = admin@example.com
    agree-tos = true
    no-eff-email = true
    # PKCS12-specific settings
    installer = pkcs12
    pkcs12-location = /etc/pki/kafka/keystore.p12
    pkcs12-phassphrase = snakeoil

**Important note**: Some software, such as
[Apache Kafka](https://kafka.apache.org), cannot decode unencrypted PKCS12
files, so you should always set a PKCS12 passphrase, even if you are not using
the PKCS12 encryption as a security boundary.

Finally, run certbot by executing the following command:

    certbot
