# Certbot PKCS#12 plugin

This is an installer plugin for [certbot](https://certbot.eff.org). Whenever
you generate a certificate with Let's Encrypt, it will save the certificate
in a [PKCS#12](https://en.wikipedia.org/wiki/PKCS_12) archive.

# Example

## Installing PKCS#12
`certbot install -i pkcs12 --pkcs12-location /etc/locationToPlaceFile.ptx`

## Intergrating with other commands
`certbot some_options --installer pkcs12 --pkcs12-location /path/to/your/pkcs12.pfx`

This probably save your option in configuration files and will be applied in renewal
:

`certbot renew # auto install due to previous options`