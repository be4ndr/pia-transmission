The public PIA CA and MIT license come from pia-foss/manual-connections,
revision `645377e87238a52596c004f760d238e3faea68d1`:

https://github.com/pia-foss/manual-connections/tree/645377e87238a52596c004f760d238e3faea68d1

`ca.crt` is extracted from `openvpn_config/strong.ovpn`. Its SHA-256 certificate
fingerprint is `1FD25658456EAB3041FBA77CCD398AB8124EDCC1B8B2FC1D55FDF6B1BBFC9D70`.
The generated client config also verifies the server role and exact CN from the
HTTPS-fetched PIA server inventory; the CA alone is not the identity check.
