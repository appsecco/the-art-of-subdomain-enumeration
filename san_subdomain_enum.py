from __future__ import print_function


__author__ = "Bharath"
__version__ = "0.1.0"
__description__ = "A script to extract sub-domains from Subject Alternate Name(SAN) in X.509 certs"

import sys
import re
import ssl

try:
    import OpenSSL as openssl
except ImportError:
    raise ImportError('pyopenssl library missing. pip install pyopenssl')
    sys.exit(1)

def get_domain_name():
    if len(sys.argv) <= 1:
        print("\n\033[33mUsage: python san_enum.py <target_domain>\033[1;m\n")
        sys.exit(1)
    else:
        return sys.argv[1]

def get_cert(domain_name):
    cert = ssl.get_server_certificate((domain_name, 443))
    return cert

def get_san(cert):
    x509 = openssl.crypto.load_certificate(openssl.crypto.FILETYPE_PEM, cert)
    domain_list = []
    for i in range(0, x509.get_extension_count()):
        ext = x509.get_extension(i)
        if "subjectAltName" in str(ext.get_short_name()):
                content = ext.__str__()
                for d in content.split(","):
                    domain_list.append(d.strip()[4:])
    return domain_list

def print_domains(domain_list):
    if len(domain_list) > 1:
        for domain in domain_list:
            print(domain)
    else:
        print("[!] No domains found using Subject Alternate Name(SAN)")

if __name__ == '__main__':
    domain_name = get_domain_name()
    cert = get_cert(domain_name)
    domain_list = get_san(cert)
    print_domains(domain_list)
