# A script to extract domain names from related SSL/TLS certificates using Censys
# You'll need Censys API ID and API Secret to be able to extract SSL/TLS certificates
# Needs censys module to run. pip install censys.

from __future__ import print_function

import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
    )

__author__  = "Bharath(github.com/yamakira)"
__version__ = "0.1"
__purpose__ = "Extract subdomains for a domain from censys certificate dataset"

CENSYS_API_ID = ""
CENSYS_API_SECRET = ""

import argparse
import re
import sys

try:
    import censys.certificates
except ImportError:
    logging.info("\033[1;31m[!] Failed to import censys module. Run 'pip install censys'\033[1;m")
    sys.exit()

def get_certificates(domain):
    if not CENSYS_API_ID or not CENSYS_API_SECRET:
        logging.info("\033[1;31m[!] API KEY or Secret for Censys not provided.\033[1;m" \
                     "\nYou'll have to provide them in the script") 
        sys.exit()
    logging.info("[+] Extracting certificates for {} using Censys".format(domain))
    c = censys.certificates.CensysCertificates(CENSYS_API_ID, CENSYS_API_SECRET)
    search_results = c.paged_search(domain)
    certificates = search_results['results']
    if len(certificates) == 0:
        print("\033[1;31m[!] No matching certificates found!\033[1;m")
        sys.exit()
    return certificates

def get_subdomains(domain, certificates):
    logging.info("[+] Extracting sub-domains for {} from certificates".format(domain))
    subdomains = []
    for certificate in certificates:
        parsed_result = re.findall(r'(?<=CN=).*', certificate[u'parsed.subject_dn'])
        if len(parsed_result) > 0 and domain in parsed_result[0]: subdomains.append(parsed_result[0])
    return subdomains

def print_subdomains(subdomains):
    unique_subdomains = list(set(subdomains))
    print("\033[1;32m[+] Total unique subdomains found: {}\033[1;m".format(len(unique_subdomains)))
    print("[+] List of subdomains extracted:\n")
    for sub_domain in unique_subdomains:
        print(sub_domain)

def get_domain():
    if len(sys.argv) < 2:
        print("\n[!] Usage: python subdomain_enum_censys.py <target_domain>\n")
        sys.exit()
    else:
        domain = sys.argv[1]
        return domain

if __name__ == '__main__':
    domain = get_domain()
    certificates = get_certificates(domain)
    subdomains = get_subdomains(domain, certificates)
    print_subdomains(subdomains)
