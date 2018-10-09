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
    import censys.ipv4
except ImportError:
    logging.info("\033[1;31m[!] Failed to import censys module. Run 'pip install censys'\033[1;m")
    sys.exit()

def get_certificates():
    try:
        if not CENSYS_API_ID or not CENSYS_API_SECRET:
            logging.info("\033[1;31m[!] API KEY or Secret for Censys not provided.\033[1;m" \
                        "\nYou'll have to provide them in the script") 
            sys.exit()
        logging.info("[+] Extracting certificates for {} using Censys".format(domain))
        censys_certificates = censys.certificates.CensysCertificates(CENSYS_API_ID, CENSYS_API_SECRET)
        return censys_certificates
    except censys.base.CensysUnauthorizedException:
        logging.info('[!] Your Censys credentials look invalid.\n')
        exit(1)
    except censys.base.CensysRateLimitExceededException:
        logging.info('[!] Looks like you exceeded your Censys account limits rate. Exiting\n')
        exit(1)

def get_subdomains(domain, certificates):
    logging.info("[+] Extracting sub-domains for {} from certificates".format(domain))
    subdomains = []
    certificate_query = 'parsed.names: {}'.format(domain)
    certificates_search_results = certificates.search(certificate_query, fields=['parsed.names'])
    for search_result in certificates_search_results:
        subdomains.extend(search_result['parsed.names'])
    return set(subdomains)

def print_subdomains(subdomains, domain):
    unique_subdomains = []
    if len(subdomains) is 0:
        logging.info('[!] Did not find any subdomains')
        return
    for subdomain in subdomains:
        if '*' not in subdomain and subdomain.endswith(domain): 
            unique_subdomains.append(subdomain)
    logging.info("\033[1;32m[+] Total unique subdomains found: {}\033[1;m".format(len(unique_subdomains)))
    for subdomain in sorted(unique_subdomains):
        print(subdomain)

def get_domain():
    if len(sys.argv) < 2:
        print("\n[!] Usage: python subdomain_enum_censys.py <target_domain>\n")
        sys.exit()
    else:
        domain = sys.argv[1]
        return domain

if __name__ == '__main__':
    domain = get_domain()
    certificates = get_certificates()
    subdomains = get_subdomains(domain, certificates)
    print_subdomains(subdomains, domain)
