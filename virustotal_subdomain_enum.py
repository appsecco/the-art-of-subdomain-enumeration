from __future__ import print_function


__author__ = "Bharath"
__version__ = "0.1.0"
__description__ = "A script to extract sub-domains that virus total \
                   has found for a given domain name"
import sys

try:
    from requests import get, exceptions
except ImportError:
    raise ImportError('requests library missing. pip install requests')
    sys.exit(1)

def get_domain():
    if len(sys.argv) <= 2:
        print("\n\033[33mUsage: python virustotal_enum.py <domain> <num_of_subdomains>\033[1;m\n")
        sys.exit(1)
    else:
        return sys.argv[1], int(sys.argv[2])

def check_virustotal(domain_name, limit):
    url = "https://www.virustotal.com/ui/domains/{0}/subdomains?limit={1}".format(domain_name, limit)
    print("URL being queried: {}".format(url))
    try:
        req = get(url)
    except exceptions.RequestException as e:  # This is the correct syntax
        print(e)
        sys.exit(1)
    response = get(url)
    return response.json()

def print_results(search_results):
    for index, item in enumerate(search_results['data']):
        print(item['id'])

if __name__ == '__main__':
    domain_name, limit = get_domain()
    if limit > 40:
      print("Limit cannot be over 40.")
      sys.exit(1)
    search_results = check_virustotal(domain_name, limit)
    print_results(search_results)
