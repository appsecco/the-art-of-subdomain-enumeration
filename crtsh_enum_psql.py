from __future__ import print_function

__author__ = 'Bharath'
__version__ = "0.1.0"

try:
    import psycopg2
except ImportError:
    raise ImportError('\n\033[33mpsycopg2 library missing. pip install psycopg2\033[1;m\n')
    sys.exit(1)
try:
    import click
except ImportError:
    raise ImportError('\n\033[33mpsycopg2 library missing. pip install click\033[1;m\n')
    sys.exit(1)
import re
import sys
import json
from socket import gethostbyname, gaierror

DB_HOST = 'crt.sh'
DB_NAME = 'certwatch'
DB_USER = 'guest'

def connect_to_db(domain_name):
    try:
        conn = psycopg2.connect("dbname={0} user={1} host={2}".format(DB_NAME, DB_USER, DB_HOST))
        cursor = conn.cursor()
        cursor.execute("SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%{}'));".format(domain_name))
    except:
        print("\n\033[1;31m[!] Unable to connect to the database\n\033[1;m")
    return cursor

def get_unique_domains(cursor, domain_name):
    unique_domains = []
    for result in cursor.fetchall():
        matches=re.findall(r"\'(.+?)\'",str(result))
        for subdomain in matches:
            if subdomain not in unique_domains:
                if ".{}".format(domain_name) in subdomain:
                    unique_domains.append(subdomain)
    return unique_domains

def print_unique_domains(unique_domains):
    for unique_domain in sorted(unique_domains):
        print(unique_domain)

def get_domain_name():
    if len(sys.argv) <= 1:
        print("\n\033[33mUsage: python crtsh_enum_psql.py <target_domain>\033[1;m\n")
        sys.exit(1)
    else:
        return sys.argv[1]

def do_dns_resolution(unique_domains):
    dns_resolution_results = {}
    for domain in set(unique_domains):
        domain = domain.replace('*.','')
        try:
            ip_address = gethostbyname(domain)
            dns_resolution_results[domain] = ip_address
            #print("\033[92m{0:<50} - {1:20}\033[1;m".format(domain,ip_address.rstrip("\n\r")))
        except gaierror as e:
            #print("\033[93m{0:<50} - {1:20}\033[1;m".format(domain,"No A record exists",end=''))
            dns_resolution_results[domain] = "No A record exists"
            #print(e.message)
    return dns_resolution_results

@click.command()
@click.argument('domain')
@click.option('--resolve/--no-resolve','-r', default=False,
                help='Enable/Disable DNS resolution')
@click.option('--output','-o',
                help='Output in JSON format')
def main(domain, resolve, output):
    domain_name = domain
    cursor = connect_to_db(domain_name)
    unique_domains = get_unique_domains(cursor, domain_name)
    if resolve == False:
        for domain in unique_domains:
            print(domain)
        sys.exit()
    else:
        dns_resolution_results = do_dns_resolution(unique_domains)

    if output=='json':
        print(json.dumps(dns_resolution_results))
    else:
        for domain,ip_address in dns_resolution_results.iteritems():
            if ip_address == "No A record exists":
                print("\033[93m{0:<50} - {1:20}\033[1;m".format(domain,ip_address.rstrip("\n\r")))
            else:
                print("\033[92m{0:<50} - {1:20}\033[1;m".format(domain,ip_address.rstrip("\n\r")))

if __name__ == '__main__':
    main()