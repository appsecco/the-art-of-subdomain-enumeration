from __future__ import print_function

__author__ = 'Bharath'
__version__ = "0.1.0"

try:
    import psycopg2
except ImportError:
    raise ImportError('\n\033[33mpsycopg2 library missing. pip install psycopg2\033[1;m\n')
    sys.exit(1)
import re
import sys

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

if __name__ == '__main__':
    domain_name = get_domain_name()
    cursor = connect_to_db(domain_name)
    unique_domains = get_unique_domains(cursor, domain_name)
    print_unique_domains(unique_domains)