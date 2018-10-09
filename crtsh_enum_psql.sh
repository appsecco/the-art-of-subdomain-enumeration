#!/bin/sh

# Script by Hanno Bock - https://github.com/hannob/tlshelpers/blob/master/getsubdomain

query="SELECT ci.NAME_VALUE NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE = 'dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.$1'));"

echo $query | \
    psql -t -h crt.sh -p 5432 -U guest certwatch | \
    sed -e 's:^ *::g' -e 's:^*\.::g' -e '/^$/d' | \
    sort -u | sed -e 's:*.::g'
