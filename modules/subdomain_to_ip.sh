#!/usr/bin/env bash

# Where to read; where to write
INPUT="$1"

# Verify inputs
if [[ -z "${INPUT}" || ! -f "${INPUT}" ]]
then
    echo "Usage: $0 <Input File>"
    exit 1
fi

# DNS resolution
while read -r subdomain
do
    # Strip protocol prefix
    subdomain="${subdomain#http://}"
    subdomain="${subdomain#https://}"
    subdomain="${subdomain%/}"
    [[ -z "${subdomain}" ]] && continue

    dig -4 +short "${subdomain}" 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | while read -r ip
    do
        echo "${subdomain} ${ip}" | anew -q "subdomain_ip_mapping.txt"
        echo "${ip}" | anew -q "ip_list.txt"
    done
done < "${INPUT}"

# ipinfo API
mkdir ip_enumeration
while read -r ip
do
    curl -s "http://ipinfo.io/${ip}" | anew -q "ip_enumeration/${ip}.txt"
done < "ip_list.txt"