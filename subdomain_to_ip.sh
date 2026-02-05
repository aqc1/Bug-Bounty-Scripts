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

    ips=$(dig +short "${subdomain}" 2>/dev/null)
    [[ -z "${ips}" ]] && continue

    while read -r ip
    do
        echo "${subdomain} ${ip}" >> "subdomain_ip_mapping.txt"
    done <<< "${ips}"
done < "${INPUT}"