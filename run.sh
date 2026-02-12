#!/usr/bin/env bash

set -eou pipefail

### === Config ===
SEED_FILE="seed_domains.txt"
RECON_DIR="recon"

### === Colors ===
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

### === Verify beginning seed file ===
if [[ ! -f "${SEED_FILE}" ]]
then
    echo "${RED}[-]${RESET} Seed file '${SEED_FILE}' not found. Add domains to such file and re-run"
    exit 1
fi

### === Begin Recon ===
mkdir "${RECON_DIR}"
cd "${RECON_DIR}"

echo "${GREEN}[+]${RESET} Subdomain enumeration starting..."
python3 modules/subdomain_enum.py --file "${SEED_FILE}"

echo "${GREEN}[+]${RESET} IP mapping and enumeration starting..."
modules/subdomain_to_ip.sh "subdomain_enumeration/found_subdomains.txt"

echo "${GREEN}[+]${RESET} Port enumeration starting..."
python3 modules/port_scan.py --file "ip_list.txt"