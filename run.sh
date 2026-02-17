#!/usr/bin/env bash

set -eou pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" > /dev/null 2>&1 && pwd)"

### === Config ===
RECON_DIR="recon"

### === Colors ===
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

### === Verify beginning seed file ===
if [[ $# -lt 1 ]]
then
    echo "Usage: ${0} <seed_file>"
    exit 1
fi 

if [[ ! -f "$(realpath ${1})" ]]
then
    echo "${RED}[-]${RESET} Seed file not found."
    exit 1
fi
SEED_FILE="$(realpath ${1})"

### === Begin Recon ===
mkdir -p "${RECON_DIR}"
cd "${RECON_DIR}"

# amass skipped - takes too long
echo "${GREEN}[+]${RESET} Subdomain enumeration starting..."
python3 "${SCRIPT_DIR}/modules/subdomain_enum.py" --file "${SEED_FILE}"

# found_subdomains.txt created by previous module
echo "${GREEN}[+]${RESET} IP mapping and enumeration starting..."
bash "${SCRIPT_DIR}/modules/subdomain_to_ip.sh" "subdomain_enumeration/found_subdomains.txt"

# ip_list.txt created by previous module
echo "${GREEN}[+]${RESET} Port enumeration starting..."
python3 "${SCRIPT_DIR}/modules/port_scan.py" --file "ip_list.txt"