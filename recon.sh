#!/usr/bin/env bash
set -o errtrace

### Pretty colors!
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
RESET=$(tput sgr0)

### Catch random stray errors
trap 'echo "${RED}[-]${RESET} Error on line $LINENO (exit code $?)"' ERR 

### Check for 'seed file'
SEED="seed_domains.txt"
if [ ! -f "${SEED}" ]
then
    echo "${RED}[-]${RESET} ${SEED} does not exist. Create, add seed domains, and re-run."
    exit 1
fi

### Create some storage
echo "${GREEN}[+]${RESET} Creating storage for recon results"
mkdir -p recon
mkdir -p recon/subdomains
mkdir -p recon/urls
output_subdomains="recon/subdomains"
output_urls="recon/urls"

### Subdomain enumeration
## - subfinder to find initial list
## - httpx to find alive hosts, status codes, tech stack fingerprinting
echo "${GREEN}[+]${RESET} Subdomain Enumeration"

echo -e "\t${YELLOW}[>]${RESET} subfinder"
subfinder -dL "${SEED}" -silent | anew -q "${output_subdomains}/initial_subdomains.txt"

echo -e "\t${YELLOW}[>]${RESET} httpx"
httpx -status-code -title -tech-detect -list "${output_subdomains}/initial_subdomains.txt" -silent -json | jq '{url, status_code, tech, webserver, cdn, title}' > "${output_subdomains}/fingerprint.json"
cat "${output_subdomains}/fingerprint.json" | jq '.url' | cut -d "\"" -f2 | sort -u | anew -q "${output_subdomains}/live_subdomains.txt"

### Link enumeration
## - use found _live_ subdomains
## - fingerprint info can be used for more precise recon later
## - urlfinder, gau, jsfinder can all be used here (urls and js files separate)
echo "${GREEN}[+]${RESET} File/Link/JS Enumeration"

echo -e "\t${YELLOW}[>]${RESET} urlfinder, gau"
while read line
do 
    domain=$(echo "${line}" | cut -d "/" -f3)
    mkdir -p "${output_urls}/${domain}"
    urlfinder -d "${domain}" -silent | anew -q "${output_urls}/${domain}/urls.txt"
    echo "${domain}" | gau 2>/dev/null | anew -q "${output_urls}/${domain}/urls.txt"
done < "${output_subdomains}/live_subdomains.txt"

echo -e "\t${YELLOW}[>]${RESET} jsfinder"
cat "${output_subdomains}/live_subdomains.txt" | jsfinder -read -s -o "${output_urls}/javascript_files.txt"