# Bug-Bounty-Scripts
A place to store my scripts, code, templates, etc. for bug bounty purposes

## What the scripts do
* `modules/subdomain_enum.py`: This is a decent starting point after a target(s) is decided. Attempts to passively scrape data sources for possible subdomains. Sources used below:
  * subfinder
  * amass
  * assetfinder
* `modules/subdomain_to_ip.sh`: Takes a list of subdomains and writes a mapping of the domains to their IPs.
* `modules/port_scan.py`: After subdomain enumeration this script is useful for mapping ports and services to found subdomains. Mainly uses Nmap to first perform an initial scan, then if interesting ports are found, performs a more intensive scan.