# Bug-Bounty-Scripts
A place to store my scripts, code, templates, etc. for bug bounty purposes

## What the scripts do
* `subdomain_enum.py`: This is a decent starting point after a target(s) is decided. Attempts to passively scrape data sources for possible subdomains. Sources used below:
  * subfinder
  * amass
  * assetfinder
* `subdomain_to_ip.sh`: Takes a list of subdomains and writes a mapping of the domains to their IPs/
* `port_scan.py`: After subdomain enumeration this script is useful for mapping ports and services to found subdomains. Mainly uses Nmap to first perform an initial scan, then if interesting ports are found, performs a more intensive scan.

## What order to run scripts
1) subdomain_enum.py
2) subdomain_to_ip.sh
3) port_scan.py