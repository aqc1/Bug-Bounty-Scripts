#!/usr/bin/env python3

import argparse
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


# Global constants
## ports may duplicate between categories - more for visual organization
INTERESTING_PORTS = {
    "web": [80, 81, 443, 3000, 3001, 5000, 8000, 8080, 8081, 8443, 8888, 9000],
    "database": [1433, 1521, 3306, 5432, 6379, 27017, 9200],
    "cloud": [2375, 2376, 6443, 10250],
    "cms": [2082, 2083, 2222, 7001, 7002],
    "ci/cd": [8080, 9000, 7990, 3000],
    "version control": [9418, 3690],
    "debug": [5005, 9222, 5858]
}
UNIQ_PORTS = sorted({str(port) for ports in INTERESTING_PORTS.values() for port in ports})
SCAN_TEMPLATES = {
    "web": "http-title,http-headers,http-methods,http-enum",
    "database": "mysql-info,mongodb-info,redis-info",
    "cloud": "docker-info,kubernetes-info",
    "debug": "banner"
}

@dataclass
class CommandResult:
    """ Result of running subprocess """
    name: str
    returncode: int
    stdout: str
    stderr: str

class NmapScanner:
    """ Class used to scan ports from subdomains via Nmap
    Args:
        targets (list): List of targets from CLI args
    """
    def __init__(self, targets: list):
        self.targets = targets
        self.base_folder = "port_enumeration"
        self.folders = [
            f"{self.base_folder}/quick_scan",
            f"{self.base_folder}/intensive_scan"
        ]
        self.interesting_hosts = []

    def run_command(self,name: str, cmd: str) -> CommandResult:
        """ Command runner """
        completed = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        return CommandResult(
            name=name,
            returncode=completed.returncode,
            stdout=completed.stdout.strip(),
            stderr=completed.stderr.strip()
        )
    
    def create_storage_structure(self):
        """ Create basic file structure for storing findings """
        base_path = Path(self.base_folder)
        if not base_path.exists():
            base_path.mkdir()
        for folder in self.folders:
            folder_path = Path(folder)
            if not folder_path.exists():
                folder_path.mkdir()
    
    def quick_scan(self) -> CommandResult:
        """ Perform initial scan to get an idea of open ports """
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".txt", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write("\n".join(self.targets) + "\n")

        try:
            output_file_name = "port_enumeration/quick_scan/scan"
            cmd = f"nmap -Pn -iL {str(tmp_path)} -T4 --top-ports 1000 -n --open -oA {output_file_name}"
            result = self.run_command(
                name="quick scan",
                cmd=cmd
            )
        finally:
            tmp_path.unlink(missing_ok=True)

        # Extract ports found
        results = {}
        with open(f"{output_file_name}.gnmap") as handle:
            for line in handle:
                if "Ports" not in line:
                    continue
                host_match = re.search(r"Host:\s+(\S+)", line)
                if not host_match:
                    continue
                host = host_match.group(1)
                ports_section = line.split("Ports:")[1]
                ports = []
                for entry in ports_section.split(","):
                    parts = entry.strip().split("/")
                    if len(parts) > 1 and parts[1] == "open":
                        ports.append(parts[0])
                    if ports:
                        results[host] = ports
        
        # Check for interesting ports
        for host, ports in results.items():
            if bool(set(ports) & set (UNIQ_PORTS)):
                self.interesting_hosts.append({
                    "host": host,
                    "interesting_ports": sorted(set(ports) & set (UNIQ_PORTS))
                })

        return result
    
    def intensive_scan(self, host: dict) -> CommandResult:
        output_file_name = f"port_enumeration/intensive_scan/{host['host']}.nmap"
        template_list = []
        for tech in SCAN_TEMPLATES.keys():
            if bool(set(host['interesting_ports']) & set([str(port) for port in INTERESTING_PORTS[tech]])):
                template_list.append(SCAN_TEMPLATES[tech])
        scripts = ",".join(template_list) if template_list else "default"
        cmd = f"nmap -Pn -sV -sC --script={scripts} -p {','.join(host['interesting_ports'])} {host['host']} -oN {output_file_name}"
        result = self.run_command(
            name=f"intensive scan - {host['host']}",
            cmd=cmd
        )
        
        return result


def parse_args() -> list:
    """ Parse CLI args (--target / --file) """
    parser = argparse.ArgumentParser(
        description="Tool to map network ports given subdomains"
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--target", "-t",
        metavar="TARGET",
        help="Single subdomain to scan."
    )
    mode.add_argument(
        "--file", "-f",
        metavar="FILE",
        help=(
            "File containing list of subdomains to scan."
            "Use '-' to read from stdin."
        )
    )

    targets = None
    args = parser.parse_args()
    # --target TARGET
    if args.target:
        targets = [args.target]
    else:
        # --file -
        if args.file == "-":
            targets = [line.strip() for line in sys.stdin if line.strip()]
        # --file FILE
        else:
            try:
                with open(args.file, "r") as handle:
                    targets = [line.strip() for line in handle if line.strip()]
            except OSError as e:
                parser.error(f"Could not read file '{args.file}': {e}")
                sys.exit(1)
    return targets


def main():
    # Fetch targets based on CLI flags
    print("[+] Parsing CLI arguments")
    targets = parse_args()

    # Pass the targets to the scanning class and prep file structure
    print("[+] Preparing file structure for port scanning")
    scanner = NmapScanner(targets=targets)
    scanner.create_storage_structure()

    # Port scanning
    print("[+] Performing initial quick scan")
    scanner.quick_scan()
    if len(scanner.interesting_hosts) == 0:
        print("[+] No interesting hosts found - quick scan is sufficient")
    else:
        print("[+] Performing intensive scan on interesting hosts")
        for host in scanner.interesting_hosts:
            scanner.intensive_scan(host=host)


if __name__ == "__main__":
    main()
