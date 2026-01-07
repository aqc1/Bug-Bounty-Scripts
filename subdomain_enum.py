#!/usr/bin/env python3

import argparse
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    """ Result of running subprocess """
    name: str
    returncode: int
    stdout: str
    stderr: str

class SubdomainEnumeration:
    """ Class used for enumerating subdomains from targets via multiple passive sources
    Args:
        targets (list): List of targets from CLI args
    """
    def __init__(self, targets: list):
        self.targets = targets
        self.sources = [
            self.subfinder,
            self.amass,
            self.assetfinder
        ]
        self.base_folder = "subdomain_enumeration"
        self.folders = [
            f"{self.base_folder}/subfinder",
            f"{self.base_folder}/amass",
            f"{self.base_folder}/assetfinder"
        ]
        self.output_files = []

    def create_storage_structure(self):
        """ Create basic file structure for storing findings """
        base_path = Path(self.base_folder)
        if not base_path.exists():
            base_path.mkdir()
        for folder in self.folders:
            folder_path = Path(folder)
            if not folder_path.exists():
                folder_path.mkdir()

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


    def subfinder(self) -> CommandResult:
        """ Runs subfinder tool """
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".txt", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write("\n".join(self.targets) + "\n")

        try:
            output_file = "subdomain_enumeration/subfinder/output.txt"
            self.output_files.append(output_file)
            cmd = f"subfinder -dL {str(tmp_path)} -silent | anew -q {output_file}"
            result = self.run_command(
                name="subfinder",
                cmd=cmd
            )
        finally:
            tmp_path.unlink(missing_ok=True)

        return result
    

    def amass(self) -> CommandResult:
        """ Runs amass tool in its passive mode """
        output_file = "subdomain_enumeration/amass/output.txt"
        self.output_files.append(output_file)
        cmd = f"amass enum -d {','.join(self.targets)} -passive -silent | anew -q {output_file}"
        result = self.run_command(
            name="amass",
            cmd=cmd
        )

        return result
    

    def assetfinder(self) -> CommandResult:
        """ Iterates over targets and runs assetfinder tool against each """
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".txt", delete=False) as tmp:
            tmp_path = Path(tmp.name)
            tmp.write("\n".join(self.targets) + "\n")

        try:
            output_file = "subdomain_enumeration/assetfinder/output.txt"
            self.output_files.append(output_file)
            cmd = f"while read -r domain; do assetfinder -subs-only $domain | anew -q {output_file}; done < {str(tmp_path)}"
            result = self.run_command(
                name="assetfinder",
                cmd=cmd
            )
        finally:
            tmp_path.unlink(missing_ok=True)

        return result
        

    def aggregate_subdomains(self):
        """ Combines all the found subdomains into a singular file """
        # Check which output files exist
        existing_files = []
        for filepath in self.output_files:
            if Path(filepath).exists():
                existing_files.append(filepath)

        # Concat all output files, sort, throw into a file
        cmd = f"cat {' '.join(existing_files)} | sort -u | httpx | anew -q subdomain_enumeration/found_subdomains.txt"
        subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )


def parse_args() -> list:
    """ Parse CLI args (--target / --file) """
    parser = argparse.ArgumentParser(
        description="Tool to find subdomains for a bug bounty target."
    )

    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--target", "-t",
        metavar="TARGET",
        help="Single domain to enumerate."
    )
    mode.add_argument(
        "--file", "-f",
        metavar="FILE",
        help=(
            "File containing list of domains to enumerate."
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

    # Pass the targets to the enumeration class and prep file structure
    print("[+] Preparing file structure for subdomain enumeration")
    enum = SubdomainEnumeration(targets=targets)
    enum.create_storage_structure()

    # Concurrently fetch data from various sources
    print("[+] Enumerating subdomains")
    with ThreadPoolExecutor(max_workers=len(enum.sources)) as executor:
        future_map = {
            executor.submit(source): {
                "name": source.__name__,
                "func": source
            } 
            for source in enum.sources
        }
        for future in as_completed(future_map):
            name = future_map[future]['name']
            try:
                future.result()
                print(f"\t[\u2705] {name}")
            except Exception as e:
                print(f"\t[-] {name} failed: {e}")
    
    # Combine results
    print("[+] Aggregating results")
    enum.aggregate_subdomains()

if __name__ == "__main__":
    main()
