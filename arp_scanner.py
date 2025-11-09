#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations
import argparse
import csv
import json
import os
import socket
import sys
import time
from dataclasses import dataclass, asdict
from typing import List, Optional

try:
    import scapy.all as scapy
except Exception as e:
    print("[-] Failed to import scapy. Install with: pip3 install scapy")
    print("    Error:", e)
    sys.exit(2)

try:
    # For pretty tables if available (optional)
    from tabulate import tabulate  # type: ignore
    _HAS_TABULATE = True
except Exception:
    _HAS_TABULATE = False

try:
    import requests
    _HAS_REQUESTS = True
except Exception:
    _HAS_REQUESTS = False

# ANSI color helpers
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_GREEN = "\033[1;32m"
C_YELLOW = "\033[1;33m"
C_RED = "\033[1;31m"
C_CYAN = "\033[1;36m"

BANNER = rf"""{C_CYAN}
 _____ _____   ___   _   _   _   _      _                      _    
/  ___/  __ \ / _ \ | \ | | | \ | |    | |                    | |   
\ `--.| /  \// /_\ \|  \| | |  \| | ___| |___      _____  _ __| | __
 `--. \ |    |  _  || . ` | | . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ /
/\__/ / \__/\| | | || |\  | | |\  |  __/ |_ \ V  V / (_) | |  |   < 
\____/ \____/\_| |_/\_| \_/ \_| \_/\___|\__| \_/\_/ \___/|_|  |_|\_\
                                                                                                                               
            Terminal ARP Scanner — fast, friendly, and extendable
                          Author : Safin Mohammad
{C_RESET}
"""

@dataclass
class HostEntry:
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    latency_ms: Optional[float] = None

def is_root() -> bool:
    if os.name == "nt":
        # Windows: can't easily check getuid; assume user must run as admin
        return True
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def reverse_dns(ip: str, timeout: float = 1.0) -> Optional[str]:
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except Exception:
        return None

def mac_vendor_lookup(mac: str) -> Optional[str]:
    if not _HAS_REQUESTS:
        return None
    # Use macvendors API (note: rate-limited, no guarantees)
    try:
        url = f"https://api.macvendors.com/{mac}"
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            return r.text.strip()
    except Exception:
        pass
    return None

def arp_scan(target: str, iface: Optional[str], timeout: float, resolve: bool, mac_vendor: bool, verbose: bool) -> List[HostEntry]:
    """
    Perform an ARP scan of the given target (IP or network like 192.168.1.0/24).
    Returns list of HostEntry.
    """
    print(f"{C_BOLD}[*]{C_RESET} Preparing ARP scan for: {target}")
    if iface:
        print(f"{C_BOLD}[*]{C_RESET} Using interface: {iface}")
    print(f"{C_BOLD}[*]{C_RESET} Timeout per request: {timeout}s\n")

    # Build packets
    try:
        arp = scapy.ARP(pdst=target)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
    except Exception as e:
        print(f"{C_RED}[-]{C_RESET} Failed to create ARP packet: {e}")
        return []

    # send and receive (srp returns (answered, unanswered))
    try:
        start = time.time()
        answered, unanswered = scapy.srp(packet, timeout=timeout, iface=iface, verbose=verbose)
        duration = time.time() - start
    except PermissionError:
        print(f"{C_RED}[-]{C_RESET} Permission denied. Try running as root / Administrator.")
        return []
    except Exception as e:
        print(f"{C_RED}[-]{C_RESET} Error while sending packets: {e}")
        return []

    hosts: List[HostEntry] = []
    for sent, received in answered:
        ip = received.psrc
        mac = received.hwsrc
        # scapy srp doesn't provide per-host latency directly; use sr1 for precise latency if needed
        hostname = reverse_dns(ip) if resolve else None
        vendor = None
        if mac_vendor:
            vendor = mac_vendor_lookup(mac)
        hosts.append(HostEntry(ip=ip, mac=mac, hostname=hostname, vendor=vendor, latency_ms=None))

    print(f"\n{C_GREEN}[+]{C_RESET} Scan completed in {duration:.2f}s — {len(hosts)} hosts found.\n")
    return hosts

def print_hosts(hosts: List[HostEntry]):
    if not hosts:
        print(f"{C_YELLOW}[!]{C_RESET} No hosts discovered.")
        return

    headers = ["IP", "MAC", "Hostname", "Vendor"]
    rows = []
    for h in hosts:
        rows.append([h.ip, h.mac, h.hostname or "-", h.vendor or "-"])

    if _HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="github"))
    else:
        # manual formatted table
        col_widths = [max(len(str(col)) for col in col_data) for col_data in zip(*([headers] + rows))]
        fmt = "  ".join("{:<" + str(w) + "}" for w in col_widths)
        print(fmt.format(*headers))
        print("-" * (sum(col_widths) + 2 * (len(col_widths) - 1)))
        for r in rows:
            print(fmt.format(*r))

def save_output(hosts: List[HostEntry], filename: str, fmt: str):
    fmt = fmt.lower()
    try:
        if fmt == "csv":
            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ip", "mac", "hostname", "vendor"])
                for h in hosts:
                    writer.writerow([h.ip, h.mac, h.hostname or "", h.vendor or ""])
            print(f"{C_GREEN}[+]{C_RESET} Saved CSV to {filename}")
        elif fmt == "json":
            with open(filename, "w", encoding="utf-8") as f:
                json.dump([asdict(h) for h in hosts], f, indent=2)
            print(f"{C_GREEN}[+]{C_RESET} Saved JSON to {filename}")
        else:
            print(f"{C_YELLOW}[!]{C_RESET} Unknown output format: {fmt} (supported: csv, json)")
    except Exception as e:
        print(f"{C_RED}[-]{C_RESET} Failed to save output: {e}")

def parse_args():
    p = argparse.ArgumentParser(prog="arp_scanner", description="ARP network scanner (Scapy).")
    p.add_argument("-t", "--target", required=True, help="Target IP or network (e.g. 192.168.1.1 or 192.168.1.0/24)")
    p.add_argument("-i", "--iface", help="Network interface to use (e.g. eth0). If omitted scapy chooses automatically.")
    p.add_argument("--timeout", type=float, default=2.0, help="Timeout (seconds) for responses (default: 2.0)")
    p.add_argument("--resolve", action="store_true", help="Perform reverse DNS lookups for discovered IPs")
    p.add_argument("--mac-vendor", action="store_true", help="Try to lookup MAC vendor (requires 'requests' and internet access)")
    p.add_argument("-o", "--output", help="Save results to file (use with --format)")
    p.add_argument("--format", choices=["csv", "json"], default="csv", help="Output file format (csv or json); default csv")
    p.add_argument("-q", "--quiet", action="store_true", help="Quiet mode: reduce informational output")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose scapy output")
    return p.parse_args()

def main():
    args = parse_args()

    print(BANNER)
    if not is_root():
        print(f"{C_YELLOW}[!]{C_RESET} Warning: running without root privileges may fail to send raw packets.")
        print(f"         On Unix systems run with sudo or as root. Continuing anyway...\n")

    if args.mac_vendor and not _HAS_REQUESTS:
        print(f"{C_YELLOW}[!]{C_RESET} MAC vendor lookup requested but 'requests' is not installed. Vendor lookup will be skipped.")
    if args.quiet:
        # silence scapy logging a bit
        scapy.conf.verb = 0

    try:
        hosts = arp_scan(target=args.target, iface=args.iface, timeout=args.timeout, resolve=args.resolve, mac_vendor=args.mac_vendor, verbose=args.verbose)
        if not args.quiet:
            print_hosts(hosts)
        if args.output:
            save_output(hosts, args.output, args.format)
    except KeyboardInterrupt:
        print(f"\n{C_RED}[-]{C_RESET} Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"{C_RED}[-]{C_RESET} Unexpected error: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
