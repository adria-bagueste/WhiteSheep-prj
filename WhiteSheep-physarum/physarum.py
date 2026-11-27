#!/usr/bin/env python3
"""
BlackSheep-physarum: a small network analyser for auditing your own networks.

Commands
  sweep    Find live hosts in an IP range (Angry IP Scanner style).
  analyse  Run a soft nmap service scan on hosts and flag risky open ports.
  scan     sweep + analyse in one go.

Only scan networks you own or are authorised to test.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import ipaddress
import os
import json
import platform
import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

VERSION = "0.1.0"

# Ports probed during the sweep to detect hosts that block ping.
DEFAULT_PROBE_PORTS = [22, 80, 443, 445, 139, 3389, 8080, 53, 21, 23]

# Ports worth a closer look when found open, with the reason.
RISKY_PORTS = {
    21: ("high", "FTP sends credentials in clear text"),
    23: ("high", "Telnet sends everything in clear text"),
    69: ("high", "TFTP has no authentication"),
    111: ("medium", "RPCbind exposes RPC service map"),
    135: ("medium", "MS RPC endpoint mapper"),
    137: ("medium", "NetBIOS name service"),
    139: ("medium", "NetBIOS/SMBv1 session service"),
    161: ("medium", "SNMP, often default community strings"),
    445: ("high", "SMB file sharing, frequent exploit target"),
    1433: ("high", "MS SQL Server exposed"),
    1900: ("medium", "UPnP/SSDP discovery"),
    2049: ("high", "NFS share exposed"),
    2375: ("high", "Docker API without TLS"),
    3306: ("high", "MySQL/MariaDB exposed"),
    3389: ("high", "RDP exposed, brute force target"),
    5432: ("high", "PostgreSQL exposed"),
    5900: ("high", "VNC remote desktop exposed"),
    5985: ("medium", "WinRM over HTTP"),
    6379: ("high", "Redis, often no authentication"),
    8080: ("low", "Alternative HTTP, often admin panels"),
    9200: ("high", "Elasticsearch, often no authentication"),
    11211: ("high", "Memcached exposed"),
    27017: ("high", "MongoDB, often no authentication"),
}
CLEARTEXT_SERVICES = {"ftp", "telnet", "http", "pop3", "imap", "snmp", "vnc", "tftp"}

IS_WINDOWS = platform.system().lower() == "windows"
USE_COLOR = sys.stdout.isatty()


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


SEV_COLOR = {"high": "31", "medium": "33", "low": "36", "info": "2"}


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #
def parse_targets(spec: str) -> list[str]:
    """Accept '192.168.1.0/24', '192.168.1.10-50', '192.168.1.10-192.168.1.50',
    a single IP, or a comma separated mix of these."""
    out: list[str] = []
    for part in (p.strip() for p in spec.split(",") if p.strip()):
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts()) or [net.network_address]
            out.extend(str(h) for h in hosts)
        elif "-" in part:
            start_s, end_s = part.split("-", 1)
            start = ipaddress.ip_address(start_s)
            if "." in end_s or ":" in end_s:
                end = ipaddress.ip_address(end_s)
            else:  # short form: 192.168.1.10-50
                prefix = start_s.rsplit(".", 1)[0]
                end = ipaddress.ip_address(f"{prefix}.{end_s}")
            if int(end) < int(start):
                raise ValueError(f"range end before start: {part}")
            out.extend(str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1))
        else:
            out.append(str(ipaddress.ip_address(part)))
    # keep order, drop duplicates
    return list(dict.fromkeys(out))


def parse_ports(spec: str) -> list[int]:
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return ports


# --------------------------------------------------------------------------- #
# Part 1: sweep (Angry IP Scanner style)
# --------------------------------------------------------------------------- #
def ping(ip: str, timeout: float) -> float | None:
    """Return round trip in ms if the host answers ICMP echo, else None."""
    if not shutil.which("ping"):
        return None
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    elif platform.system().lower() == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(round(timeout)))), ip]
    start = dt.datetime.now()
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                           timeout=timeout + 2,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (subprocess.TimeoutExpired, OSError):
        return None
    out = r.stdout.decode(errors="ignore").lower()
    # Windows returns 0 for "destination host unreachable" replies, so check TTL.
    if r.returncode == 0 and "ttl" in out:
        return round((dt.datetime.now() - start).total_seconds() * 1000, 1)
    return None


def tcp_probe(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except ConnectionRefusedError:
        # A refusal (RST) still proves the host is up; caller treats it as alive.
        raise
    except OSError:
        return False


def probe_host(ip: str, ports: list[int], timeout: float, use_ping: bool) -> dict | None:
    rtt = ping(ip, timeout) if use_ping else None
    open_ports: list[int] = []
    refused = False
    for p in ports:
        try:
            if tcp_probe(ip, p, timeout):
                open_ports.append(p)
        except ConnectionRefusedError:
            refused = True
    if rtt is None and not open_ports and not refused:
        return None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        hostname = ""
    how = "ping" if rtt is not None else ("tcp" if open_ports else "tcp-rst")
    return {"ip": ip, "hostname": hostname, "ping_ms": rtt,
            "open_ports": open_ports, "detected_by": how}


def sweep(targets: list[str], ports: list[int], timeout: float, workers: int,
          use_ping: bool, quiet: bool = False) -> list[dict]:
    alive: list[dict] = []
    total = len(targets)
    done = 0
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe_host, ip, ports, timeout, use_ping): ip for ip in targets}
        for fut in cf.as_completed(futs):
            done += 1
            res = fut.result()
            if res:
                alive.append(res)
                if not quiet:
                    print(f"\r  {c('UP', '32')}  {res['ip']:<16} {res['hostname'][:40]}"
                          + " " * 10)
            if not quiet and sys.stderr.isatty():
                print(f"\r  scanned {done}/{total}", end="", file=sys.stderr, flush=True)
    if not quiet and sys.stderr.isatty():
        print("\r" + " " * 30 + "\r", end="", file=sys.stderr)
    alive.sort(key=lambda h: ipaddress.ip_address(h["ip"]))
    return alive


def print_sweep_table(hosts: list[dict]) -> None:
    print()
    print(c(f"{'IP':<16} {'HOSTNAME':<32} {'PING':>8}  {'VIA':<8} OPEN (probe)", "1"))
    for h in hosts:
        ping_s = f"{h['ping_ms']}ms" if h["ping_ms"] is not None else "-"
        ports = ",".join(map(str, h["open_ports"])) or "-"
        print(f"{h['ip']:<16} {h['hostname'][:32]:<32} {ping_s:>8}  {h['detected_by']:<8} {ports}")
    print(f"\n{len(hosts)} host(s) alive")


# --------------------------------------------------------------------------- #
# Part 2: analyse (nmap)
# --------------------------------------------------------------------------- #
NMAP_PROFILES = {
    # soft: polite timing, top 1000 TCP ports, light version detection
    "soft": ["-sV", "--version-light", "-T3", "--top-ports", "1000", "--open"],
    # quick: top 100 ports, no version detection
    "quick": ["-T4", "--top-ports", "100", "--open"],
    # deep: all TCP ports, default safe scripts, OS guess (slow; OS guess needs admin)
    "deep": ["-sV", "-sC", "-T3", "-p-", "--open"],
}


def find_nmap() -> str | None:
    path = shutil.which("nmap")
    if path:
        return path
    if IS_WINDOWS:
        for cand in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
            if os.path.exists(cand):
                return cand
    return None


def run_nmap(nmap: str, ip: str, profile: str, extra: list[str]) -> str:
    cmd = [nmap, *NMAP_PROFILES[profile], *extra, "-oX", "-", ip]
    r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if r.returncode != 0 and not r.stdout:
        raise RuntimeError(r.stderr.decode(errors="ignore").strip() or "nmap failed")
    return r.stdout.decode(errors="ignore")


def parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts = []
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            addr = host.find("address")
        mac = host.find("address[@addrtype='mac']")
        status = host.find("status")
        hn = host.find("hostnames/hostname")
        ports = []
        for p in host.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": svc.get("name", "") if svc is not None else "",
                "product": " ".join(filter(None, [
                    svc.get("product", "") if svc is not None else "",
                    svc.get("version", "") if svc is not None else "",
                    svc.get("extrainfo", "") if svc is not None else "",
                ])),
                "tunnel": svc.get("tunnel", "") if svc is not None else "",
            })
        os_match = host.find("os/osmatch")
        hosts.append({
            "ip": addr.get("addr") if addr is not None else "",
            "mac": mac.get("addr") if mac is not None else "",
            "vendor": mac.get("vendor", "") if mac is not None else "",
            "state": status.get("state") if status is not None else "",
            "hostname": hn.get("name") if hn is not None else "",
            "os": os_match.get("name") if os_match is not None else "",
            "ports": ports,
        })
    return hosts


def assess(host: dict) -> list[dict]:
    """Attach findings to open ports based on simple rules."""
    findings = []
    for p in host["ports"]:
        sev, why = "info", "open port"
        if p["port"] in RISKY_PORTS:
            sev, why = RISKY_PORTS[p["port"]]
        elif p["service"] in CLEARTEXT_SERVICES and p["tunnel"] != "ssl":
            sev, why = "medium", f"{p['service']} is unencrypted"
        if p["service"] == "http" and p["tunnel"] != "ssl" and sev == "info":
            sev, why = "low", "plain HTTP, check for admin interfaces"
        findings.append({**p, "severity": sev, "note": why})
    return findings


def analyse(ips: list[str], profile: str, extra: list[str], workers: int) -> list[dict]:
    nmap = find_nmap()
    if not nmap:
        sys.exit("nmap not found. Install it from https://nmap.org/download.html "
                 "and make sure it is on PATH.")
    results = []

    def one(ip: str) -> dict:
        try:
            hosts = parse_nmap_xml(run_nmap(nmap, ip, profile, extra))
            h = hosts[0] if hosts else {"ip": ip, "state": "down", "ports": [],
                                        "hostname": "", "mac": "", "vendor": "", "os": ""}
            h["findings"] = assess(h)
        except Exception as e:  # keep going on per-host errors
            h = {"ip": ip, "error": str(e), "ports": [], "findings": []}
        return h

    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        for i, h in enumerate(pool.map(one, ips), 1):
            print(f"  [{i}/{len(ips)}] analysed {h['ip']}", file=sys.stderr)
            results.append(h)
    return results


def print_analysis(results: list[dict]) -> None:
    counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
    for h in results:
        title = h["ip"] + (f"  ({h['hostname']})" if h.get("hostname") else "")
        if h.get("vendor"):
            title += f"  [{h['vendor']}]"
        print("\n" + c(title, "1"))
        if h.get("error"):
            print("  " + c(f"error: {h['error']}", "31"))
            continue
        if not h["findings"]:
            print("  no open ports found")
            continue
        for f in h["findings"]:
            counts[f["severity"]] += 1
            sev = c(f"{f['severity'].upper():<6}", SEV_COLOR[f["severity"]])
            port = f"{f['port']}/{f['proto']}"
            print(f"  {sev} {port:<10} {f['service']:<14} {f['product'][:38]:<38} {f['note']}")
    print("\n" + c("Summary", "1") + ": " + ", ".join(
        c(f"{n} {k}", SEV_COLOR[k]) for k, n in counts.items()))


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def save_json(path: str, kind: str, data: list[dict]) -> None:
    doc = {"tool": "blacksheep-physarum", "version": VERSION, "kind": kind,
           "generated": dt.datetime.now().isoformat(timespec="seconds"), "results": data}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
    print(f"saved {path}", file=sys.stderr)


def load_ips(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        doc = json.load(fh)
    return [h["ip"] for h in doc.get("results", doc)]


def cmd_sweep(a) -> list[dict]:
    targets = parse_targets(a.range)
    print(f"Sweeping {len(targets)} address(es) with {a.workers} workers...", file=sys.stderr)
    hosts = sweep(targets, parse_ports(a.ports), a.timeout, a.workers, not a.no_ping)
    print_sweep_table(hosts)
    if a.output:
        save_json(a.output, "sweep", hosts)
    return hosts


def cmd_analyse(a, ips: list[str] | None = None) -> None:
    if ips is None:
        ips = load_ips(a.input) if a.input else parse_targets(",".join(a.targets))
    if not ips:
        sys.exit("no hosts to analyse")
    extra = a.nmap_args.split() if a.nmap_args else []
    print(f"Analysing {len(ips)} host(s) with nmap profile '{a.profile}'...", file=sys.stderr)
    results = analyse(ips, a.profile, extra, a.parallel)
    print_analysis(results)
    if a.report:
        save_json(a.report, "analyse", results)


def cmd_scan(a) -> None:
    hosts = cmd_sweep(a)
    cmd_analyse(a, [h["ip"] for h in hosts])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="physarum", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def sweep_args(sp):
        sp.add_argument("range", help="e.g. 192.168.1.0/24, 192.168.1.1-254, 10.0.0.5")
        sp.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PROBE_PORTS)),
                        help="TCP ports probed to detect hosts that ignore ping")
        sp.add_argument("-t", "--timeout", type=float, default=1.0, help="seconds per probe")
        sp.add_argument("-w", "--workers", type=int, default=128, help="parallel hosts")
        sp.add_argument("--no-ping", action="store_true", help="TCP probes only")
        sp.add_argument("-o", "--output", help="save live hosts to JSON")

    def analyse_args(sp):
        sp.add_argument("--profile", choices=NMAP_PROFILES, default="soft",
                        help="soft (default), quick, or deep")
        sp.add_argument("--nmap-args", help="extra nmap arguments, e.g. --nmap-args=\"-Pn\" (use =)")
        sp.add_argument("-P", "--parallel", type=int, default=4, help="nmap runs at once")
        sp.add_argument("-r", "--report", help="save findings to JSON")

    s = sub.add_parser("sweep", help="find live hosts in a range")
    sweep_args(s)
    s.set_defaults(func=cmd_sweep)

    an = sub.add_parser("analyse", aliases=["analyze"], help="nmap analysis of hosts")
    an.add_argument("targets", nargs="*", help="IPs or ranges (or use --input)")
    an.add_argument("-i", "--input", help="JSON from 'sweep -o'")
    analyse_args(an)
    an.set_defaults(func=cmd_analyse)

    sc = sub.add_parser("scan", help="sweep then analyse every live host")
    sweep_args(sc)
    analyse_args(sc)
    sc.set_defaults(func=cmd_scan)
    return p


def main(argv: list[str] | None = None) -> None:
    if IS_WINDOWS:
        os.system("")  # enable ANSI colours in Windows terminals
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit("\ninterrupted")
    except ValueError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
