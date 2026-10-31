#!/usr/bin/env python3
"""Block Minescan scanner IPs from reaching a Minecraft server port.

Downloads the Minescan feed (IPs and/or CIDR ranges) and installs a drop rule
for the given TCP port using nftables or ipset+iptables (Linux), pf (macOS)
or Windows Firewall.

The script is idempotent: re-running it (cron / systemd timer) replaces the
block list in place without duplicating rules.

Examples:
    sudo ./mc-firewall.py --dry-run
    sudo ./mc-firewall.py --port 25565 --allow 203.0.113.0/24
    sudo ./mc-firewall.py --secondary https://example.com/list.txt --secondary extra.txt
    sudo ./mc-firewall.py --remove
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

DEFAULT_URL = "https://data.minescan.xyz/scanners/export?format=ip&includeMinescan=true"
DEFAULT_PORT = 25565
DEFAULT_LIMIT = 50000   # the Minescan feed returns only 1000 entries unless "limit" is set
SERVER_DEFAULT_CAP = 1000
USER_AGENT = "mc-firewall/2.0"

SET_NAME = "minescan_blocklist"   # ipset base name (suffixed _v4 / _v6)
NFT_TABLE = "minescan_filter"
PF_ANCHOR = "minescan"
RULE_NAME = "MinescanBlocklist"   # Windows rule prefix

MAX_FEED_BYTES = 50 * 1024 * 1024
IPSET_MAXELEM = 1_000_000
WIN_BATCH = 500
# Safety net against a broken/poisoned feed blocking half the internet.
MIN_PREFIX = {4: 16, 6: 32}


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def is_admin() -> bool:
    if platform.system() == "Windows":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd, input_text=None, check=True):
    result = subprocess.run(cmd, input=input_text, text=True, capture_output=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed: {' '.join(cmd)}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def write_file(path: str, text: str):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def parse_feed(raw: str, allow: list) -> tuple[dict, int]:
    """Return ({4: [nets], 6: [nets]}, skipped_count). Accepts IPs and CIDRs."""
    found = {4: [], 6: []}
    skipped = 0
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            skipped += 1
            continue
        if (
            not net.network_address.is_global          # private, loopback, etc.
            or net.prefixlen < MIN_PREFIX[net.version]  # suspiciously huge range
            or any(net.version == a.version and net.overlaps(a) for a in allow)
        ):
            skipped += 1
            continue
        found[net.version].append(net)

    return found, skipped


def read_source(src: str) -> str:
    """Read a feed from a local file or an http(s) URL."""
    if os.path.isfile(src):
        with open(src, "rb") as f:
            raw = f.read(MAX_FEED_BYTES + 1)
    else:
        if not src.lower().startswith(("http://", "https://")):
            raise RuntimeError(f"'{src}' is neither an existing file nor an http(s) URL")
        req = urllib.request.Request(src, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read(MAX_FEED_BYTES + 1)
    if len(raw) > MAX_FEED_BYTES:
        raise RuntimeError(f"{src} is unreasonably large; refusing to process it.")
    return raw.decode("utf-8", errors="ignore")


def with_limit(src: str, limit: int) -> str:
    """Add ?limit=N to an http(s) URL unless it already has one."""
    if not limit or os.path.isfile(src):
        return src
    parts = urllib.parse.urlsplit(src)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if any(k == "limit" for k, _ in query):
        return src
    query.append(("limit", str(limit)))
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(query)))


def load_list(src: str, limit: int) -> str:
    url = with_limit(src, limit)
    try:
        text = read_source(url)
    except HTTPError as e:
        if url == src or e.code not in (400, 413, 422):
            raise
        print(f"[!] Server rejected limit={limit} (HTTP {e.code}); retrying without it. "
              f"The list may be capped.", file=sys.stderr)
        url, text = src, read_source(src)

    count = sum(1 for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#"))
    cap = limit if url != src else SERVER_DEFAULT_CAP
    if src.lower().startswith(("http://", "https://")) and count >= cap:
        print(f"[!] Received exactly {count} entries - the list is probably truncated. "
              f"Raise --limit.", file=sys.stderr)
    return text


def fetch_networks(primary: str, secondary: list, allow: list, limit: int) -> dict:
    found = {4: [], 6: []}
    skipped = 0
    for i, src in enumerate([primary] + secondary):
        print(f"[*] Loading {'primary' if i == 0 else 'secondary'} list: {src}")
        try:
            # --limit only applies to the primary feed; secondary sources are used as given.
            part, s = parse_feed(load_list(src, limit if i == 0 else 0), allow)
        except (URLError, OSError, RuntimeError, ValueError) as e:
            if i == 0:
                raise                      # primary list is required
            print(f"[!] Skipping secondary list: {e}", file=sys.stderr)
            continue
        for v in (4, 6):
            found[v].extend(part[v])
        skipped += s
        print(f"    {len(part[4]) + len(part[6])} usable entries")

    # Merge overlapping/duplicate entries across all lists.
    nets = {v: sorted(ipaddress.collapse_addresses(found[v])) for v in (4, 6)}
    if not (nets[4] or nets[6]):
        raise RuntimeError("No valid entries found in the downloaded feed(s).")
    print(f"[*] Total after merging: {len(nets[4])} IPv4 + {len(nets[6])} IPv6 entries "
          f"({skipped} lines skipped: invalid, private, too broad or allow-listed).")
    return nets


# --------------------------------------------------------------------------- #
# Linux: nftables
# --------------------------------------------------------------------------- #
def nft_set(name: str, addr_type: str, nets: list) -> str:
    elems = f" elements = {{ {', '.join(map(str, nets))} }}" if nets else ""
    return f"    set {name} {{ type {addr_type}; flags interval; auto-merge;{elems} }}\n"


def nft_apply(nets: dict, port: int):
    print("[*] Using nftables backend.")
    # Hooking prerouting (priority raw) also covers traffic to Docker-published
    # ports, which never reaches the INPUT chain.
    script = (
        f"table inet {NFT_TABLE}\n"          # ensures it exists so delete can't fail
        f"delete table inet {NFT_TABLE}\n"
        f"table inet {NFT_TABLE} {{\n"
        + nft_set("blocked4", "ipv4_addr", nets[4])
        + nft_set("blocked6", "ipv6_addr", nets[6])
        + "    chain prerouting {\n"
        "        type filter hook prerouting priority raw; policy accept;\n"
        f"        tcp dport {port} ip saddr @blocked4 drop\n"
        f"        tcp dport {port} ip6 saddr @blocked6 drop\n"
        "    }\n"
        "}\n"
    )
    run(["nft", "-f", "-"], input_text=script)   # applied atomically
    print(f"[+] Dropping tcp/{port} from {len(nets[4]) + len(nets[6])} entries.")
    print("    Not persistent across reboots: re-run this script at boot "
          "(systemd timer/cron), or include the table in your nftables config.")


def nft_remove():
    run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)


# --------------------------------------------------------------------------- #
# Linux: ipset + iptables fallback
# --------------------------------------------------------------------------- #
IPSET_FAMILIES = ((4, "iptables", "inet"), (6, "ip6tables", "inet6"))


def ipset_rule(tool: str, name: str, port: int, action: str) -> list[str]:
    return [tool, "-t", "raw", action, "PREROUTING", "-p", "tcp", "--dport", str(port),
            "-m", "set", "--match-set", name, "src", "-j", "DROP"]


def ipset_apply(nets: dict, port: int):
    print("[*] Using ipset + iptables backend.")
    for ver, tool, family in IPSET_FAMILIES:
        if not nets[ver]:
            continue
        if not which(tool):
            print(f"[!] {tool} not found; skipping IPv{ver} entries.", file=sys.stderr)
            continue
        name = f"{SET_NAME}_v{ver}"
        tmp = name + "_tmp"
        spec = f"hash:net family {family} maxelem {IPSET_MAXELEM}"
        lines = [f"create {tmp} {spec} -exist", f"flush {tmp}"]
        lines += [f"add {tmp} {n}" for n in nets[ver]]
        lines += [f"create {name} {spec} -exist", f"swap {tmp} {name}", f"destroy {tmp}"]
        run(["ipset", "restore", "-exist"], input_text="\n".join(lines) + "\n")

        if run(ipset_rule(tool, name, port, "-C"), check=False).returncode != 0:
            run(ipset_rule(tool, name, port, "-I"))
        print(f"[+] IPv{ver}: {len(nets[ver])} entries, DROP on tcp/{port}.")
    print("    Not persistent across reboots: re-run this script at boot, or use "
          "ipset-persistent / netfilter-persistent.")


def ipset_remove(port: int):
    for ver, tool, _ in IPSET_FAMILIES:
        name = f"{SET_NAME}_v{ver}"
        if which(tool):
            while run(ipset_rule(tool, name, port, "-D"), check=False).returncode == 0:
                pass
        if which("ipset"):
            run(["ipset", "destroy", name], check=False)


def linux_apply(nets: dict, port: int):
    if which("nft"):
        nft_apply(nets, port)
    elif which("ipset") and which("iptables"):
        ipset_apply(nets, port)
    else:
        raise RuntimeError("Neither nft nor ipset+iptables found. Install nftables.")


def linux_remove(port: int):
    if which("nft"):
        nft_remove()
    if which("ipset"):
        ipset_remove(port)
    print("[+] Removed.")


# --------------------------------------------------------------------------- #
# macOS: pf
# --------------------------------------------------------------------------- #
PF_CONF = "/etc/pf.conf"
PF_ANCHOR_FILE = f"/etc/pf.anchors/{PF_ANCHOR}"
PF_TABLE_FILE = f"/etc/pf.{PF_ANCHOR}_blocklist.txt"
PF_LINES = (f'anchor "{PF_ANCHOR}"', f'load anchor "{PF_ANCHOR}" from "{PF_ANCHOR_FILE}"')


def pf_apply(nets: dict, port: int):
    print("[*] Using pf backend.")
    entries = [str(n) for v in (4, 6) for n in nets[v]]
    write_file(PF_TABLE_FILE, "\n".join(entries) + "\n")
    write_file(PF_ANCHOR_FILE,
               f'table <{PF_ANCHOR}_blocklist> persist file "{PF_TABLE_FILE}"\n'
               f"block drop in quick proto tcp from <{PF_ANCHOR}_blocklist> "
               f"to any port {port}\n")

    with open(PF_CONF) as f:
        contents = f.read()
    if PF_LINES[0] not in contents:
        shutil.copy2(PF_CONF, PF_CONF + ".bak")
        write_file(PF_CONF, contents.rstrip("\n") + "\n" + "\n".join(PF_LINES) + "\n")
        print(f"[*] Registered anchor in {PF_CONF} (backup: {PF_CONF}.bak).")

    run(["pfctl", "-a", PF_ANCHOR, "-f", PF_ANCHOR_FILE])
    run(["pfctl", "-e"], check=False)   # fails harmlessly if already enabled
    print(f"[+] Dropping tcp/{port} from {len(entries)} entries.")


def pf_remove():
    run(["pfctl", "-a", PF_ANCHOR, "-F", "all"], check=False)
    if os.path.exists(PF_CONF):
        with open(PF_CONF) as f:
            kept = [l for l in f.read().splitlines() if l.strip() not in PF_LINES]
        write_file(PF_CONF, "\n".join(kept) + "\n")
    for path in (PF_ANCHOR_FILE, PF_TABLE_FILE):
        if os.path.exists(path):
            os.remove(path)
    print("[+] Removed.")


# --------------------------------------------------------------------------- #
# Windows Firewall
# --------------------------------------------------------------------------- #
def powershell(cmd: str, check=True):
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd], check=check)


def windows_remove():
    powershell(f"Get-NetFirewallRule -DisplayName '{RULE_NAME}_*' "
               f"-ErrorAction SilentlyContinue | Remove-NetFirewallRule", check=False)


def windows_apply(nets: dict, port: int):
    print("[*] Using Windows Firewall backend.")
    addrs = [str(n) for v in (4, 6) for n in nets[v]]
    windows_remove()
    batches = [addrs[i:i + WIN_BATCH] for i in range(0, len(addrs), WIN_BATCH)]
    for idx, batch in enumerate(batches, start=1):
        remote = ",".join(f"'{a}'" for a in batch)
        powershell(
            f"New-NetFirewallRule -DisplayName '{RULE_NAME}_{idx}' -Direction Inbound "
            f"-Action Block -Protocol TCP -LocalPort {port} "
            f"-RemoteAddress @({remote}) -Profile Any"
        )
    print(f"[+] Created {len(batches)} rule(s) covering {len(addrs)} entries on tcp/{port}.")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def parse_args():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help=f"TCP port to protect (default: {DEFAULT_PORT})")
    p.add_argument("--url", default=DEFAULT_URL, help="Feed URL (one IP or CIDR per line)")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT,
                   help=f"Max entries to request from the primary feed (default: {DEFAULT_LIMIT}). "
                        f"The Minescan API returns only {SERVER_DEFAULT_CAP} without it. "
                        f"0 = don't send a limit.")
    p.add_argument("--secondary", action="append", default=[], metavar="URL|FILE",
                   help="Additional list (URL or local file, one IP/CIDR per line); "
                        "merged with the primary list. Repeatable. If it can't be "
                        "loaded it is skipped with a warning.")
    p.add_argument("--allow", action="append", default=[], metavar="CIDR",
                   help="Never block entries overlapping this IP/CIDR (repeatable)")
    p.add_argument("--dry-run", action="store_true",
                   help="Download and parse only; don't touch the firewall (no root needed)")
    p.add_argument("--remove", action="store_true",
                   help="Remove the rules and block list installed by this script")
    args = p.parse_args()

    if not 1 <= args.port <= 65535:
        p.error("--port must be between 1 and 65535")
    if args.limit < 0:
        p.error("--limit must be 0 or greater")
    try:
        args.allow = [ipaddress.ip_network(a, strict=False) for a in args.allow]
    except ValueError as e:
        p.error(f"invalid --allow value: {e}")
    return args


def main():
    args = parse_args()
    system = platform.system()
    if system not in ("Linux", "Darwin", "Windows"):
        sys.exit(f"Unsupported OS: {system}")

    if not args.dry_run and not is_admin():
        sys.exit("[!] Run with administrator/root privileges (or use --dry-run).")

    try:
        if args.remove:
            {"Linux": lambda: linux_remove(args.port),
             "Darwin": pf_remove,
             "Windows": lambda: (windows_remove(), print("[+] Removed."))}[system]()
            return

        nets = fetch_networks(args.url, args.secondary, args.allow, args.limit)
        if args.dry_run:
            print(f"[dry-run] Would block {len(nets[4]) + len(nets[6])} entries "
                  f"on tcp/{args.port}.")
            return

        {"Linux": linux_apply, "Darwin": pf_apply, "Windows": windows_apply}[system](
            nets, args.port)
    except (RuntimeError, URLError, OSError, ValueError) as e:
        sys.exit(f"[!] {e}")


if __name__ == "__main__":
    main()
