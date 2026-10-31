# Minescan IP Blocker

A Python script that fetches known Minecraft scanner IPs and blocks them from connecting to your server port. It can also merge in extra blocklists of your own.

## Quick Start

Run the script with **Administrator** or **root** privileges:

* **Linux / macOS:**
```bash
wget -O mc-firewall.py https://raw.githubusercontent.com/aleksireede/mc-firewall/refs/heads/main/main.py
chmod +x mc-firewall.py
sudo python3 mc-firewall.py
```

* **Windows (Administrator PowerShell):**
```powershell
Invoke-WebRequest -Uri https://raw.githubusercontent.com/aleksireede/mc-firewall/refs/heads/main/main.py -OutFile mc-firewall.py
python mc-firewall.py
```

By default, it downloads the Minescan blocklist and blocks inbound connections on port **25565**.

The script is safe to re-run: each run replaces the existing block list instead of adding duplicate rules, so you can schedule it to keep the list fresh (see [Keeping it up to date](#keeping-it-up-to-date)).

---

## Minescan API

The Minescan API endpoint is rate-limited to **5 requests per minute** and **60 requests per hour**. If you're using a custom script or frequently refreshing the blocklist, make sure your requests stay within these limits.

For updates, support, and discussion, join the **Minescan Discord server:**
https://discord.gg/AYbDNEWgHE

---

## Options

| Flag | Description | Default |
| --- | --- | --- |
| `--port <number>` | TCP port to protect. | `25565` |
| `--url <url>` | Use a different primary blocklist feed. | Minescan export feed |
| `--secondary <url or file>` | Add an extra blocklist (URL or local file, one IP or CIDR per line). Merged with the primary list. Can be repeated. If it can't be loaded, it is skipped with a warning. | None |
| `--allow <cidr>` | Never block entries that overlap this IP or range, e.g. your own network. Can be repeated. | None |
| `--dry-run` | Download and parse the lists without changing firewall settings (no root needed). | *Off* |
| `--remove` | Remove the rules and block list installed by this script. | *Off* |

**Examples:**
```bash
# Block port 25566 instead
sudo python3 mc-firewall.py --port 25566

# Add a second blocklist (URL) and a local file of your own
sudo python3 mc-firewall.py --secondary https://example.com/list.txt --secondary my-ips.txt

# Different primary list
sudo python3 mc-firewall.py --url https://gitlab.com/-/snippets/6073805/raw/main/snippetfile1.txt

# Make sure your home network is never blocked
sudo python3 mc-firewall.py --allow 203.0.113.0/24

# Test the script without applying firewall rules
python3 mc-firewall.py --dry-run

# Remove everything the script installed
sudo python3 mc-firewall.py --remove
```

Blocklist files can contain single IPs or CIDR ranges (IPv4 and IPv6). Lines starting with `#` are treated as comments.

If you change `--port`, run `--remove --port <old port>` first so the old rule doesn't stay behind.

---

## Safety Filters

All lists, primary and secondary, go through the same checks before anything is applied:

* Invalid lines are ignored.
* Private, loopback and other non-public addresses are skipped.
* Overly broad ranges (wider than /16 for IPv4 or /32 for IPv6) are skipped, so a broken feed can't block a large part of the internet.
* Entries overlapping an `--allow` range are skipped.
* Duplicate and overlapping entries are merged.

The primary list is required: if it can't be downloaded, the script stops and changes nothing.

---

## Keeping it up to date

On **Linux**, the rules do not survive a reboot. On **macOS** and **Windows**, the rules persist. To keep the blocklist current (and restored after reboots on Linux), run the script on a schedule, for example from root's crontab:

```cron
@reboot /usr/bin/python3 /opt/mc-firewall.py
0 4 * * * /usr/bin/python3 /opt/mc-firewall.py
```

A daily run stays well within the Minescan rate limits.

---

## Requirements & Compatibility

**Python:** 3.7+ (no external `pip` packages needed).

**Supported OS:**
* **Linux:** Uses `nftables`, or `ipset` + `iptables` if `nft` isn't installed. These work alongside `ufw` and `firewalld`.
* **macOS:** Uses `pf` (Packet Filter). `/etc/pf.conf` is backed up to `/etc/pf.conf.bak` before the first change.
* **Windows:** Uses Windows Defender Firewall.

**Docker:** On Linux the rules are applied before Docker's port forwarding, so containers with published Minecraft ports are protected too.
